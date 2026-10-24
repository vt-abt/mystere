import hashlib
import os
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from relay.app.auth import registration_payload
from relay.app.db import Base, get_db
from relay.app.main import app


@pytest.fixture
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine)

    def database():
        with local_session() as db:
            yield db

    app.dependency_overrides[get_db] = database
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    engine.dispose()


def register(client):
    private = Ed25519PrivateKey.generate()
    signing_key = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    identity_key = os.urandom(33)
    signed_key = os.urandom(33)
    signed_signature = os.urandom(64)
    one_time = [(1, os.urandom(33)), (2, os.urandom(33))]
    proof = private.sign(registration_payload(
        identity_key, 123, 1, signed_key, signed_signature, one_time,
    ))
    data = {
        "identity_pubkey": identity_key.hex(),
        "signing_pubkey": signing_key.hex(),
        "registration_id": 123,
        "signed_prekey_id": 1,
        "signed_prekey": signed_key.hex(),
        "signed_prekey_sig": signed_signature.hex(),
        "one_time_prekeys": [{"key_id": key_id, "pubkey": key.hex()} for key_id, key in one_time],
        "registration_signature": proof.hex(),
    }
    response = client.post("/keys/identity", json=data)
    assert response.status_code == 200, response.text
    return uuid.UUID(response.json()["user_id"]), private, data


def timestamp():
    return int(time.time() * 1000).to_bytes(8, "big")


def test_signatures_gate_commitment_and_one_time_prekey(client):
    initiator, initiator_private, _ = register(client)
    responder, responder_private, _ = register(client)
    request = responder.bytes + os.urandom(32) + timestamp()
    request_data = {
        "initiator_id": str(initiator), "responder_id": str(responder),
        "payload": request.hex(), "signature": os.urandom(64).hex(),
    }
    assert client.post("/session/request", json=request_data).status_code == 403
    request_data["signature"] = initiator_private.sign(request).hex()
    response = client.post("/session/request", json=request_data)
    assert response.status_code == 200, response.text
    temp_id = response.json()["temp_id"]

    acknowledgment = hashlib.sha512(request).digest() + os.urandom(32) + timestamp()
    ack_data = {
        "temp_id": temp_id, "payload": acknowledgment.hex(),
        "signature": initiator_private.sign(acknowledgment).hex(),
    }
    assert client.post("/session/ack", json=ack_data).status_code == 403
    ack_data["signature"] = responder_private.sign(acknowledgment).hex()
    response = client.post("/session/ack", json=ack_data)
    assert response.status_code == 200, response.text
    session_id = response.json()["session_id"]

    proof = initiator_private.sign(
        b"MYSTERE_PREKEY_FETCH_V1" + bytes.fromhex(session_id) + responder.bytes,
    )
    payload = {"session_id": session_id, "proof": proof.hex()}
    first = client.post(f"/keys/prekeys/{responder}/fetch", json=payload)
    second = client.post(f"/keys/prekeys/{responder}/fetch", json=payload)
    assert first.status_code == second.status_code == 200
    assert first.json()["one_time_prekey"] == second.json()["one_time_prekey"]
    assert first.json()["one_time_prekey_id"] == second.json()["one_time_prekey_id"]
    assert client.post(f"/keys/prekeys/{responder}/fetch", json={
        "session_id": session_id, "proof": os.urandom(64).hex(),
    }).status_code == 403


def test_websocket_rejects_impersonation_and_preserves_sender(client):
    sender, sender_private, _ = register(client)
    recipient, recipient_private, _ = register(client)
    with client.websocket_connect(f"/ws/{recipient}") as websocket:
        challenge = websocket.receive_bytes()
        assert challenge[0] == 0 and len(challenge) == 33
        websocket.send_bytes(sender_private.sign(b"MYSTERE_WS_V1" + recipient.bytes + challenge[1:]))
        with pytest.raises(Exception):
            websocket.receive_bytes()

    with client.websocket_connect(f"/ws/{recipient}") as websocket:
        challenge = websocket.receive_bytes()
        websocket.send_bytes(recipient_private.sign(b"MYSTERE_WS_V1" + recipient.bytes + challenge[1:]))
        assert websocket.receive_bytes() == b"\x00\x01"

    with client.websocket_connect(f"/ws/{sender}") as websocket:
        challenge = websocket.receive_bytes()
        websocket.send_bytes(sender_private.sign(b"MYSTERE_WS_V1" + sender.bytes + challenge[1:]))
        assert websocket.receive_bytes() == b"\x00\x01"
        websocket.send_bytes(recipient.bytes + b"\x01" + b"ciphertext")

    with client.websocket_connect(f"/ws/{recipient}") as websocket:
        challenge = websocket.receive_bytes()
        websocket.send_bytes(recipient_private.sign(b"MYSTERE_WS_V1" + recipient.bytes + challenge[1:]))
        assert websocket.receive_bytes() == b"\x00\x01"
        frame = websocket.receive_bytes()
        assert uuid.UUID(bytes=frame[16:32]) == sender
        assert frame[32:] == b"\x01ciphertext"
        websocket.send_bytes(uuid.UUID(int=0).bytes + b"\x0b" + frame[:16])


def test_online_delivery_is_queued_until_recipient_acknowledges(client):
    sender, sender_private, _ = register(client)
    recipient, recipient_private, _ = register(client)
    with client.websocket_connect(f"/ws/{recipient}") as receiving:
        challenge = receiving.receive_bytes()
        receiving.send_bytes(recipient_private.sign(
            b"MYSTERE_WS_V1" + recipient.bytes + challenge[1:],
        ))
        assert receiving.receive_bytes() == b"\x00\x01"
        with client.websocket_connect(f"/ws/{sender}") as sending:
            challenge = sending.receive_bytes()
            sending.send_bytes(sender_private.sign(
                b"MYSTERE_WS_V1" + sender.bytes + challenge[1:],
            ))
            assert sending.receive_bytes() == b"\x00\x01"
            sending.send_bytes(recipient.bytes + b"\x01" + b"encrypted")
            frame = receiving.receive_bytes()
            assert frame[:16] != bytes(16)
            assert uuid.UUID(bytes=frame[16:32]) == sender
            assert frame[32:] == b"\x01encrypted"
            receiving.send_bytes(uuid.UUID(int=0).bytes + b"\x0b" + frame[:16])


def test_prekey_refill_is_signed_and_safe_to_retry(client):
    user_id, private, _ = register(client)
    key_id = 3
    key = os.urandom(33)
    payload = b"MYSTERE_REPLENISH_V1" + user_id.bytes + key_id.to_bytes(4, "big") + key
    data = {
        "user_id": str(user_id),
        "one_time_prekeys": [{"key_id": key_id, "pubkey": key.hex()}],
        "signature": private.sign(payload).hex(),
    }
    assert client.post("/keys/prekeys/replenish", json=data).status_code == 200
    assert client.post("/keys/prekeys/replenish", json=data).status_code == 200
    data["one_time_prekeys"][0]["pubkey"] = os.urandom(33).hex()
    assert client.post("/keys/prekeys/replenish", json=data).status_code == 403
