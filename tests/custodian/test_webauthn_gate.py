import base64
import hashlib
import json
import os
import time

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from custodian.app.db import Base, get_db
from custodian.app.main import app


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


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


def client_data(kind, challenge, origin="http://localhost:5173"):
    return json.dumps({
        "type": kind, "challenge": b64(challenge), "origin": origin,
        "crossOrigin": False,
    }, separators=(",", ":")).encode()


def credential_for(client):
    options = client.post("/credentials/options").json()
    challenge = unb64(options["challenge"])
    private = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private.public_key().public_numbers()
    credential_id = os.urandom(32)
    cose = cbor2.dumps({
        1: 2, 3: -7, -1: 1,
        -2: public_numbers.x.to_bytes(32, "big"),
        -3: public_numbers.y.to_bytes(32, "big"),
    })
    auth_data = (
        hashlib.sha256(b"localhost").digest() + b"\x45" + (0).to_bytes(4, "big")
        + bytes(16) + len(credential_id).to_bytes(2, "big") + credential_id + cose
    )
    registration = {
        "id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key",
        "response": {
            "clientDataJSON": b64(client_data("webauthn.create", challenge)),
            "attestationObject": b64(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})),
        },
    }
    enrolled = client.post("/credentials/enroll", json={
        "challenge": challenge.hex(), "credential": registration,
    })
    assert enrolled.status_code == 200, enrolled.text
    assert client.post("/credentials/enroll", json={
        "challenge": challenge.hex(), "credential": registration,
    }).status_code == 403
    return private, credential_id


def assertion(private, credential_id, challenge, flags=0x05, origin="http://localhost:5173"):
    auth_data = hashlib.sha256(b"localhost").digest() + bytes([flags]) + (1).to_bytes(4, "big")
    data = client_data("webauthn.get", challenge, origin)
    signature = private.sign(auth_data + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key",
        "response": {
            "authenticatorData": b64(auth_data),
            "clientDataJSON": b64(data),
            "signature": b64(signature),
        },
    }


def test_verified_credential_opens_bound_blob_once_per_challenge(client):
    private, credential_id = credential_for(client)
    key = os.urandom(32)
    blob = os.urandom(140)
    deposit = {
        "key": key.hex(), "value": blob.hex(), "ttl": int(time.time()) + 600,
        "credential_id": b64(credential_id),
    }
    assert client.post("/deposit", json=deposit).status_code == 200
    assert client.post("/deposit", json=deposit).status_code == 409
    challenge = unb64(client.post("/retrieve/challenge", json={"key": key.hex()}).json()["challenge"])
    request = {"key": key.hex(), "challenge": challenge.hex(),
               "assertion": assertion(private, credential_id, challenge)}
    response = client.post("/retrieve", json=request)
    assert response.status_code == 200, response.text
    assert response.json()["value"] == blob.hex()
    receipt = response.json()["receipt"]
    public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(
        client.get("/receipt-key").json()["public_key"],
    ))
    public.verify(bytes.fromhex(receipt["signature"]), bytes.fromhex(receipt["payload"]))
    assert key in bytes.fromhex(receipt["payload"])
    assert client.post("/retrieve", json=request).status_code == 403


def test_storage_capability_deletes_only_its_blob(client):
    _, credential_id = credential_for(client)
    first, second = os.urandom(32), os.urandom(32)
    for key in (first, second):
        response = client.post("/deposit", json={
            "key": key.hex(), "value": os.urandom(32).hex(),
            "ttl": int(time.time()) + 600, "credential_id": b64(credential_id),
        })
        assert response.status_code == 200, response.text
    assert client.post("/delete", json={"key": first.hex()}).json() == {"deleted": True}
    assert client.post("/delete", json={"key": first.hex()}).json() == {"deleted": False}
    assert client.post("/retrieve/challenge", json={"key": first.hex()}).status_code == 404
    assert client.post("/retrieve/challenge", json={"key": second.hex()}).status_code == 200
    assert client.post("/delete", json={"key": "0"}).status_code == 400


@pytest.mark.parametrize("flags,origin", [(0x01, "http://localhost:5173"), (0x05, "https://evil.example")])
def test_rejects_missing_user_verification_or_wrong_origin(client, flags, origin):
    private, credential_id = credential_for(client)
    key = os.urandom(32)
    assert client.post("/deposit", json={
        "key": key.hex(), "value": os.urandom(140).hex(),
        "ttl": int(time.time()) + 600, "credential_id": b64(credential_id),
    }).status_code == 200
    challenge = unb64(client.post("/retrieve/challenge", json={"key": key.hex()}).json()["challenge"])
    response = client.post("/retrieve", json={
        "key": key.hex(), "challenge": challenge.hex(),
        "assertion": assertion(private, credential_id, challenge, flags, origin),
    })
    assert response.status_code == 403


def test_rejects_other_credential_and_substituted_challenge(client):
    private, credential_id = credential_for(client)
    _, other_credential_id = credential_for(client)
    key = os.urandom(32)
    assert client.post("/deposit", json={
        "key": key.hex(), "value": os.urandom(140).hex(),
        "ttl": int(time.time()) + 600, "credential_id": b64(credential_id),
    }).status_code == 200
    challenge = unb64(client.post("/retrieve/challenge", json={"key": key.hex()}).json()["challenge"])
    wrong_credential = client.post("/retrieve", json={
        "key": key.hex(), "challenge": challenge.hex(),
        "assertion": assertion(private, other_credential_id, challenge),
    })
    assert wrong_credential.status_code == 403
    wrong_challenge = client.post("/retrieve", json={
        "key": key.hex(), "challenge": challenge.hex(),
        "assertion": assertion(private, credential_id, os.urandom(32)),
    })
    assert wrong_challenge.status_code == 403

    fake = assertion(private, credential_id, challenge)
    fake["response"]["signature"] = b64(bytes(72))
    flags_without_signature = client.post("/retrieve", json={
        "key": key.hex(), "challenge": challenge.hex(), "assertion": fake,
    })
    assert flags_without_signature.status_code == 403
