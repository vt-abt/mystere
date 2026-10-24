import { useEffect, useMemo, useRef, useState } from 'react'
import { MSG, uuidToBytes } from '../transport/messages.js'
import { createSessionRequest, createSessionAck, computeSessionId, verifySessionRequest, verifySessionAck } from '../crypto/commitment.js'
import { ensurePrekeys, fetchPeerIdentity, fromHex, toHex } from '../crypto/identity.js'
import { encryptMessage, decryptMessage, initSession } from '../crypto/signal.js'
import { prepareOutboundMessage, readRecipientMessage, openMessage } from '../crypto/message.js'
import { decryptShareCustodian, storageKey } from '../crypto/capability.js'
import { registerCredential, getAssertion, fromBase64url } from '../crypto/webauthn.js'
import { verifyReleaseReceipt } from '../crypto/release.js'
import { CustodianClient } from '../transport/custodian.js'
import { encodeJson, decodeJson, serializeSignal, deserializeSignal } from '../transport/protocol.js'
import { wipe } from '../crypto/webcrypto.js'
import { RotationManager } from '../defence/rotation.js'
import { DecoyTraffic, createDecoyFrame, encodeTrafficFrame } from '../defence/decoy.js'
import { sendTombstone, verifyTombstone } from '../defence/tombstone.js'
import { panicWipe } from '../defence/panic.js'
import { SessionStateMachine, STATE, EVENT } from '../state/machine.js'

const RELAY_API = import.meta.env.VITE_RELAY_API || 'http://localhost:8000'
const CUSTODIAN_API = import.meta.env.VITE_CUSTODIAN_API || 'http://localhost:8001'
const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

async function post(path, body) {
  const response = await fetch(`${RELAY_API}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  if (!response.ok) throw new Error(`${path} failed (${response.status})`)
  return response.json()
}

async function fetchSignalBundle(user, peerId, sessionId, expectedIdentityKey) {
  const prefix = encoder.encode('MYSTERE_PREKEY_FETCH_V1')
  const challenge = new Uint8Array(prefix.length + 64 + 16)
  challenge.set(prefix)
  challenge.set(sessionId, prefix.length)
  challenge.set(uuidToBytes(peerId), prefix.length + 64)
  const proof = await crypto.subtle.sign('Ed25519', user.signingPrivateKey, challenge)
  const data = await post(`/keys/prekeys/${peerId}/fetch`, {
    session_id: toHex(sessionId), proof: toHex(proof),
  })
  if (data.identity_pubkey !== expectedIdentityKey) {
    throw new Error('Peer Signal identity changed after fingerprint verification')
  }
  return {
    registrationId: data.registration_id,
    identityKey: fromHex(data.identity_pubkey, 33).buffer,
    signedPreKey: {
      keyId: data.signed_prekey_id,
      publicKey: fromHex(data.signed_prekey, 33).buffer,
      signature: fromHex(data.signed_prekey_sig, 64).buffer,
    },
    preKey: {
      keyId: data.one_time_prekey_id,
      publicKey: fromHex(data.one_time_prekey, 33).buffer,
    },
  }
}

export default function Chat({ user, socket, onPanic }) {
  const custodian = useMemo(() => new CustodianClient(CUSTODIAN_API), [])
  const [credentialId, setCredentialId] = useState('')
  const [peerCredentialId, setPeerCredentialId] = useState('')
  const [recipientId, setRecipientId] = useState('')
  const [expectedFingerprint, setExpectedFingerprint] = useState('')
  const [incomingFingerprint, setIncomingFingerprint] = useState('')
  const [pending, setPending] = useState(null)
  const [active, setActive] = useState(null)
  const [draft, setDraft] = useState('')
  const [messages, setMessages] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [sessionState, setSessionState] = useState(STATE.HEALTHY)
  const [rotating, setRotating] = useState(false)
  const [awaitingPeer, setAwaitingPeer] = useState(false)
  const credentialRef = useRef('')
  const peerCredentialRef = useRef('')
  const activeRef = useRef(null)
  const outgoing = useRef(null)
  const inbound = useRef(new Map())
  const outbound = useRef(new Map())
  const seenQueues = useRef(new Set())
  const sequence = useRef(0)
  const signalQueue = useRef(Promise.resolve())
  const rotation = useRef(null)
  const decoys = useRef(null)
  const machine = useRef(null)
  const seenMessages = useRef(new Set())
  const seenTombstones = useRef(new Set())
  const trafficSize = useRef(2048)
  const trafficCiphertextLength = useRef(1052)
  const lastInboundSequence = useRef(0)
  const sending = useRef(false)
  const trustedPeer = useRef(null)
  const renewing = useRef(false)

  function withSignal(task) {
    const operation = signalQueue.current.then(task)
    signalQueue.current = operation.catch(() => {})
    return operation
  }

  function clearHeldShares() {
    const keys = []
    for (const held of inbound.current.values()) {
      keys.push(held.storageKey.slice())
      wipe(held.recipientShare, held.capabilityToken, held.custodianShare, held.storageKey)
    }
    inbound.current.clear()
    for (const held of outbound.current.values()) {
      keys.push(held.storageKey.slice())
      clearTimeout(held.purgeTimer)
      wipe(held.senderShare, held.storageKey)
    }
    outbound.current.clear()
    return keys
  }

  function deleteCustodianKeys(keys) {
    return Promise.allSettled(keys.map(key => custodian.delete(key).finally(() => wipe(key))))
  }

  function endSession() {
    rotation.current?.stop()
    decoys.current?.stop()
    rotation.current = null
    decoys.current = null
    machine.current = null
    const keys = clearHeldShares()
    activeRef.current = null
    peerCredentialRef.current = ''
    seenMessages.current.clear()
    seenTombstones.current.clear()
    sequence.current = 0
    lastInboundSequence.current = 0
    setActive(null)
    setPeerCredentialId('')
    setMessages([])
    setRotating(false)
    return keys
  }

  async function requestSession(peerId, peer) {
    const request = await createSessionRequest({ privateKey: user.signingPrivateKey }, peerId)
    outgoing.current = { recipientId: peerId, peer, payload: request.payload }
    setAwaitingPeer(true)
    await post('/session/request', {
      initiator_id: user.userId, responder_id: peerId,
      payload: toHex(request.payload), signature: toHex(request.signature),
    })
  }

  async function renewSession() {
    const session = activeRef.current
    if (!session) return
    const keys = endSession()
    renewing.current = true
    try {
      deleteCustodianKeys(keys)
      if (activeRef.current) return
      const peer = await fetchPeerIdentity(RELAY_API, session.peerId)
      if (peer.fingerprint !== session.peer.fingerprint) throw new Error('Peer identity changed during rotation')
      await requestSession(session.peerId, peer)
    } catch (failure) {
      renewing.current = false
      outgoing.current = null
      setAwaitingPeer(false)
      setError(`Session renewal failed: ${failure.message}`)
    }
  }

  function setCurrentSession(session) {
    if (activeRef.current && activeRef.current !== session) {
      const keys = endSession()
      deleteCustodianKeys(keys)
    }
    activeRef.current = session
    trustedPeer.current = { ...session.peer, userId: session.peerId }
    renewing.current = false
    setActive(session)
    setSessionState(STATE.HEALTHY)
    const state = new SessionStateMachine(async () => {
      deleteCustodianKeys(endSession())
      trustedPeer.current = null
      setError('Session frozen after an authentication failure')
    }, setSessionState)
    machine.current = state
    const manager = new RotationManager(session.sessionId, renewSession)
    rotation.current = manager
    manager.init().catch(failure => setError(failure.message))
  }

  function startDecoys() {
    decoys.current?.stop()
    const cover = new DecoyTraffic(async () => {
      const session = activeRef.current
      if (!session || !socket.connected || rotation.current?.rotating || sending.current) return
      const next = ++sequence.current
      const payload = await withSignal(() => createDecoyFrame(
        user.signalStore, session.peerId, session.sessionId, next,
        trafficSize.current, trafficCiphertextLength.current,
      ))
      socket.send(session.peerId, MSG.MESSAGE, payload)
    })
    decoys.current = cover
    cover.start()
  }

  function acknowledge(frame) {
    seenQueues.current.add(toHex(frame.queueId))
    socket.acknowledge(frame.queueId)
  }

  async function sendControl(type, data) {
    const session = activeRef.current
    if (!session) throw new Error('No active session')
    const payload = encodeJson({ v: 1, session: toHex(session.sessionId), ...data })
    const envelope = await withSignal(() => encryptMessage(user.signalStore, session.peerId, payload))
    socket.send(session.peerId, type, encodeJson(serializeSignal(envelope)))
  }

  async function handleSignalControl(frame) {
    const session = activeRef.current
    if (!session || frame.senderId !== session.peerId) throw new Error('Message from an unverified peer')
    const envelope = deserializeSignal(decodeJson(frame.payload))
    const plain = new Uint8Array(await withSignal(() => decryptMessage(
      user.signalStore, frame.senderId, envelope,
    )))
    try {
      const data = decodeJson(plain)
      if (data.v !== 1 || data.session !== toHex(session.sessionId)) {
        throw new Error('Encrypted control message has the wrong session')
      }
      return data
    } finally {
      wipe(plain)
    }
  }

  useEffect(() => {
    let mounted = true
    const handleFrame = async frame => {
      try {
        if (seenQueues.current.has(toHex(frame.queueId))) {
          socket.acknowledge(frame.queueId)
          return
        }
        if (frame.type === MSG.COMMIT_REQ) {
          if (frame.payload.length !== 120) throw new Error('Invalid session request')
          const peer = await fetchPeerIdentity(RELAY_API, frame.senderId)
          const payload = frame.payload.slice(0, 56)
          const signature = frame.payload.slice(56)
          if (!await verifySessionRequest(peer.signingPublicKey, payload, signature, user.userId)) {
            throw new Error('Invalid session request signature or target')
          }
          const current = activeRef.current
          if ((current || renewing.current) && frame.senderId === (current?.peerId || trustedPeer.current?.userId)
              && peer.fingerprint === trustedPeer.current?.fingerprint) {
            if (outgoing.current && user.userId < frame.senderId) {
              acknowledge(frame)
              return
            }
            outgoing.current = null
            setAwaitingPeer(false)
            await ensurePrekeys(user, RELAY_API)
            const ack = await createSessionAck({ privateKey: user.signingPrivateKey }, { payload })
            const tempId = await crypto.subtle.digest('SHA-256', payload)
            const sessionId = await computeSessionId(payload, ack.payload)
            await post('/session/ack', {
              temp_id: toHex(tempId), payload: toHex(ack.payload), signature: toHex(ack.signature),
            })
            setCurrentSession({ peerId: frame.senderId, sessionId, peer })
            user.remainingPrekeys--
            acknowledge(frame)
            return
          }
          if (mounted) setPending({ senderId: frame.senderId, peer, payload, queueId: frame.queueId })
          return
        }
        if (frame.type === MSG.COMMIT_ACK) {
          const request = outgoing.current
          if (!request || frame.senderId !== request.recipientId || frame.payload.length !== 168) {
            throw new Error('Unexpected session acknowledgment')
          }
          const ackPayload = frame.payload.slice(0, 104)
          const signature = frame.payload.slice(104)
          if (!await verifySessionAck(request.peer.signingPublicKey, request.payload, ackPayload, signature)) {
            throw new Error('Invalid session acknowledgment')
          }
          const sessionId = await computeSessionId(request.payload, ackPayload)
          const bundle = await fetchSignalBundle(
            user, request.recipientId, sessionId, request.peer.identity_pubkey,
          )
          await withSignal(() => initSession(user.signalStore, request.recipientId, bundle))
          setCurrentSession({ peerId: request.recipientId, sessionId, peer: request.peer })
          outgoing.current = null
          setAwaitingPeer(false)
          await sendControl(MSG.KEY_REQ, { credentialId: credentialRef.current })
          acknowledge(frame)
          return
        }
        if (frame.type === MSG.KEY_REQ || frame.type === MSG.KEY_RESP) {
          const data = await handleSignalControl(frame)
          fromBase64url(data.credentialId)
          peerCredentialRef.current = data.credentialId
          if (mounted) setPeerCredentialId(data.credentialId)
          if (frame.type === MSG.KEY_REQ) {
            await sendControl(MSG.KEY_RESP, { credentialId: credentialRef.current })
          }
          startDecoys()
          acknowledge(frame)
          return
        }
        if (frame.type === MSG.MESSAGE) {
          const session = activeRef.current
          if (!session || frame.senderId !== session.peerId) throw new Error('Message from an unverified peer')
          const data = decodeJson(frame.payload)
          if (data.v !== 1 || data.session !== toHex(session.sessionId)
              || !Number.isSafeInteger(data.sequence) || data.sequence < 1) {
            throw new Error('Message session or sequence invalid')
          }
          const messageId = fromHex(data.id, 16)
          const id = toHex(messageId)
          if (seenMessages.current.has(id)) {
            acknowledge(frame)
            return
          }
          const ciphertext = fromHex(data.ciphertext, data.ciphertext.length / 2)
          const recipientEnvelope = deserializeSignal(data.signal)
          const { recipientShare, capabilityToken, decoy } = await withSignal(() => readRecipientMessage(
            user.signalStore, frame.senderId, recipientEnvelope,
            session.sessionId, messageId, data.sequence,
          ))
          seenMessages.current.add(id)
          if (decoy) {
            acknowledge(frame)
            return
          }
          if (data.sequence <= lastInboundSequence.current) {
            await machine.current?.handleEvent(EVENT.OUT_OF_ORDER)
          } else {
            lastInboundSequence.current = data.sequence
            await machine.current?.handleEvent(EVENT.HEALTHY_MESSAGE)
          }
          const key = new Uint8Array(await storageKey(capabilityToken, messageId))
          inbound.current.set(id, {
            messageId, sequence: data.sequence, ciphertext,
            recipientShare, capabilityToken, storageKey: key, custodianShare: null,
          })
          if (mounted) setMessages(current => [...current, {
            id, direction: 'in', status: 'Device verification required', text: '',
          }])
          acknowledge(frame)
          return
        }
        if (frame.type === MSG.TOMBSTONE) {
          const session = activeRef.current
          if (!session || frame.senderId !== session.peerId) throw new Error('Tombstone from unverified peer')
          const data = await verifyTombstone(
            frame.payload, session.peer.signingPublicKey, session.sessionId, seenTombstones.current,
          )
          acknowledge(frame)
          deleteCustodianKeys(endSession())
          trustedPeer.current = null
          renewing.current = false
          setError(data.reason === 'rotation' ? 'Peer renewed the session' : 'Peer revoked the session')
          return
        }
        if (frame.type === MSG.FRAGMENT) {
          const data = await handleSignalControl(frame)
          const messageId = fromHex(data.id, 16)
          const id = toHex(messageId)
          if (data.kind === 'release-request') {
            const held = outbound.current.get(id)
            if (!held) throw new Error('Sender share unavailable')
            if (held.expiresAt <= Date.now()) {
              clearTimeout(held.purgeTimer)
              wipe(held.senderShare)
              outbound.current.delete(id)
              deleteCustodianKeys([held.storageKey.slice()])
              wipe(held.storageKey)
              throw new Error('Sender share expired')
            }
            const publicKey = await custodian.receiptPublicKey()
            if (!await verifyReleaseReceipt(data.receipt, held.storageKey, publicKey)) {
              throw new Error('Custodian release receipt invalid')
            }
            await sendControl(MSG.FRAGMENT, { kind: 'release-share', id, share: toHex(held.senderShare) })
            clearTimeout(held.purgeTimer)
            wipe(held.senderShare)
            outbound.current.delete(id)
            deleteCustodianKeys([held.storageKey.slice()])
            wipe(held.storageKey)
          } else if (data.kind === 'release-share') {
            const held = inbound.current.get(id)
            if (!held?.custodianShare) throw new Error('Custodian share not released')
            const senderShare = fromHex(data.share, 32)
            try {
              const opened = await openMessage(
                held.ciphertext, activeRef.current.sessionId, messageId, held.sequence,
                senderShare, held.recipientShare, held.custodianShare,
              )
              const text = decoder.decode(opened)
              if (mounted) setMessages(current => current.map(message =>
                message.id === id ? { ...message, text, status: 'Opened' } : message,
              ))
              await machine.current?.handleEvent(EVENT.HEALTHY_MESSAGE)
            } finally {
              wipe(senderShare, held.recipientShare, held.custodianShare, held.capabilityToken)
              inbound.current.delete(id)
            }
          } else throw new Error('Unknown fragment operation')
          acknowledge(frame)
        }
      } catch (failure) {
        if ([MSG.MESSAGE, MSG.KEY_REQ, MSG.KEY_RESP, MSG.TOMBSTONE].includes(frame.type)
            && frame.senderId === activeRef.current?.peerId) {
          await machine.current?.handleEvent(EVENT.AUTH_FAILURE)
          setSessionState(STATE.FROZEN)
        }
        if (mounted) setError(failure.message)
      }
    }
    socket.setMessageHandler(handleFrame).catch(failure => {
      if (mounted) setError(failure.message)
    })
    socket.onClose = () => {
      if (activeRef.current) {
        machine.current?.handleEvent(EVENT.TIMEOUT)
        setSessionState(STATE.DELAYED)
      }
    }
    return () => {
      mounted = false
      socket.onMessage = null
      socket.onClose = null
    }
  }, [socket, user, custodian])

  useEffect(() => () => {
    rotation.current?.stop()
    decoys.current?.stop()
    clearHeldShares()
  }, [])

  async function enrollDevice() {
    setBusy(true)
    setError('')
    try {
      const id = await registerCredential(custodian)
      credentialRef.current = id
      setCredentialId(id)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  async function startHandshake() {
    setBusy(true)
    setError('')
    try {
      if (!credentialRef.current) throw new Error('Enroll device verification first')
      uuidToBytes(recipientId)
      if (recipientId === user.userId) throw new Error('Choose another identity')
      const peer = await fetchPeerIdentity(RELAY_API, recipientId)
      if (peer.fingerprint !== expectedFingerprint.trim().toLowerCase()) {
        throw new Error('Peer fingerprint does not match')
      }
      await requestSession(recipientId, peer)
    } catch (failure) {
      outgoing.current = null
      setAwaitingPeer(false)
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  async function acceptHandshake() {
    if (!pending) return
    setBusy(true)
    setError('')
    try {
      if (!credentialRef.current) throw new Error('Enroll device verification first')
      if (pending.peer.fingerprint !== incomingFingerprint.trim().toLowerCase()) {
        throw new Error('Peer fingerprint does not match')
      }
      const ack = await createSessionAck({ privateKey: user.signingPrivateKey }, { payload: pending.payload })
      await ensurePrekeys(user, RELAY_API)
      const tempId = await crypto.subtle.digest('SHA-256', pending.payload)
      const sessionId = await computeSessionId(pending.payload, ack.payload)
      await post('/session/ack', {
        temp_id: toHex(tempId), payload: toHex(ack.payload), signature: toHex(ack.signature),
      })
      setCurrentSession({ peerId: pending.senderId, sessionId, peer: pending.peer })
      user.remainingPrekeys--
      socket.acknowledge(pending.queueId)
      setPending(null)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  async function sendMessage() {
    const session = activeRef.current
    if (!session || !draft.trim()) return
    sending.current = true
    setBusy(true)
    setError('')
    const capability = crypto.getRandomValues(new Uint8Array(32))
    let packed = null
    let queued = false
    let messageIdHex = null
    try {
      if (!peerCredentialRef.current) throw new Error('Peer device credential not available')
      const messageId = crypto.getRandomValues(new Uint8Array(16))
      const nextSequence = ++sequence.current
      packed = await withSignal(() => prepareOutboundMessage(
        user.signalStore, session.peerId, draft, session.sessionId,
        messageId, nextSequence, capability,
      ))
      const expiresAt = Date.now() + 60 * 60 * 1000
      await custodian.deposit(
        packed.custodianRecord.key, packed.custodianRecord.value,
        peerCredentialRef.current, Math.floor(expiresAt / 1000),
      )
      const id = toHex(messageId)
      messageIdHex = id
      const held = {
        senderShare: packed.senderShare,
        storageKey: packed.custodianRecord.key,
        expiresAt,
      }
      held.purgeTimer = setTimeout(() => {
        if (outbound.current.get(id) === held && held.expiresAt <= Date.now()) {
          wipe(held.senderShare)
          outbound.current.delete(id)
          custodian.delete(held.storageKey).catch(() => {})
          wipe(held.storageKey)
        }
      }, 60 * 60 * 1000 + 1000)
      outbound.current.set(id, held)
      const frame = encodeTrafficFrame({
        v: 1, session: toHex(session.sessionId), id,
        sequence: nextSequence, ciphertext: toHex(packed.ciphertext),
        signal: serializeSignal(packed.recipientEnvelope),
      })
      trafficSize.current = frame.length
      trafficCiphertextLength.current = packed.ciphertext.length
      socket.send(session.peerId, MSG.MESSAGE, frame)
      queued = true
      rotation.current?.onMessage()
      if (rotation.current?.rotating) setRotating(true)
      setMessages(current => [...current, { id, direction: 'out', status: 'Sent', text: draft }])
      setDraft('')
    } catch (failure) {
      setError(failure.message)
    } finally {
      if (!queued && packed) {
        if (messageIdHex) {
          const held = outbound.current.get(messageIdHex)
          if (held) clearTimeout(held.purgeTimer)
          outbound.current.delete(messageIdHex)
        }
        wipe(packed.senderShare)
        try {
          await custodian.delete(packed.custodianRecord.key)
        } catch { /* The deposited blob remains inaccessible and expires within one hour. */ }
        wipe(packed.custodianRecord.key)
      }
      wipe(capability)
      sending.current = false
      setBusy(false)
    }
  }

  async function verifyAndOpen(id) {
    const held = inbound.current.get(id)
    if (!held) return
    setBusy(true)
    setError('')
    try {
      if (!credentialRef.current) throw new Error('Device credential unavailable')
      const options = await custodian.challenge(held.storageKey)
      const challenge = toHex(fromBase64url(options.challenge))
      const assertion = await getAssertion(credentialRef.current, options)
      const result = await custodian.retrieve(held.storageKey, challenge, assertion)
      held.custodianShare = await decryptShareCustodian(
        held.capabilityToken, result.blob, held.messageId, activeRef.current.sessionId,
      )
      setMessages(current => current.map(message =>
        message.id === id ? { ...message, status: 'Waiting for sender share' } : message,
      ))
      await sendControl(MSG.FRAGMENT, { kind: 'release-request', id, receipt: result.receipt })
    } catch (failure) {
      wipe(held.custodianShare)
      held.custodianShare = null
      setMessages(current => current.map(message =>
        message.id === id ? { ...message, status: 'Device verification required' } : message,
      ))
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  async function revokeSession() {
    const session = activeRef.current
    if (!session) return
    setBusy(true)
    setError('')
    try {
      await sendTombstone(socket, session.peerId, session.sessionId, user.signingPrivateKey, 'revoked')
      const keys = endSession()
      trustedPeer.current = null
      renewing.current = false
      await deleteCustodianKeys(keys)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  async function panic() {
    setBusy(true)
    setError('')
    try {
      await panicWipe({
        socket, session: activeRef.current, signingPrivateKey: user.signingPrivateKey,
        clearMemory: () => {
          endSession()
          trustedPeer.current = null
          renewing.current = false
          user.signalStore.memory?.clear()
          outgoing.current = null
          setAwaitingPeer(false)
          setPending(null)
          setDraft('')
        },
      })
      onPanic()
    } catch (failure) {
      onPanic(failure.message)
    }
  }

  return (
    <section className="chat-workspace">
      <header className="workspace-header">
        <div>
          <h2>{active ? 'Private session' : 'Your next conversation'}</h2>
          <p className="workspace-subtitle">
            {active ? 'Share messages with your verified peer.' : 'Verify your device and a peer to begin.'}
          </p>
        </div>
        <button className="button button--danger" disabled={busy} onClick={panic}>Panic wipe this device</button>
      </header>
      {error && <p className="notice notice--error" role="alert">{error}</p>}
      {sessionState === STATE.DELAYED && <p className="notice" role="status">Relay connection lost. Session delayed.</p>}
      {sessionState === STATE.FROZEN && <p className="notice notice--error" role="status">Session frozen after failed authentication.</p>}
      <div className="device-panel">
        <div className="device-panel-copy">
          <span className="detail-label">Device verification</span>
          <p>{credentialId ? 'Enrolled and ready for custodian access' : 'Enroll device verification to access custodian shares.'}</p>
        </div>
        {!credentialId && <button className="button button--secondary" disabled={busy} onClick={enrollDevice}>Enroll device verification</button>}
        {credentialId && <span className="status-pill"><span aria-hidden="true" className="status-dot" />Ready</span>}
      </div>
      {pending && !active && (
        <div className="session-panel">
          <h3>Incoming session request</h3>
          <p className="form-intro">Confirm this peer’s fingerprint with them before accepting.</p>
          <div className="read-only-detail"><span className="detail-label">From</span><code>{pending.senderId}</code></div>
          <div className="read-only-detail"><span className="detail-label">Peer fingerprint</span><code>{pending.peer.fingerprint}</code></div>
          <label htmlFor="incoming-fingerprint">Expected sender fingerprint</label>
          <input id="incoming-fingerprint" aria-label="Expected sender fingerprint" value={incomingFingerprint}
            onChange={event => setIncomingFingerprint(event.target.value)} />
          <button className="button button--primary" disabled={busy || !credentialId} onClick={acceptHandshake}>Accept verified peer</button>
        </div>
      )}
      {!active && !pending && (
        <div className="session-panel">
          <h3>Start a session</h3>
          <p className="form-intro">Enter the peer’s ID and the fingerprint you confirmed with them.</p>
          <label htmlFor="recipient-id">Recipient user ID</label>
          <input id="recipient-id" aria-label="Recipient user ID" placeholder="Recipient user ID" value={recipientId}
            onChange={event => setRecipientId(event.target.value)} />
          <label htmlFor="recipient-fingerprint">Expected recipient fingerprint</label>
          <input id="recipient-fingerprint" aria-label="Expected recipient fingerprint" placeholder="Recipient fingerprint"
            value={expectedFingerprint} onChange={event => setExpectedFingerprint(event.target.value)} />
          <button className="button button--primary" disabled={busy || !credentialId || !socket.connected || awaitingPeer} onClick={startHandshake}>
            {awaitingPeer ? 'Waiting for peer…' : 'Request session'}
          </button>
        </div>
      )}
      {active && (
        <div className="conversation">
          <div className="conversation-heading">
            <div>
              <span className="detail-label">Session with</span>
              <h3 className="peer-id">{active.peerId}</h3>
              <p className="session-id">Session ID: <code>{toHex(active.sessionId).slice(0, 32)}…</code></p>
            </div>
            <button className="button button--secondary" disabled={busy} onClick={revokeSession}>Revoke session</button>
          </div>
          <div className="conversation-meta">
            <span className={peerCredentialId ? 'status-pill' : 'status-pill status-pill--waiting'}>
              <span aria-hidden="true" className="status-dot" />
              {peerCredentialId ? 'Peer device ready' : 'Waiting for peer device'}
            </span>
            {!peerCredentialId && <button className="button button--text" disabled={busy} onClick={() => sendControl(
              MSG.KEY_REQ, { credentialId: credentialRef.current },
            ).catch(failure => setError(failure.message))}>Retry device exchange</button>}
          </div>
          <p className="session-note">Keep this page open until the recipient opens the message; your sender share is held in memory.</p>
          {rotating && <p className="notice" role="status">Session renewing after a short share grace period.</p>}
          <div className="message-list" aria-label="Messages">
            {messages.length === 0 && <p className="empty-messages">No messages yet. Your conversation will appear here.</p>}
            {messages.map(message => (
              <div className={`message-row message-row--${message.direction}`} key={message.id}>
                <div className="message-bubble">
                  {message.text && <p className="message-text">{message.text}</p>}
                  <p className="message-status">{message.direction === 'in' ? 'Received' : 'Sent'} · {message.status}</p>
                  {message.direction === 'in' && message.status === 'Device verification required' && (
                    <button className="button button--secondary" disabled={busy} onClick={() => verifyAndOpen(message.id)}>Verify and open</button>
                  )}
                </div>
              </div>
            ))}
          </div>
          <div className="composer">
            <label htmlFor="message-draft">Message</label>
            <div className="composer-controls">
              <textarea id="message-draft" aria-label="Message" placeholder="Write a message…" value={draft} maxLength={16000}
                onChange={event => setDraft(event.target.value)} />
              <button className="button button--primary" disabled={busy || rotating || !peerCredentialId || !draft.trim()} onClick={sendMessage}>Send encrypted message</button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
