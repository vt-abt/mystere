import { MSG } from '../transport/messages.js'
import { uuidToBytes } from '../transport/messages.js'

const MAX_AGE_MS = 5 * 60 * 1000

function timestampBytes() {
  const bytes = new Uint8Array(8)
  new DataView(bytes.buffer).setBigUint64(0, BigInt(Date.now()))
  return bytes
}

function fresh(bytes, offset) {
  const value = Number(new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0))
  return Number.isSafeInteger(value) && Math.abs(Date.now() - value) <= MAX_AGE_MS
}

function sameBytes(a, b) {
  return a.length === b.length && a.every((byte, index) => byte === b[index])
}

export async function createSessionRequest(identityKeyPair, targetId) {
  const target = uuidToBytes(targetId)
  const nonce = crypto.getRandomValues(new Uint8Array(32))
  const timestamp = timestampBytes()

  // Payload: [16 bytes target UUID][32 bytes nonce][8 bytes timestamp]
  const payload = new Uint8Array(56)
  payload.set(target, 0)
  payload.set(nonce, 16)
  payload.set(timestamp, 48)

  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    identityKeyPair.privateKey,
    payload
  )

  return {
    payload,
    signature: new Uint8Array(signature),
    type: MSG.COMMIT_REQ
  }
}

export async function createSessionAck(identityKeyPair, sessionRequest) {
  const requestHash = new Uint8Array(
    await crypto.subtle.digest('SHA-512', sessionRequest.payload)
  )
  const nonce = crypto.getRandomValues(new Uint8Array(32))
  const timestamp = timestampBytes()

  // Payload: [64 bytes requestHash][32 bytes nonce][8 bytes timestamp]
  const payload = new Uint8Array(104)
  payload.set(requestHash, 0)
  payload.set(nonce, 64)
  payload.set(timestamp, 96)

  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    identityKeyPair.privateKey,
    payload
  )

  return {
    payload,
    signature: new Uint8Array(signature),
    type: MSG.COMMIT_ACK
  }
}

export async function computeSessionId(requestPayload, ackPayload) {
  const combined = new Uint8Array(requestPayload.length + ackPayload.length)
  combined.set(requestPayload, 0)
  combined.set(ackPayload, requestPayload.length)

  return new Uint8Array(await crypto.subtle.digest('SHA-512', combined))
}

export async function verifyCommitmentSignature(publicKey, payload, signature) {
  return crypto.subtle.verify(
    { name: 'Ed25519' },
    publicKey,
    signature,
    payload
  )
}

export async function verifySessionRequest(publicKey, payload, signature, targetId) {
  const target = uuidToBytes(targetId)
  if (payload.length !== 56 || !sameBytes(payload.slice(0, 16), target) || !fresh(payload, 48)) return false
  return verifyCommitmentSignature(publicKey, payload, signature)
}

export async function verifySessionAck(publicKey, requestPayload, ackPayload, signature) {
  if (ackPayload.length !== 104 || !fresh(ackPayload, 96)) return false
  const expected = new Uint8Array(await crypto.subtle.digest('SHA-512', requestPayload))
  if (!sameBytes(ackPayload.slice(0, 64), expected)) return false
  return verifyCommitmentSignature(publicKey, ackPayload, signature)
}
