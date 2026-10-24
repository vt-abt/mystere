import { fromHex, toHex } from '../crypto/identity.js'
import { encodeJson, decodeJson } from '../transport/protocol.js'
import { MSG } from '../transport/messages.js'

const MAX_AGE_MS = 5 * 60 * 1000

export async function createTombstone(sessionId, privateKey, reason = 'revoked') {
  const payload = encodeJson({
    v: 1, session: toHex(sessionId), timestamp: Date.now(), reason,
    nonce: toHex(crypto.getRandomValues(new Uint8Array(16))),
  })
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, payload))
  return encodeJson({ payload: toHex(payload), signature: toHex(signature) })
}

export async function sendTombstone(socket, peerId, sessionId, privateKey, reason) {
  socket.send(peerId, MSG.TOMBSTONE, await createTombstone(sessionId, privateKey, reason))
}

export async function verifyTombstone(bytes, publicKey, expectedSessionId, seenNonces) {
  const envelope = decodeJson(bytes)
  const payload = fromHex(envelope.payload, envelope.payload.length / 2)
  const signature = fromHex(envelope.signature, 64)
  if (!await crypto.subtle.verify('Ed25519', publicKey, signature, payload)) {
    throw new Error('Invalid tombstone signature')
  }
  const data = decodeJson(payload)
  if (data.v !== 1 || data.session !== toHex(expectedSessionId)
      || !Number.isSafeInteger(data.timestamp)
      || Math.abs(Date.now() - data.timestamp) > MAX_AGE_MS
      || !['revoked', 'rotation', 'panic'].includes(data.reason)) {
    throw new Error('Invalid tombstone context')
  }
  fromHex(data.nonce, 16)
  if (seenNonces.has(data.nonce)) throw new Error('Replayed tombstone')
  seenNonces.add(data.nonce)
  return data
}
