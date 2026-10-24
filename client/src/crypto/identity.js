import { createSignalIdentity } from './signal.js'
import { MemorySignalStore } from './signal-store.js'
import { KeyHelper } from '@privacyresearch/libsignal-protocol-typescript'

const encoder = new TextEncoder()

export function toHex(bytes) {
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('')
}

export function fromHex(hex, length) {
  if (typeof hex !== 'string' || hex.length !== length * 2 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error('Invalid public key')
  }
  return Uint8Array.from(hex.match(/.{2}/g), byte => Number.parseInt(byte, 16))
}

function uint(value, length) {
  const bytes = new Uint8Array(length)
  const view = new DataView(bytes.buffer)
  if (length === 2) view.setUint16(0, value)
  else view.setUint32(0, value)
  return bytes
}

function concat(...parts) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0))
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

export function registrationPayload(signal) {
  return concat(
    encoder.encode('MYSTERE_IDENTITY_V1'),
    new Uint8Array(signal.identityKey),
    uint(signal.registrationId, 2),
    uint(signal.signedPreKey.keyId, 4),
    new Uint8Array(signal.signedPreKey.publicKey),
    new Uint8Array(signal.signedPreKey.signature),
    ...signal.preKeys.flatMap(key => [uint(key.keyId, 4), new Uint8Array(key.publicKey)]),
  )
}

export async function identityFingerprint(signingPublicKey, signalPublicKey) {
  return toHex(await crypto.subtle.digest('SHA-256', concat(
    new Uint8Array(signingPublicKey), new Uint8Array(signalPublicKey),
  )))
}

export async function registerIdentity(relayApi) {
  const signalStore = new MemorySignalStore()
  const signal = await createSignalIdentity(signalStore)
  const signingKeys = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])
  const signingPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', signingKeys.publicKey))
  const proof = new Uint8Array(await crypto.subtle.sign('Ed25519', signingKeys.privateKey, registrationPayload(signal)))
  const response = await fetch(`${relayApi}/keys/identity`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identity_pubkey: toHex(signal.identityKey),
      signing_pubkey: toHex(signingPublicKey),
      registration_id: signal.registrationId,
      signed_prekey_id: signal.signedPreKey.keyId,
      signed_prekey: toHex(signal.signedPreKey.publicKey),
      signed_prekey_sig: toHex(signal.signedPreKey.signature),
      one_time_prekeys: signal.preKeys.map(key => ({ key_id: key.keyId, pubkey: toHex(key.publicKey) })),
      registration_signature: toHex(proof),
    }),
  })
  if (!response.ok) throw new Error(`Registration failed (${response.status})`)
  const { user_id: userId } = await response.json()
  return {
    userId,
    signingPrivateKey: signingKeys.privateKey,
    signingPublicKey,
    signalStore,
    fingerprint: await identityFingerprint(signingPublicKey, signal.identityKey),
    nextPreKeyId: signal.preKeys.length + 1,
    remainingPrekeys: signal.preKeys.length,
  }
}

export async function ensurePrekeys(user, relayApi) {
  if (user.remainingPrekeys > 2) return
  const keys = user.pendingPrekeys || await Promise.all(Array.from({ length: 20 }, (_, index) =>
    KeyHelper.generatePreKey(user.nextPreKeyId + index)))
  user.pendingPrekeys = keys
  const bytes = concat(
    encoder.encode('MYSTERE_REPLENISH_V1'),
    Uint8Array.from(user.userId.replaceAll('-', '').match(/.{2}/g), byte => Number.parseInt(byte, 16)),
    ...keys.flatMap(({ keyId, keyPair }) => [uint(keyId, 4), new Uint8Array(keyPair.pubKey)]),
  )
  const signature = await crypto.subtle.sign('Ed25519', user.signingPrivateKey, bytes)
  for (const { keyId, keyPair } of keys) await user.signalStore.storePreKey(keyId, keyPair)
  const response = await fetch(`${relayApi}/keys/prekeys/replenish`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id: user.userId,
      one_time_prekeys: keys.map(({ keyId, keyPair }) => ({
        key_id: keyId, pubkey: toHex(keyPair.pubKey),
      })),
      signature: toHex(signature),
    }),
  })
  if (!response.ok) throw new Error(`Prekey refill failed (${response.status})`)
  user.nextPreKeyId += keys.length
  user.remainingPrekeys += keys.length
  user.pendingPrekeys = null
}

export async function fetchPeerIdentity(relayApi, userId) {
  const response = await fetch(`${relayApi}/keys/identity/${userId}`)
  if (!response.ok) throw new Error(`Identity lookup failed (${response.status})`)
  const data = await response.json()
  const signingPublicKey = fromHex(data.signing_pubkey, 32)
  const signalPublicKey = fromHex(data.identity_pubkey, 33)
  const publicKey = await crypto.subtle.importKey('raw', signingPublicKey, 'Ed25519', false, ['verify'])
  return {
    ...data,
    signingPublicKey: publicKey,
    fingerprint: await identityFingerprint(signingPublicKey, signalPublicKey),
  }
}
