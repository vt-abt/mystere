import { expect, test, vi } from 'vitest'
import { toHex } from '../src/crypto/identity.js'
import { verifyReleaseReceipt } from '../src/crypto/release.js'
import { registerCredential, getAssertion, base64url } from '../src/crypto/webauthn.js'
import { deserializeSignal, serializeSignal } from '../src/transport/protocol.js'

test('sender accepts only a fresh custodian receipt for its storage key', async () => {
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))
  const prefix = new TextEncoder().encode('MYSTERE_RELEASE_V1')
  const key = crypto.getRandomValues(new Uint8Array(32))
  const payload = new Uint8Array(prefix.length + 72)
  payload.set(prefix)
  payload.set(key, prefix.length)
  payload.set(crypto.getRandomValues(new Uint8Array(32)), prefix.length + 32)
  new DataView(payload.buffer).setBigUint64(prefix.length + 64, BigInt(Date.now()))
  const signature = await crypto.subtle.sign('Ed25519', keys.privateKey, payload)
  const receipt = { payload: toHex(payload), signature: toHex(signature) }
  expect(await verifyReleaseReceipt(receipt, key, publicKey)).toBe(true)
  expect(await verifyReleaseReceipt(receipt, new Uint8Array(32), publicKey)).toBe(false)
  const tampered = { ...receipt, signature: '00'.repeat(64) }
  expect(await verifyReleaseReceipt(tampered, key, publicKey)).toBe(false)
  new DataView(payload.buffer).setBigUint64(prefix.length + 64, BigInt(Date.now() - 10 * 60 * 1000))
  const staleSignature = await crypto.subtle.sign('Ed25519', keys.privateKey, payload)
  expect(await verifyReleaseReceipt({
    payload: toHex(payload), signature: toHex(staleSignature),
  }, key, publicKey)).toBe(false)
})

test('WebAuthn client uses custodian challenges and requests user verification', async () => {
  const registrationChallenge = crypto.getRandomValues(new Uint8Array(32))
  const assertionChallenge = crypto.getRandomValues(new Uint8Array(32))
  const id = crypto.getRandomValues(new Uint8Array(32))
  const create = vi.fn().mockResolvedValue({
    id: base64url(id), rawId: id.buffer, type: 'public-key',
    response: { clientDataJSON: new Uint8Array([1]).buffer, attestationObject: new Uint8Array([2]).buffer },
  })
  const get = vi.fn().mockResolvedValue({
    id: base64url(id), rawId: id.buffer, type: 'public-key',
    response: {
      authenticatorData: new Uint8Array([3]).buffer,
      clientDataJSON: new Uint8Array([4]).buffer,
      signature: new Uint8Array([5]).buffer,
    },
  })
  vi.stubGlobal('navigator', { credentials: { create, get } })
  const custodian = {
    registrationOptions: async () => ({
      challenge: base64url(registrationChallenge), rp_id: 'localhost',
      user_id: base64url(crypto.getRandomValues(new Uint8Array(16))),
    }),
    enroll: vi.fn().mockResolvedValue({ credential_id: base64url(id) }),
  }
  try {
    expect(await registerCredential(custodian)).toBe(base64url(id))
    expect(create.mock.calls[0][0].publicKey.authenticatorSelection.userVerification).toBe('required')
    expect(create.mock.calls[0][0].publicKey.challenge).toEqual(registrationChallenge)
    expect(custodian.enroll.mock.calls[0][0]).toBe(toHex(registrationChallenge))
    await getAssertion(base64url(id), { challenge: base64url(assertionChallenge), rp_id: 'localhost' })
    expect(get.mock.calls[0][0].publicKey.userVerification).toBe('required')
    expect(get.mock.calls[0][0].publicKey.challenge).toEqual(assertionChallenge)
  } finally {
    vi.unstubAllGlobals()
  }
})

test('Signal frame serialization preserves binary ciphertext', () => {
  const original = { type: 3, body: String.fromCharCode(0, 1, 127, 128, 255) }
  expect(deserializeSignal(serializeSignal(original))).toEqual(original)
})
