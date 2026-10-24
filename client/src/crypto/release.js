import { fromHex } from './identity.js'

const prefix = new TextEncoder().encode('MYSTERE_RELEASE_V1')
const maxAgeMs = 5 * 60 * 1000

export async function verifyReleaseReceipt(receipt, expectedStorageKey, publicKeyBytes) {
  const payload = fromHex(receipt.payload, prefix.length + 32 + 32 + 8)
  const signature = fromHex(receipt.signature, 64)
  if (!prefix.every((byte, index) => payload[index] === byte)) return false
  const keyOffset = prefix.length
  if (!expectedStorageKey.every((byte, index) => payload[keyOffset + index] === byte)) return false
  const timestamp = Number(new DataView(payload.buffer).getBigUint64(keyOffset + 64))
  if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > maxAgeMs) return false
  const publicKey = await crypto.subtle.importKey('raw', publicKeyBytes, 'Ed25519', false, ['verify'])
  return crypto.subtle.verify('Ed25519', publicKey, signature, payload)
}
