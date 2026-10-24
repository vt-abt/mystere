import { hkdf, aesGCMEncrypt, aesGCMDecrypt, wipe } from './webcrypto.js'

const KDF_CUSTODIAN_ENC  = "custodian_enc_"

async function sha256(data) {
  return crypto.subtle.digest('SHA-256', data)
}

function encodeHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function concat(...arrays) {
  const totalLength = arrays.reduce((acc, value) => acc + value.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const array of arrays) {
    result.set(array, offset)
    offset += array.length
  }
  return result
}

export async function encryptShareCustodian(capabilityToken, shareCustodian, messageId, sessionId) {
  const encoder = new TextEncoder()
  const messageIdBytes = typeof messageId === 'string' ? encoder.encode(messageId) : messageId
  const sessionIdBytes = typeof sessionId === 'string' ? encoder.encode(sessionId) : sessionId

  const encKeyBytes = await hkdf(
    capabilityToken,
    new Uint8Array(32),
    KDF_CUSTODIAN_ENC + encodeHex(messageIdBytes),
    32
  )
  try {
    const encKey = await crypto.subtle.importKey('raw', encKeyBytes, 'AES-GCM', false, ['encrypt'])
    const aad = await sha256(concat(capabilityToken, messageIdBytes, sessionIdBytes))
    const payload = concat(shareCustodian, messageIdBytes, sessionIdBytes)
    return await aesGCMEncrypt(encKey, payload, aad)
  } finally {
    wipe(encKeyBytes)
  }
}

export async function decryptShareCustodian(capabilityToken, blob, messageId, sessionId) {
  const encoder = new TextEncoder()
  const messageIdBytes = typeof messageId === 'string' ? encoder.encode(messageId) : messageId
  const sessionIdBytes = typeof sessionId === 'string' ? encoder.encode(sessionId) : sessionId

  const encKeyBytes = await hkdf(
    capabilityToken,
    new Uint8Array(32),
    KDF_CUSTODIAN_ENC + encodeHex(messageIdBytes),
    32
  )
  try {
    const encKey = await crypto.subtle.importKey('raw', encKeyBytes, 'AES-GCM', false, ['decrypt'])
    const aad = await sha256(concat(capabilityToken, messageIdBytes, sessionIdBytes))
    const payload = new Uint8Array(await aesGCMDecrypt(encKey, blob, aad))
    if (payload.length !== 32 + messageIdBytes.length + sessionIdBytes.length
        || !messageIdBytes.every((byte, index) => payload[32 + index] === byte)
        || !sessionIdBytes.every((byte, index) => payload[32 + messageIdBytes.length + index] === byte)) {
      throw new Error('Custodian blob context mismatch')
    }
    return payload.slice(0, 32)
  } finally {
    wipe(encKeyBytes)
  }
}

export async function storageKey(capabilityToken, messageId) {
  const encoder = new TextEncoder()
  const messageIdBytes = typeof messageId === 'string' ? encoder.encode(messageId) : messageId
  return sha256(concat(capabilityToken, messageIdBytes))
}
