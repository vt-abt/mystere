const encoder = new TextEncoder();

export async function generateAESKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false, // Keep generated key material non-extractable.
    ['encrypt', 'decrypt']
  )
}

export async function aesGCMEncrypt(key, plaintext, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    plaintext
  )
  const result = new Uint8Array(12 + ciphertext.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(ciphertext), 12)
  return result
}

export async function aesGCMDecrypt(key, ivAndCiphertext, aad) {
  const iv = ivAndCiphertext.slice(0, 12)
  const ciphertext = ivAndCiphertext.slice(12)
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    ciphertext
  )
}

export async function hkdf(keyMaterial, salt, info, length = 32) {
  const hkdfKey = await crypto.subtle.importKey(
    'raw', keyMaterial, 'HKDF', false, ['deriveKey', 'deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-512', salt, info: encoder.encode(info) },
    hkdfKey,
    length * 8
  )
  return new Uint8Array(bits)
}

export function wipe(...arrays) {
  for (const arr of arrays) {
    if (arr instanceof Uint8Array) arr.fill(0)
  }
}
