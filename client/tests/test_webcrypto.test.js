import { expect, test } from 'vitest'
import { generateAESKey, aesGCMEncrypt, aesGCMDecrypt, hkdf, wipe } from '../../client/src/crypto/webcrypto.js'

test('AES Key generation and encryption/decryption', async () => {
  const key = await generateAESKey()
  const plaintext = new TextEncoder().encode('Hello Mystere')
  const aad = new TextEncoder().encode('AAD')

  const encrypted = await aesGCMEncrypt(key, plaintext, aad)
  expect(encrypted).toBeDefined()
  expect(encrypted.length).toBeGreaterThan(12)

  const decrypted = await aesGCMDecrypt(key, encrypted, aad)
  expect(new TextDecoder().decode(decrypted)).toBe('Hello Mystere')
})

test('HKDF derivation', async () => {
  const keyMaterial = new Uint8Array(32).fill(1)
  const salt = new Uint8Array(32).fill(0)
  const info = 'mystere_root_v1'

  const derived = await hkdf(keyMaterial, salt, info)
  expect(derived.length).toBe(32)

  const derived2 = await hkdf(keyMaterial, salt, info)
  expect(derived).toEqual(derived2)
})

test('Wipe utility', () => {
  const data = new Uint8Array([1, 2, 3, 4])
  wipe(data)
  expect(data).toEqual(new Uint8Array([0, 0, 0, 0]))
})
