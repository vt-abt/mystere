import test from 'node:test'
import assert from 'node:assert/strict'

import { generateAESKey, aesGCMEncrypt, aesGCMDecrypt } from '../client/src/crypto/webcrypto.js'
import { splitKey, reconstructKey } from '../client/src/crypto/fragments.js'
import { computeSessionId } from '../client/src/crypto/commitment.js'
import { encryptShareCustodian, decryptShareCustodian, storageKey } from '../client/src/crypto/capability.js'

test('AES-GCM authenticates the session context', async () => {
  const key = await generateAESKey()
  const content = new TextEncoder().encode('private message')
  const context = new TextEncoder().encode('session-a:message-1')
  const ciphertext = await aesGCMEncrypt(key, content, context)

  assert.deepEqual(new Uint8Array(await aesGCMDecrypt(key, ciphertext, context)), content)
  await assert.rejects(aesGCMDecrypt(key, ciphertext, new TextEncoder().encode('session-b:message-1')))
})

test('all three independent shares reconstruct the message key', async () => {
  const messageKey = crypto.getRandomValues(new Uint8Array(32))
  const { shareX, shareY, shareCustodian } = await splitKey(messageKey)

  assert.equal(shareX.length, 32)
  assert.equal(shareY.length, 32)
  assert.equal(shareCustodian.length, 32)
  assert.deepEqual(reconstructKey(shareX, shareY, shareCustodian), messageKey)
})

test('a custodian blob is bound to its message and session', async () => {
  const capability = crypto.getRandomValues(new Uint8Array(32))
  const share = crypto.getRandomValues(new Uint8Array(32))
  const messageId = crypto.getRandomValues(new Uint8Array(16))
  const sessionId = crypto.getRandomValues(new Uint8Array(64))
  const blob = await encryptShareCustodian(capability, share, messageId, sessionId)

  assert.deepEqual(await decryptShareCustodian(capability, blob, messageId, sessionId), share)
  const otherSession = sessionId.slice()
  otherSession[0] ^= 1
  await assert.rejects(decryptShareCustodian(capability, blob, messageId, otherSession))

  const otherMessage = messageId.slice()
  otherMessage[0] ^= 1
  assert.notDeepEqual(await storageKey(capability, messageId), await storageKey(capability, otherMessage))
})

test('session ID changes when either commitment payload changes', async () => {
  const request = crypto.getRandomValues(new Uint8Array(40))
  const acknowledgment = crypto.getRandomValues(new Uint8Array(96))
  const first = await computeSessionId(request, acknowledgment)
  const changed = acknowledgment.slice()
  changed[0] ^= 1

  assert.equal(first.length, 64)
  assert.deepEqual(await computeSessionId(request, acknowledgment), first)
  assert.notDeepEqual(await computeSessionId(request, changed), first)
})
