import { expect, test, vi } from 'vitest'
import { SignalProtocolStore } from '../src/crypto/signal-store.js'
import { createSignalIdentity, initSession, encryptMessage, decryptMessage } from '../src/crypto/signal.js'
import { sealMessage, openMessage, prepareOutboundMessage, openInboundMessage } from '../src/crypto/message.js'
import { decryptShareCustodian } from '../src/crypto/capability.js'
import { deserializeSignal, serializeSignal } from '../src/transport/protocol.js'
import { decodeJson } from '../src/transport/protocol.js'
import { createDecoyFrame, encodeTrafficFrame } from '../src/defence/decoy.js'
import { readRecipientMessage } from '../src/crypto/message.js'
import { ensurePrekeys, fromHex } from '../src/crypto/identity.js'

class MemoryStore extends SignalProtocolStore {
  async initDB() { this.memory = new Map() }
  async get(store, key) { return this.memory.get(`${store}:${key}`) }
  async put(store, key, value) { this.memory.set(`${store}:${key}`, value) }
  async remove(store, key) { this.memory.delete(`${store}:${key}`) }
}

test('two real Signal identities exchange encrypted messages', async () => {
  const aliceStore = new MemoryStore()
  const bobStore = new MemoryStore()
  const alice = await createSignalIdentity(aliceStore)
  const bob = await createSignalIdentity(bobStore)
  const bobBundle = {
    registrationId: bob.registrationId,
    identityKey: bob.identityKey,
    signedPreKey: bob.signedPreKey,
    preKey: bob.preKeys[0],
  }

  await initSession(aliceStore, 'bob', bobBundle)
  const encrypted = await encryptMessage(aliceStore, 'bob', new TextEncoder().encode('Hello Bob'))
  expect(encrypted.type).toBe(3)
  const plaintext = await decryptMessage(bobStore, 'alice', deserializeSignal(serializeSignal(encrypted)))
  expect(new TextDecoder().decode(plaintext)).toBe('Hello Bob')

  const reply = await encryptMessage(bobStore, 'alice', new TextEncoder().encode('Hello Alice'))
  const replyPlaintext = await decryptMessage(aliceStore, 'bob', reply)
  expect(new TextDecoder().decode(replyPlaintext)).toBe('Hello Alice')
  expect(alice.identityKey).toBeDefined()
})

test('message opens only after all three shares reach the recipient', async () => {
  const aliceStore = new MemoryStore()
  const bobStore = new MemoryStore()
  await createSignalIdentity(aliceStore)
  const bob = await createSignalIdentity(bobStore)
  await initSession(aliceStore, 'bob', {
    registrationId: bob.registrationId,
    identityKey: bob.identityKey,
    signedPreKey: bob.signedPreKey,
    preKey: bob.preKeys[0],
  })

  const sessionId = crypto.getRandomValues(new Uint8Array(64))
  const messageId = crypto.getRandomValues(new Uint8Array(16))
  const capability = crypto.getRandomValues(new Uint8Array(32))
  const sealed = await sealMessage('three domains', sessionId, messageId, 1, capability)
  const signalEnvelope = await encryptMessage(aliceStore, 'bob', sealed.shareY)
  const recipientShare = new Uint8Array(await decryptMessage(bobStore, 'alice', signalEnvelope))
  const custodianShare = await decryptShareCustodian(
    capability, sealed.custodianBlob, messageId, sessionId,
  )

  const plaintext = await openMessage(
    sealed.ciphertext, sessionId, messageId, 1,
    sealed.shareX, recipientShare, custodianShare,
  )
  expect(new TextDecoder().decode(plaintext)).toBe('three domains')
  await expect(openMessage(
    sealed.ciphertext, sessionId, messageId, 1,
    new Uint8Array(32), recipientShare, custodianShare,
  )).rejects.toThrow()
  await expect(openMessage(
    sealed.ciphertext, sessionId, messageId, 2,
    sealed.shareX, recipientShare, custodianShare,
  )).rejects.toThrow()
})

test('message lengths are hidden within encrypted size buckets', async () => {
  const sessionId = crypto.getRandomValues(new Uint8Array(64))
  const capability = crypto.getRandomValues(new Uint8Array(32))
  const short = await sealMessage('a', sessionId, crypto.getRandomValues(new Uint8Array(16)), 1, capability)
  const longer = await sealMessage('a'.repeat(900), sessionId,
    crypto.getRandomValues(new Uint8Array(16)), 2, capability)
  const nextBucket = await sealMessage('a'.repeat(1100), sessionId,
    crypto.getRandomValues(new Uint8Array(16)), 3, capability)
  expect(short.ciphertext.length).toBe(longer.ciphertext.length)
  expect(nextBucket.ciphertext.length).toBeGreaterThan(short.ciphertext.length)
})

test('outbound package separates Signal and custodian material', async () => {
  const aliceStore = new MemoryStore()
  const bobStore = new MemoryStore()
  await createSignalIdentity(aliceStore)
  const bob = await createSignalIdentity(bobStore)
  await initSession(aliceStore, 'bob', {
    registrationId: bob.registrationId,
    identityKey: bob.identityKey,
    signedPreKey: bob.signedPreKey,
    preKey: bob.preKeys[0],
  })
  const sessionId = crypto.getRandomValues(new Uint8Array(64))
  const messageId = crypto.getRandomValues(new Uint8Array(16))
  const capability = crypto.getRandomValues(new Uint8Array(32))
  const packed = await prepareOutboundMessage(
    aliceStore, 'bob', 'separated paths', sessionId, messageId, 1, capability,
  )
  packed.recipientEnvelope = deserializeSignal(serializeSignal(packed.recipientEnvelope))
  expect(packed.custodianRecord.key).toHaveLength(32)
  expect(packed.custodianRecord.value).not.toEqual(packed.senderShare)
  const custodianShare = await decryptShareCustodian(
    capability, packed.custodianRecord.value, messageId, sessionId,
  )
  const opened = await openInboundMessage(
    bobStore, 'alice', packed, sessionId, messageId, 1, custodianShare,
  )
  expect(new TextDecoder().decode(opened)).toBe('separated paths')
})

test('cover traffic decrypts as a decoy without asking for custodian release', async () => {
  const aliceStore = new MemoryStore()
  const bobStore = new MemoryStore()
  await createSignalIdentity(aliceStore)
  const bob = await createSignalIdentity(bobStore)
  await initSession(aliceStore, 'bob', {
    registrationId: bob.registrationId,
    identityKey: bob.identityKey,
    signedPreKey: bob.signedPreKey,
    preKey: bob.preKeys[0],
  })
  const sessionId = crypto.getRandomValues(new Uint8Array(64))
  const frame = await createDecoyFrame(aliceStore, 'bob', sessionId, 1)
  expect(frame.length).toBeGreaterThanOrEqual(2048)
  expect(Number.isInteger(Math.log2(frame.length))).toBe(true)
  const data = decodeJson(frame)
  const result = await readRecipientMessage(
    bobStore, 'alice', deserializeSignal(data.signal),
    sessionId, fromHex(data.id, 16), 1,
  )
  expect(result).toEqual({ decoy: true })
  const wrong = await createDecoyFrame(aliceStore, 'bob', sessionId, 2)
  const wrongData = decodeJson(wrong)
  await expect(readRecipientMessage(
    bobStore, 'alice', deserializeSignal(wrongData.signal),
    new Uint8Array(64), fromHex(wrongData.id, 16), 2,
  )).rejects.toThrow('context mismatch')
})

test('cover and real traffic expose matching field lengths to the relay', async () => {
  const aliceStore = new MemoryStore()
  await createSignalIdentity(aliceStore)
  const bob = await createSignalIdentity(new MemoryStore())
  await initSession(aliceStore, 'bob', {
    registrationId: bob.registrationId,
    identityKey: bob.identityKey,
    signedPreKey: bob.signedPreKey,
    preKey: bob.preKeys[0],
  })
  const sessionId = crypto.getRandomValues(new Uint8Array(64))
  for (let sequence = 1; sequence <= 2; sequence++) {
    const packed = await prepareOutboundMessage(
      aliceStore, 'bob', 'hello', sessionId,
      crypto.getRandomValues(new Uint8Array(16)), sequence,
      crypto.getRandomValues(new Uint8Array(32)),
    )
    if (sequence === 1) continue
    const real = encodeTrafficFrame({
      v: 1, session: 'a'.repeat(128), id: 'b'.repeat(32), sequence,
      ciphertext: Array.from(packed.ciphertext, byte => byte.toString(16).padStart(2, '0')).join(''),
      signal: serializeSignal(packed.recipientEnvelope),
    })
    const decoy = await createDecoyFrame(
      aliceStore, 'bob', sessionId, 3, real.length, packed.ciphertext.length,
    )
    const realData = decodeJson(real)
    const decoyData = decodeJson(decoy)
    expect(decoy.length).toBe(real.length)
    expect(decoyData.ciphertext.length).toBe(realData.ciphertext.length)
    expect(decoyData.signal.body.length).toBe(realData.signal.body.length)
  }
})

test('prekey refill signs the exact keys stored for future sessions', async () => {
  const signing = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])
  const store = new MemoryStore()
  const user = {
    userId: '00000000-0000-0000-0000-000000000001',
    signingPrivateKey: signing.privateKey,
    signalStore: store,
    nextPreKeyId: 6,
    remainingPrekeys: 1,
  }
  const fetchMock = vi.fn().mockResolvedValue({ ok: true })
  vi.stubGlobal('fetch', fetchMock)
  try {
    await ensurePrekeys(user, 'http://localhost:8000')
    const request = JSON.parse(fetchMock.mock.calls[0][1].body)
    expect(request.one_time_prekeys).toHaveLength(20)
    expect(user.remainingPrekeys).toBe(21)
    expect(user.nextPreKeyId).toBe(26)
    const prefix = new TextEncoder().encode('MYSTERE_REPLENISH_V1')
    const payload = new Uint8Array(prefix.length + 16 + 20 * 37)
    payload.set(prefix)
    payload[16 + prefix.length - 1] = 1
    let offset = prefix.length + 16
    for (const entry of request.one_time_prekeys) {
      new DataView(payload.buffer).setUint32(offset, entry.key_id)
      payload.set(fromHex(entry.pubkey, 33), offset + 4)
      expect(await store.loadPreKey(entry.key_id)).toBeDefined()
      offset += 37
    }
    expect(await crypto.subtle.verify('Ed25519', signing.publicKey,
      fromHex(request.signature, 64), payload)).toBe(true)
  } finally {
    vi.unstubAllGlobals()
  }
})
