import { expect, test, vi } from 'vitest'
import { computeRotationThreshold, RotationManager } from '../src/defence/rotation.js'
import { createTombstone, verifyTombstone } from '../src/defence/tombstone.js'
import { panicWipe } from '../src/defence/panic.js'
import { encodeTrafficFrame } from '../src/defence/decoy.js'
import { STATE, EVENT, SessionStateMachine } from '../src/state/machine.js'
import { decodeJson, encodeJson } from '../src/transport/protocol.js'
import { toHex } from '../src/crypto/identity.js'
import { MSG } from '../src/transport/messages.js'

test('rotation threshold is session bound and old shares expire after grace', async () => {
  vi.useFakeTimers()
  try {
    const session = crypto.getRandomValues(new Uint8Array(64))
    const threshold = await computeRotationThreshold(session)
    expect(threshold).toBeGreaterThanOrEqual(50)
    expect(threshold).toBeLessThan(70)
    expect(await computeRotationThreshold(session)).toBe(threshold)
    const rotate = vi.fn()
    const manager = new RotationManager(session, rotate, 30)
    await manager.init()
    for (let i = 0; i < threshold - 1; i++) manager.onMessage()
    expect(manager.rotating).toBe(false)
    manager.onMessage()
    expect(manager.rotating).toBe(true)
    vi.advanceTimersByTime(29)
    expect(rotate).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1)
    expect(rotate).toHaveBeenCalledTimes(1)
    manager.stop()
    const cancelled = new RotationManager(session, rotate, 30)
    await cancelled.init()
    for (let i = 0; i < threshold; i++) cancelled.onMessage()
    cancelled.stop()
    vi.advanceTimersByTime(30)
    expect(rotate).toHaveBeenCalledTimes(1)
  } finally {
    vi.useRealTimers()
  }
})

test('signed tombstone rejects a wrong session, mutation, and replay', async () => {
  const keys = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])
  const session = crypto.getRandomValues(new Uint8Array(64))
  const bytes = await createTombstone(session, keys.privateKey)
  const seen = new Set()
  await expect(verifyTombstone(bytes, keys.publicKey, new Uint8Array(64), seen)).rejects.toThrow()
  expect((await verifyTombstone(bytes, keys.publicKey, session, seen)).session).toBe(toHex(session))
  await expect(verifyTombstone(bytes, keys.publicKey, session, seen)).rejects.toThrow('Replayed')
  const changed = decodeJson(bytes)
  changed.payload = changed.payload.replace(/^../, changed.payload.startsWith('00') ? '01' : '00')
  await expect(verifyTombstone(encodeJson(changed), keys.publicKey, session, new Set()))
    .rejects.toThrow('signature')
})

test('network delay remains separate from authentication failure', async () => {
  const freeze = vi.fn()
  const machine = new SessionStateMachine(freeze)
  await machine.handleEvent(EVENT.TIMEOUT)
  expect(machine.state).toBe(STATE.DELAYED)
  await machine.handleEvent(EVENT.HEALTHY_MESSAGE)
  expect(machine.state).toBe(STATE.HEALTHY)
  await machine.handleEvent(EVENT.OUT_OF_ORDER)
  expect(machine.state).toBe(STATE.SUSPECTED)
  await machine.handleEvent(EVENT.HEALTHY_MESSAGE)
  expect(machine.state).toBe(STATE.HEALTHY)
  await machine.handleEvent(EVENT.AUTH_FAILURE)
  await machine.handleEvent(EVENT.AUTH_FAILURE)
  expect(machine.state).toBe(STATE.FROZEN)
  expect(freeze).toHaveBeenCalledTimes(1)
})

test('real and cover frames use the same fixed size buckets', () => {
  const fields = {
    v: 1, session: 'a'.repeat(128), id: 'b'.repeat(32), sequence: 1,
    ciphertext: 'c'.repeat(128), signal: { type: 1, body: 'd'.repeat(512) },
  }
  const real = encodeTrafficFrame(fields)
  const cover = encodeTrafficFrame({ ...fields, id: 'e'.repeat(32) })
  expect(real.length).toBe(2048)
  expect(cover.length).toBe(real.length)
  expect(decodeJson(real).pad).toHaveLength(decodeJson(cover).pad.length)
})

test('panic erases only Mystere storage and waits for completion', async () => {
  const deleted = []
  const old = globalThis.indexedDB
  vi.stubGlobal('indexedDB', {
    deleteDatabase(name) {
      deleted.push(name)
      const request = {}
      queueMicrotask(() => request.onsuccess())
      return request
    },
  })
  const clearMemory = vi.fn()
  const close = vi.fn()
  try {
    await panicWipe({ socket: { connected: false, close }, clearMemory })
    expect(deleted).toEqual(['mystere_signal_store', 'mystere_idb'])
    expect(clearMemory).toHaveBeenCalledTimes(1)
    expect(close).toHaveBeenCalledTimes(1)
  } finally {
    vi.stubGlobal('indexedDB', old)
    vi.unstubAllGlobals()
  }
})

test('panic sends a verifiable tombstone before closing a connected session', async () => {
  const keys = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])
  const sessionId = crypto.getRandomValues(new Uint8Array(64))
  const send = vi.fn()
  const close = vi.fn()
  vi.stubGlobal('indexedDB', {
    deleteDatabase() {
      const request = {}
      queueMicrotask(() => request.onsuccess())
      return request
    },
  })
  try {
    await panicWipe({
      socket: { connected: true, send, close },
      session: { peerId: '00000000-0000-0000-0000-000000000001', sessionId },
      signingPrivateKey: keys.privateKey,
      clearMemory: vi.fn(),
    })
    expect(send).toHaveBeenCalledTimes(1)
    expect(send.mock.calls[0][1]).toBe(MSG.TOMBSTONE)
    expect((await verifyTombstone(send.mock.calls[0][2], keys.publicKey, sessionId, new Set())).reason)
      .toBe('panic')
    expect(close).toHaveBeenCalledTimes(1)
  } finally {
    vi.unstubAllGlobals()
  }
})
