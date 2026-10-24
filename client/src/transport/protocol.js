import { fromHex, toHex } from '../crypto/identity.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

export function encodeJson(value) {
  return encoder.encode(JSON.stringify(value))
}

export function decodeJson(bytes) {
  return JSON.parse(decoder.decode(bytes))
}

export function serializeSignal(envelope) {
  const body = typeof envelope.body === 'string'
    ? Uint8Array.from(envelope.body, character => character.charCodeAt(0))
    : new Uint8Array(envelope.body)
  if (![1, 3].includes(envelope.type)) throw new Error('Invalid Signal message type')
  return { type: envelope.type, body: toHex(body) }
}

export function deserializeSignal(value) {
  if (![1, 3].includes(value?.type) || typeof value.body !== 'string'
      || value.body.length > 2 * 1024 * 1024) throw new Error('Invalid Signal envelope')
  const bytes = fromHex(value.body, value.body.length / 2)
  let body = ''
  for (const byte of bytes) body += String.fromCharCode(byte)
  return { type: value.type, body }
}
