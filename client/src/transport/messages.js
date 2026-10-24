export const MSG = {
  MESSAGE:    0x01,
  FRAGMENT:   0x02,
  TOMBSTONE:  0x04,
  COMMIT_REQ: 0x07,
  COMMIT_ACK: 0x08,
  KEY_REQ:    0x09,
  KEY_RESP:   0x0A,
}

export function uuidToBytes(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error('Invalid user ID')
  }
  return Uint8Array.from(value.replaceAll('-', '').match(/.{2}/g), byte => Number.parseInt(byte, 16))
}

export function bytesToUuid(bytes) {
  if (bytes.length !== 16) throw new Error('Invalid user ID bytes')
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
