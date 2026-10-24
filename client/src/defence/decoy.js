import { encodeJson, serializeSignal } from '../transport/protocol.js'
import { toHex } from '../crypto/identity.js'
import { encryptMessage } from '../crypto/signal.js'

function randomBytes(length) {
  const bytes = new Uint8Array(length)
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65536, length)))
  }
  return bytes
}

export function encodeTrafficFrame(data, minimumSize = 2048) {
  const frame = { ...data, pad: '' }
  const size = encodeJson(frame).length
  const target = Math.max(minimumSize, 2 ** Math.ceil(Math.log2(size)))
  frame.pad = '0'.repeat(target - size)
  return encodeJson(frame)
}

export async function createDecoyFrame(store, peerId, sessionId, sequence,
                                       minimumSize = 2048, ciphertextLength = 1052) {
  const id = toHex(crypto.getRandomValues(new Uint8Array(16)))
  const envelope = await encryptMessage(store, peerId, encodeJson({
    v: 1, session: toHex(sessionId), id, sequence, kind: 'd',
    share: toHex(crypto.getRandomValues(new Uint8Array(32))),
    capability: toHex(crypto.getRandomValues(new Uint8Array(32))),
  }))
  return encodeTrafficFrame({
    v: 1, session: toHex(sessionId), id, sequence,
    ciphertext: toHex(randomBytes(ciphertextLength)),
    signal: serializeSignal(envelope),
  }, minimumSize)
}

export class DecoyTraffic {
  constructor(send, intervalMs = 6000) {
    this.send = send
    this.intervalMs = intervalMs
    this.timer = null
    this.inFlight = false
  }

  start() {
    if (this.timer !== null) return
    this.timer = setInterval(async () => {
      if (this.inFlight) return
      this.inFlight = true
      try {
        await this.send()
      } catch (error) {
        console.error('Decoy send failed', error)
      } finally {
        this.inFlight = false
      }
    }, this.intervalMs)
  }

  stop() {
    if (this.timer !== null) clearInterval(this.timer)
    this.timer = null
  }
}
