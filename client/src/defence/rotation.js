import { hkdf } from '../crypto/webcrypto.js'

export const ROTATION_GRACE_MS = 30_000

export async function computeRotationThreshold(sessionId) {
  if (!(sessionId instanceof Uint8Array) || sessionId.length !== 64) throw new Error('Invalid session ID')
  const bytes = await hkdf(sessionId, new Uint8Array(32), 'mystere-session-rotation-v1', 4)
  return 50 + new DataView(bytes.buffer).getUint32(0) % 20
}

export class RotationManager {
  constructor(sessionId, onRotate, graceMs = ROTATION_GRACE_MS) {
    this.sessionId = sessionId
    this.onRotate = onRotate
    this.graceMs = graceMs
    this.messageCount = 0
    this.threshold = Number.POSITIVE_INFINITY
    this.timer = null
    this.rotating = false
  }

  async init() { this.threshold = await computeRotationThreshold(this.sessionId) }

  onMessage() {
    if (this.rotating) return
    this.messageCount++
    if (this.messageCount < this.threshold) return
    this.rotating = true
    this.timer = setTimeout(() => {
      this.timer = null
      Promise.resolve(this.onRotate()).catch(error => console.error('Session renewal failed', error))
    }, this.graceMs)
  }

  stop() {
    if (this.timer !== null) clearTimeout(this.timer)
    this.timer = null
  }
}
