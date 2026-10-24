import { bytesToUuid, uuidToBytes } from './messages.js'

const AUTH_PREFIX = new TextEncoder().encode('MYSTERE_WS_V1')

export function outboundFrame(recipientId, type, payload) {
  const recipient = uuidToBytes(recipientId)
  const frame = new Uint8Array(17 + payload.length)
  frame.set(recipient)
  frame[16] = type
  frame.set(payload, 17)
  return frame
}

export function parseDeliveryFrame(frame) {
  if (frame.length < 33) throw new Error('Invalid delivery frame')
  return {
    queueId: frame.slice(0, 16),
    senderId: bytesToUuid(frame.slice(16, 32)),
    type: frame[32],
    payload: frame.slice(33),
  }
}

export class MystereSocket {
  constructor(url, userId, signingPrivateKey, onMessage) {
    this.url = `${url}/${userId}`
    this.userId = userId
    this.signingPrivateKey = signingPrivateKey
    this.socket = null
    this.onMessage = onMessage
    this.pending = []
    this.processing = Promise.resolve()
    this.connected = false
  }

  connect() {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(this.url)
      this.socket = socket
      socket.binaryType = 'arraybuffer'
      let state = 'challenge'

      socket.onmessage = async event => {
        try {
          const bytes = new Uint8Array(event.data)
          if (state === 'challenge') {
            if (bytes.length !== 33 || bytes[0] !== 0) throw new Error('Invalid relay challenge')
            const userId = uuidToBytes(this.userId)
            const signed = new Uint8Array(AUTH_PREFIX.length + 16 + 32)
            signed.set(AUTH_PREFIX)
            signed.set(userId, AUTH_PREFIX.length)
            signed.set(bytes.slice(1), AUTH_PREFIX.length + 16)
            const signature = await crypto.subtle.sign('Ed25519', this.signingPrivateKey, signed)
            socket.send(signature)
            state = 'confirmation'
          } else if (state === 'confirmation') {
            if (bytes.length !== 2 || bytes[0] !== 0 || bytes[1] !== 1) throw new Error('Relay authentication failed')
            state = 'ready'
            this.connected = true
            resolve()
          } else {
            const frame = parseDeliveryFrame(bytes)
            const handler = this.onMessage
            if (handler) {
              this.processing = this.processing.then(() => handler(frame))
              await this.processing
            } else this.pending.push(frame)
          }
        } catch (error) {
          if (state !== 'ready') reject(error)
          else console.error('Invalid relay message', error)
          socket.close()
        }
      }
      socket.onerror = () => {
        if (state !== 'ready') reject(new Error('Relay connection failed'))
      }
      socket.onclose = () => {
        this.connected = false
        this.onClose?.()
        if (state !== 'ready') reject(new Error('Relay connection closed before authentication'))
      }
    })
  }

  async setMessageHandler(handler) {
    this.onMessage = handler
    while (this.pending.length) {
      const frame = this.pending.shift()
      this.processing = this.processing.then(() => handler(frame))
    }
    await this.processing
  }

  send(recipientId, type, payload) {
    if (!this.connected) throw new Error('Socket not authenticated')
    this.socket.send(outboundFrame(recipientId, type, payload))
  }

  acknowledge(queueId) {
    if (!this.connected || queueId.every(byte => byte === 0)) return
    this.send('00000000-0000-0000-0000-000000000000', 0x0B, queueId)
  }

  close() {
    this.socket?.close()
  }
}
