import { fromHex, toHex } from '../crypto/identity.js'

export class CustodianClient {
  constructor(baseUrl) {
    const url = new URL(baseUrl)
    if (url.protocol !== 'https:' && !(url.protocol === 'http:'
        && ['localhost', '127.0.0.1'].includes(url.hostname))) {
      throw new Error('Custodian requires HTTPS outside local development')
    }
    this.baseUrl = baseUrl.replace(/\/$/, '')
  }

  async request(path, body) {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!response.ok) throw new Error(`Custodian ${path} failed (${response.status})`)
    return response.json()
  }

  registrationOptions() { return this.request('/credentials/options', {}) }

  enroll(challenge, credential) {
    return this.request('/credentials/enroll', { challenge, credential })
  }

  deposit(storageKey, encryptedShare, credentialId, ttl) {
    return this.request('/deposit', {
      key: toHex(storageKey), value: toHex(encryptedShare),
      credential_id: credentialId, ttl,
    })
  }

  delete(storageKey) {
    return this.request('/delete', { key: toHex(storageKey) })
  }

  challenge(storageKey) {
    return this.request('/retrieve/challenge', { key: toHex(storageKey) })
  }

  async retrieve(storageKey, challenge, assertion) {
    const data = await this.request('/retrieve', {
      key: toHex(storageKey), challenge, assertion,
    })
    return { blob: fromHex(data.value, data.value.length / 2), receipt: data.receipt }
  }

  async receiptPublicKey() {
    const response = await fetch(`${this.baseUrl}/receipt-key`)
    if (!response.ok) throw new Error('Custodian receipt key unavailable')
    const data = await response.json()
    return fromHex(data.public_key, 32)
  }
}
