import { useState } from 'react'
import { registerIdentity } from '../crypto/identity.js'

const RELAY_API = import.meta.env.VITE_RELAY_API || 'http://localhost:8000'

export default function Session({ onEstablished }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleRegister() {
    setLoading(true)
    setError('')
    try {
      onEstablished(await registerIdentity(RELAY_API))
    } catch (failure) {
      setError(failure.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="session-setup">
      <div className="welcome-mark" aria-hidden="true">M</div>
      <h2>Start a private conversation</h2>
      <p>Register a new identity to connect. This identity lasts until this page is closed or refreshed.</p>
      <button className="button button--primary" onClick={handleRegister} disabled={loading}>
        {loading ? 'Registering…' : 'Register & Connect'}
      </button>
      {error && <p className="notice notice--error" role="alert">{error}</p>}
    </div>
  )
}
