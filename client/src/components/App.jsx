import { useState, useEffect } from 'react'
import Session from './Session.jsx'
import Chat from './Chat.jsx'
import { MystereSocket } from '../transport/socket.js'

function App() {
  const [user, setUser] = useState(null)
  const [socket, setSocket] = useState(null)
  const [connectionError, setConnectionError] = useState('')
  const [wipeComplete, setWipeComplete] = useState(false)
  const [wipeError, setWipeError] = useState('')

  useEffect(() => {
    if (!user) return
    let cancelled = false
    const url = import.meta.env.VITE_RELAY_URL || 'ws://localhost:8000/ws'
    const connection = new MystereSocket(url, user.userId, user.signingPrivateKey)
    connection.connect().then(() => {
      if (cancelled) connection.close()
      else setSocket(connection)
    }).catch(error => {
      if (!cancelled) setConnectionError(error.message)
    })
    return () => {
      cancelled = true
      connection.close()
    }
  }, [user])

  return (
    <div className="mystere-app">
      <header className="app-header">
        <h1>MYSTERE</h1>
        <span className="app-header-note">Private messaging</span>
      </header>
      <div className={user ? 'app-layout' : 'app-layout app-layout--welcome'}>
        {user && (
          <aside className="identity-rail" aria-label="Your identity">
            <h2>Your identity</h2>
            <div className="identity-detail">
              <span className="detail-label">Mystere ID</span>
              <code>{user.userId}</code>
            </div>
            <div className="identity-detail">
              <span className="detail-label">Identity fingerprint</span>
              <code>{user.fingerprint}</code>
            </div>
            <p className="identity-note">Confirm fingerprints with your peer before starting a session.</p>
          </aside>
        )}
        <main className="app-main">
          {wipeComplete && <p className="notice notice--success" role="status">Local Mystere data erased. Close this tab to release any remaining browser memory.</p>}
          {wipeError && <p className="notice notice--error" role="alert">Local data was cleared, but storage deletion needs attention: {wipeError}</p>}
          {!user ? (
            <Session onEstablished={(u) => setUser(u)} />
          ) : (
            socket ? <Chat user={user} socket={socket} onPanic={(error) => {
              setSocket(null)
              setUser(null)
              if (error) setWipeError(error)
              else setWipeComplete(true)
            }} /> : <p className="notice">{connectionError || 'Connecting to relay…'}</p>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
