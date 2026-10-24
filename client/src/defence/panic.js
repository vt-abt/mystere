import { sendTombstone } from './tombstone.js'

const OWN_DATABASES = ['mystere_signal_store', 'mystere_idb']

function deleteDatabase(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => reject(new Error(`Close other Mystere tabs to erase ${name}`))
  })
}

export async function panicWipe({ socket, session, signingPrivateKey, clearMemory }) {
  try {
    if (socket?.connected && session) {
      await sendTombstone(socket, session.peerId, session.sessionId, signingPrivateKey, 'panic')
    }
  } catch { /* Local erasure must still run if the relay is unavailable. */ }
  clearMemory()
  socket?.close()
  await Promise.all(OWN_DATABASES.map(deleteDatabase))
}
