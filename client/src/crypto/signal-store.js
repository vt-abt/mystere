// SignalProtocolStore implementation for libsignal-protocol
// Backed by IndexedDB

export class SignalProtocolStore {
  constructor() {
    this.db = null;
    this.ready = this.initDB();
  }

  async initDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('mystere_signal_store', 1);
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        db.createObjectStore('identityKeys');
        db.createObjectStore('registrationId');
        db.createObjectStore('preKeys');
        db.createObjectStore('signedPreKeys');
        db.createObjectStore('sessions');
      };
      request.onsuccess = (event) => {
        this.db = event.target.result;
        resolve();
      };
      request.onerror = (event) => reject(event.target.error);
    });
  }

  async get(storeName, key) {
    await this.ready;
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async put(storeName, key, value) {
    await this.ready;
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.put(value, key);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async remove(storeName, key) {
    await this.ready;
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.delete(key);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  // libsignal interface
  async getIdentityKeyPair() {
    return this.get('identityKeys', 'keyPair');
  }

  async getLocalRegistrationId() {
    return this.get('registrationId', 'id');
  }

  async isTrustedIdentity(identifier, identityKey, direction) {
    const trusted = await this.get('identityKeys', identifier);
    if (trusted === undefined) {
      return true;
    }
    const expected = new Uint8Array(trusted);
    const actual = new Uint8Array(identityKey);
    return expected.length === actual.length && expected.every((byte, index) => byte === actual[index]);
  }

  async saveIdentity(identifier, identityKey) {
    const previouslyTrusted = await this.get('identityKeys', identifier);
    await this.put('identityKeys', identifier, identityKey);
    return previouslyTrusted !== undefined;
  }

  async loadIdentityKey(identifier) {
    return this.get('identityKeys', identifier);
  }

  async loadPreKey(keyId) {
    return this.get('preKeys', keyId);
  }

  async storePreKey(keyId, keyPair) {
    return this.put('preKeys', keyId, keyPair);
  }

  async removePreKey(keyId) {
    return this.remove('preKeys', keyId);
  }

  async loadSignedPreKey(keyId) {
    return this.get('signedPreKeys', keyId);
  }

  async storeSignedPreKey(keyId, keyPair) {
    return this.put('signedPreKeys', keyId, keyPair);
  }

  async removeSignedPreKey(keyId) {
    return this.remove('signedPreKeys', keyId);
  }

  async loadSession(identifier) {
    return this.get('sessions', identifier);
  }

  async storeSession(identifier, record) {
    return this.put('sessions', identifier, record);
  }
}

export class MemorySignalStore extends SignalProtocolStore {
  async initDB() { this.memory = new Map() }
  async get(store, key) { return this.memory.get(`${store}:${key}`) }
  async put(store, key, value) { this.memory.set(`${store}:${key}`, value) }
  async remove(store, key) { this.memory.delete(`${store}:${key}`) }
}
