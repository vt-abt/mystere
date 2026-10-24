import { KeyHelper, SignalProtocolAddress, SessionBuilder, SessionCipher } from '@privacyresearch/libsignal-protocol-typescript'

export async function createSignalIdentity(store, preKeyCount = 5) {
  const identityKeyPair = await KeyHelper.generateIdentityKeyPair()
  const registrationId = KeyHelper.generateRegistrationId()
  const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, 1)
  const preKeys = await Promise.all(
    Array.from({ length: preKeyCount }, (_, index) => KeyHelper.generatePreKey(index + 1)),
  )

  await store.put('identityKeys', 'keyPair', identityKeyPair)
  await store.put('registrationId', 'id', registrationId)
  await store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair)
  for (const preKey of preKeys) {
    await store.storePreKey(preKey.keyId, preKey.keyPair)
  }

  return {
    registrationId,
    identityKey: identityKeyPair.pubKey,
    signedPreKey: {
      keyId: signedPreKey.keyId,
      publicKey: signedPreKey.keyPair.pubKey,
      signature: signedPreKey.signature,
    },
    preKeys: preKeys.map(({ keyId, keyPair }) => ({ keyId, publicKey: keyPair.pubKey })),
  }
}

export async function initSession(store, recipientId, preKeyBundle) {
  const address = new SignalProtocolAddress(recipientId, 1)
  const builder = new SessionBuilder(store, address)
  await builder.processPreKey(preKeyBundle)
}

export async function encryptMessage(store, recipientId, plaintext) {
  const cipher = new SessionCipher(store, new SignalProtocolAddress(recipientId, 1))
  const bytes = plaintext instanceof ArrayBuffer ? plaintext : plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength)
  return cipher.encrypt(bytes)
}

export async function decryptMessage(store, senderId, ciphertext) {
  const cipher = new SessionCipher(store, new SignalProtocolAddress(senderId, 1))
  if (ciphertext.type === 3) {
    return cipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary')
  }
  if (ciphertext.type === 1) {
    return cipher.decryptWhisperMessage(ciphertext.body, 'binary')
  }
  throw new Error('Unsupported Signal message type')
}
