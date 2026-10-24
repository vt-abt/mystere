import { aesGCMDecrypt, aesGCMEncrypt, wipe } from './webcrypto.js'
import { splitKey, reconstructKey } from './fragments.js'
import { encryptShareCustodian, storageKey } from './capability.js'
import { encryptMessage, decryptMessage } from './signal.js'
import { fromHex, toHex } from './identity.js'
import { encodeJson, decodeJson } from '../transport/protocol.js'

function requireBytes(bytes, length, name) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new Error(`Invalid ${name}`)
  }
}

export function messageAad(sessionId, messageId, sequence) {
  requireBytes(sessionId, 64, 'session ID')
  requireBytes(messageId, 16, 'message ID')
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error('Invalid sequence')
  const aad = new Uint8Array(88)
  aad.set(sessionId)
  aad.set(messageId, 64)
  new DataView(aad.buffer).setBigUint64(80, BigInt(sequence))
  return aad
}

export async function sealMessage(plaintext, sessionId, messageId, sequence, capabilityToken) {
  requireBytes(capabilityToken, 32, 'capability token')
  const content = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext
  if (!(content instanceof Uint8Array)) throw new Error('Invalid plaintext')
  if (content.length > 256 * 1024) throw new Error('Message too large')
  const size = Math.max(1024, 2 ** Math.ceil(Math.log2(content.length + 4)))
  const padded = new Uint8Array(size)
  new DataView(padded.buffer).setUint32(0, content.length)
  padded.set(content, 4)
  const keyBytes = crypto.getRandomValues(new Uint8Array(32))
  let shares
  try {
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt'])
    const ciphertext = await aesGCMEncrypt(key, padded, messageAad(sessionId, messageId, sequence))
    shares = await splitKey(keyBytes)
    const custodianBlob = await encryptShareCustodian(
      capabilityToken, shares.shareCustodian, messageId, sessionId,
    )
    const keyForStorage = new Uint8Array(await storageKey(capabilityToken, messageId))
    return { ciphertext, ...shares, custodianBlob, storageKey: keyForStorage }
  } catch (error) {
    if (shares) wipe(shares.shareX, shares.shareY, shares.shareCustodian)
    throw error
  } finally {
    wipe(padded)
    wipe(keyBytes)
  }
}

export async function openMessage(ciphertext, sessionId, messageId, sequence,
                                  shareX, shareY, shareCustodian) {
  requireBytes(shareX, 32, 'sender share')
  requireBytes(shareY, 32, 'recipient share')
  requireBytes(shareCustodian, 32, 'custodian share')
  const keyBytes = reconstructKey(shareX, shareY, shareCustodian)
  try {
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt'])
    const padded = new Uint8Array(await aesGCMDecrypt(key, ciphertext, messageAad(sessionId, messageId, sequence)))
    try {
      if (padded.length < 4) throw new Error('Invalid message padding')
      const length = new DataView(padded.buffer).getUint32(0)
      if (length > padded.length - 4) throw new Error('Invalid message padding')
      return padded.slice(4, 4 + length)
    } finally {
      wipe(padded)
    }
  } finally {
    wipe(keyBytes)
  }
}

export async function prepareOutboundMessage(store, recipientId, plaintext,
                                             sessionId, messageId, sequence, capabilityToken) {
  const sealed = await sealMessage(plaintext, sessionId, messageId, sequence, capabilityToken)
  try {
    const recipientEnvelope = await encryptMessage(store, recipientId, encodeJson({
      v: 1, session: toHex(sessionId), id: toHex(messageId), sequence, kind: 'r',
      share: toHex(sealed.shareY), capability: toHex(capabilityToken),
    }))
    return {
      ciphertext: sealed.ciphertext,
      senderShare: sealed.shareX,
      recipientEnvelope,
      custodianRecord: { key: sealed.storageKey, value: sealed.custodianBlob },
    }
  } catch (error) {
    wipe(sealed.shareX)
    throw error
  } finally {
    wipe(sealed.shareY, sealed.shareCustodian)
  }
}

export async function readRecipientMessage(store, senderId, recipientEnvelope,
                                           sessionId, messageId, sequence) {
  const plaintext = new Uint8Array(await decryptMessage(store, senderId, recipientEnvelope))
  try {
    const data = decodeJson(plaintext)
    if (data.v !== 1 || data.session !== toHex(sessionId)
        || data.id !== toHex(messageId) || data.sequence !== sequence) {
      throw new Error('Signal message context mismatch')
    }
    if (data.kind === 'd') {
      fromHex(data.share, 32)
      fromHex(data.capability, 32)
      return { decoy: true }
    }
    if (data.kind !== 'r') throw new Error('Invalid message kind')
    return { recipientShare: fromHex(data.share, 32), capabilityToken: fromHex(data.capability, 32) }
  } finally {
    wipe(plaintext)
  }
}

export async function openInboundMessage(store, senderId, packageData, sessionId,
                                         messageId, sequence, custodianShare) {
  const { recipientShare, capabilityToken } = await readRecipientMessage(
    store, senderId, packageData.recipientEnvelope, sessionId, messageId, sequence,
  )
  try {
    return await openMessage(packageData.ciphertext, sessionId, messageId, sequence,
                             packageData.senderShare, recipientShare, custodianShare)
  } finally {
    wipe(recipientShare, capabilityToken)
  }
}
