import { toHex } from './identity.js'

export function base64url(bytes) {
  let binary = ''
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

export function fromBase64url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid credential encoding')
  }
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4))
  return Uint8Array.from(binary, char => char.charCodeAt(0))
}

function responseJson(credential, fields) {
  const response = {}
  for (const field of fields) response[field] = base64url(credential.response[field])
  return {
    id: credential.id,
    rawId: base64url(credential.rawId),
    type: credential.type,
    response,
  }
}

export async function registerCredential(custodian) {
  if (!navigator.credentials?.create) throw new Error('WebAuthn is unavailable in this browser')
  const options = await custodian.registrationOptions()
  const challenge = fromBase64url(options.challenge)
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: options.rp_id, name: 'Mystere Custodian' },
      user: {
        id: fromBase64url(options.user_id),
        name: `mystere-${options.user_id}`,
        displayName: 'Mystere device',
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'required' },
      attestation: 'none',
      timeout: 60000,
    },
  })
  if (!credential) throw new Error('Credential enrollment cancelled')
  const result = await custodian.enroll(toHex(challenge), responseJson(
    credential, ['clientDataJSON', 'attestationObject'],
  ))
  return result.credential_id
}

export async function getAssertion(credentialId, options) {
  if (!navigator.credentials?.get) throw new Error('WebAuthn is unavailable in this browser')
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: fromBase64url(options.challenge),
      rpId: options.rp_id,
      allowCredentials: [{ type: 'public-key', id: fromBase64url(credentialId) }],
      userVerification: 'required',
      timeout: 60000,
    },
  })
  if (!credential) throw new Error('Device verification cancelled')
  return responseJson(credential, ['authenticatorData', 'clientDataJSON', 'signature'])
}
