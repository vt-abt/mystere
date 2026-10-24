export async function splitKey(mKeyBytes) {
  const pad1 = crypto.getRandomValues(new Uint8Array(32))
  const pad2 = crypto.getRandomValues(new Uint8Array(32))

  const shareX = new Uint8Array(32)
  const shareY = new Uint8Array(32)
  const shareCustodian = new Uint8Array(32)

  for (let i = 0; i < 32; i++) {
    shareX[i] = mKeyBytes[i] ^ pad1[i] ^ pad2[i]
    shareY[i] = pad1[i]
    shareCustodian[i] = pad2[i]
  }

  // Wipe intermediates immediately
  pad1.fill(0)
  pad2.fill(0)

  return { shareX, shareY, shareCustodian }
}

export function reconstructKey(shareX, shareY, shareCustodian) {
  const mKeyBytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    mKeyBytes[i] = shareX[i] ^ shareY[i] ^ shareCustodian[i]
  }
  return mKeyBytes
}
