interface Uint8Array {
  toBase64(): string
  toHex(): string
}

interface Uint8ArrayConstructor {
  fromBase64(text: string): Uint8Array<ArrayBuffer>
  fromHex(text: string): Uint8Array<ArrayBuffer>
}