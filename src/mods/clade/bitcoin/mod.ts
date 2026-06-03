import { Cursor } from "@hazae41/cursor";
import { secp256k1 } from "@hazae41/secp256k1";

export class BitcoinSeedKey {

  constructor(
    readonly seed: Uint8Array<ArrayBuffer>
  ) { }

  /**
   * Generate the master private key using SLIP-0010 (~BIP-32)
   * @returns master private key
   */
  async generate() {
    let input = this.seed

    const alg = { name: "HMAC", hash: "SHA-512" }
    const ref = await crypto.subtle.importKey("raw", new TextEncoder().encode("Bitcoin seed"), alg, false, ["sign"])

    while (true) {
      const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, input))

      const key = sig.slice(0, 32)
      const ext = sig.slice(32, 64)

      input = key

      const x = BigInt("0x" + key.toHex())

      if (x === 0n)
        continue
      if (x >= secp256k1.Curve.order)
        continue

      return new BitcoinExtendedPrivateKey(key, ext)
    }
  }

  /**
   * Derive recursively to the child private key at the BIP-44 path
   * @param path 
   * @returns child private key
   */
  async derive(path: string) {
    let derived = await this.generate()

    for (const segment of path.matchAll(/\/([0-9]+)('?)/g)) {
      let index = Number(segment[1])

      if (index > 2 ** 32)
        throw new Error("Index out of bounds")

      if (segment[2] === "'")
        index += 2 ** 31

      derived = await derived.derive(index)
    }

    return derived
  }

}

export class BitcoinExtendedPrivateKey {

  constructor(
    readonly key: Uint8Array<ArrayBuffer>,
    readonly ext: Uint8Array<ArrayBuffer>,
  ) { }

  /**
   * Get the public key
   * @returns public key
   */
  publish() {
    const key = secp256k1.SecretKey.import(this.key).publish().export(true)
    const ext = this.ext

    return new BitcoinExtendedPublicKey(key, ext)
  }

  /**
   * Derive the child private key at index using SLIP-0010 (~BIP-32)
   * @param index 
   * @returns child private key
   */
  async derive(index: number) {
    const alg = { name: "HMAC", hash: "SHA-512" }
    const ref = await crypto.subtle.importKey("raw", this.ext, alg, false, ["sign"])

    const input = new Uint8Array(1 + 32 + 4)

    if (index < (2 ** 31)) {
      const cursor = new Cursor(input)
      cursor.write(secp256k1.SecretKey.import(this.key).publish().export(true))
      cursor.writeUint32(index)
    } else {
      const cursor = new Cursor(input)
      cursor.writeUint8(0)
      cursor.write(this.key)
      cursor.writeUint32(index)
    }

    while (true) {
      const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, input))

      const l = sig.slice(0, 32)
      const r = sig.slice(32, 64)

      const i = BigInt("0x" + l.toHex())

      if (i >= secp256k1.Curve.order) {
        const cursor = new Cursor(input)
        cursor.writeUint8(1)
        cursor.write(l)
        cursor.writeUint32(index)

        continue
      }

      const x = i
      const y = BigInt("0x" + this.key.toHex())
      const z = (x + y) % secp256k1.Curve.order

      if (z === 0n) {
        const cursor = new Cursor(input)
        cursor.writeUint8(1)
        cursor.write(l)
        cursor.writeUint32(index)

        continue
      }

      const key = Uint8Array.fromHex(z.toString(16).padStart(64, "0"))
      const ext = r

      return new BitcoinExtendedPrivateKey(key, ext)
    }
  }

}

export class BitcoinExtendedPublicKey {

  constructor(
    readonly key: Uint8Array<ArrayBuffer>,
    readonly ext: Uint8Array<ArrayBuffer>,
  ) { }

  /**
   * Derive the child public key at index using SLIP-0010 (~BIP-32)
   * @param index 
   * @returns child public key
   */
  async derive(index: number) {
    const alg = { name: "HMAC", hash: "SHA-512" }
    const ref = await crypto.subtle.importKey("raw", this.ext, alg, false, ["sign"])

    const input = new Uint8Array(33 + 4)

    if (index < (2 ** 31)) {
      const cursor = new Cursor(input)
      cursor.write(this.key)
      cursor.writeUint32(index)
    } else {
      throw new Error("Cannot do hardened derivation from public key")
    }

    while (true) {
      const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, input))

      const l = sig.slice(0, 32)
      const r = sig.slice(32, 64)

      const i = BigInt("0x" + l.toHex())

      if (i >= secp256k1.Curve.order) {
        const cursor = new Cursor(input)
        cursor.writeUint8(1)
        cursor.write(l)
        cursor.writeUint32(index)

        continue
      }

      const x = secp256k1.Point.generator.mul(i)
      const y = secp256k1.PublicKey.import(this.key).downcast()
      const z = x.add(y)

      if (z.identity) {
        const cursor = new Cursor(input)
        cursor.writeUint8(1)
        cursor.write(l)
        cursor.writeUint32(index)

        continue
      }

      const key = new Uint8Array(z.upcast().export(true))
      const ext = r

      return new BitcoinExtendedPublicKey(key, ext)
    }
  }

}