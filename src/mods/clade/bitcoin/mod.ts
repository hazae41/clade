import { Lengthed } from "@/libs/lengthed/mod.ts";
import * as secp256k1 from "@/libs/secp256k1/mod.ts";
import { Cursor } from "@hazae41/cursor";

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

      const key = sig.slice(0, 32) as Uint8Array<ArrayBuffer> & Lengthed<32>
      const ext = sig.slice(32, 64) as Uint8Array<ArrayBuffer> & Lengthed<32>

      input = key

      const x = BigInt("0x" + key.toHex())

      if (x === 0n)
        continue
      if (x >= secp256k1.order)
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
    readonly key: Uint8Array<ArrayBuffer> & Lengthed<32>,
    readonly ext: Uint8Array<ArrayBuffer> & Lengthed<32>,
  ) { }

  /**
   * Get the public key
   * @returns public key
   */
  publish() {
    const key = secp256k1.getPublicKey(this.key, true) as Uint8Array<ArrayBuffer> & Lengthed<33>
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
      cursor.writeOrThrow(secp256k1.getPublicKey(this.key, true))
      cursor.writeUint32OrThrow(index)
    } else {
      const cursor = new Cursor(input)
      cursor.writeUint8OrThrow(0)
      cursor.writeOrThrow(this.key)
      cursor.writeUint32OrThrow(index)
    }

    while (true) {
      const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, input))

      const l = sig.slice(0, 32) as Uint8Array<ArrayBuffer> & Lengthed<32>
      const r = sig.slice(32, 64) as Uint8Array<ArrayBuffer> & Lengthed<32>

      const i = BigInt("0x" + l.toHex())

      if (i >= secp256k1.order) {
        const cursor = new Cursor(input)
        cursor.writeUint8OrThrow(1)
        cursor.writeOrThrow(l)
        cursor.writeUint32OrThrow(index)

        continue
      }

      const x = i
      const y = BigInt("0x" + this.key.toHex())
      const z = (x + y) % secp256k1.order

      if (z === 0n) {
        const cursor = new Cursor(input)
        cursor.writeUint8OrThrow(1)
        cursor.writeOrThrow(l)
        cursor.writeUint32OrThrow(index)

        continue
      }

      const key = Uint8Array.fromHex(z.toString(16).padStart(64, "0")) as Uint8Array<ArrayBuffer> & Lengthed<32>
      const ext = r

      return new BitcoinExtendedPrivateKey(key, ext)
    }
  }

}

export class BitcoinExtendedPublicKey {

  constructor(
    readonly key: Uint8Array<ArrayBuffer> & Lengthed<33>,
    readonly ext: Uint8Array<ArrayBuffer> & Lengthed<32>,
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
      cursor.writeOrThrow(this.key)
      cursor.writeUint32OrThrow(index)
    } else {
      throw new Error("Cannot do hardened derivation from public key")
    }

    while (true) {
      const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, input))

      const l = sig.slice(0, 32) as Uint8Array<ArrayBuffer> & Lengthed<32>
      const r = sig.slice(32, 64) as Uint8Array<ArrayBuffer> & Lengthed<32>

      const i = BigInt("0x" + l.toHex())

      if (i >= secp256k1.order) {
        const cursor = new Cursor(input)
        cursor.writeUint8OrThrow(1)
        cursor.writeOrThrow(l)
        cursor.writeUint32OrThrow(index)

        continue
      }

      const x = secp256k1.Point.BASE.multiply(i)
      const y = secp256k1.Point.fromBytes(this.key)
      const z = x.add(y)

      if (z.is0()) {
        const cursor = new Cursor(input)
        cursor.writeUint8OrThrow(1)
        cursor.writeOrThrow(l)
        cursor.writeUint32OrThrow(index)

        continue
      }

      const key = z.toBytes(true) as Uint8Array<ArrayBuffer> & Lengthed<33>
      const ext = r

      return new BitcoinExtendedPublicKey(key, ext)
    }
  }

}