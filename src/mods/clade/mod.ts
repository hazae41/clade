import { Lengthed } from "@/libs/lengthed/mod.ts";
import { secp256k1 } from "@/libs/secp256k1/mod.ts";
import { Cursor } from "@hazae41/cursor";

export class BitcoinSeed {

  constructor(
    readonly seed: Uint8Array<ArrayBuffer>
  ) { }

  async generate() {
    let input = this.seed

    const alg = { name: "HMAC", hash: "SHA-512" }
    const key = new TextEncoder().encode("Bitcoin seed")
    const ref = await crypto.subtle.importKey("raw", key, alg, false, ["sign"])

    while (true) {
      const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, input))

      const data = sig.slice(0, 32) as Uint8Array<ArrayBuffer> & Lengthed<32>
      const code = sig.slice(32, 64) as Uint8Array<ArrayBuffer> & Lengthed<32>

      input = data

      const x = BigInt("0x" + data.toHex())

      if (x === 0n)
        continue
      if (x >= secp256k1.order)
        continue

      return new BitcoinExtendedKey(data, code)
    }
  }

}

export class BitcoinExtendedKey {

  constructor(
    readonly data: Uint8Array<ArrayBuffer> & Lengthed<32>,
    readonly code: Uint8Array<ArrayBuffer> & Lengthed<32>,
  ) { }

  async derive(index: number) {
    if (index < (2 ** 31))
      throw new Error("Only hardened derivation is supported")

    const alg = { name: "HMAC", hash: "SHA-512" }
    const ref = await crypto.subtle.importKey("raw", this.code, alg, false, ["sign"])

    const input = new Uint8Array(1 + 32 + 4)

    const cursor = new Cursor(input)
    cursor.writeUint8OrThrow(0)
    cursor.writeOrThrow(this.data)
    cursor.writeUint32OrThrow(index)

    while (true) {
      const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, input))

      const l = sig.slice(0, 32) as Uint8Array<ArrayBuffer> & Lengthed<32>
      const r = sig.slice(32, 64) as Uint8Array<ArrayBuffer> & Lengthed<32>

      const x = BigInt("0x" + l.toHex())
      const y = BigInt("0x" + this.data.toHex())

      if (x >= secp256k1.order) {
        const cursor = new Cursor(input)
        cursor.writeUint8OrThrow(1)
        cursor.writeOrThrow(l)
        cursor.writeUint32OrThrow(index)

        continue
      }

      const z = (x + y) % secp256k1.order

      if (z === 0n) {
        const cursor = new Cursor(input)
        cursor.writeUint8OrThrow(1)
        cursor.writeOrThrow(l)
        cursor.writeUint32OrThrow(index)

        continue
      }

      const data = Uint8Array.fromHex(z.toString(16).padStart(64, "0")) as Uint8Array<ArrayBuffer> & Lengthed<32>
      const code = r

      return new BitcoinExtendedKey(data, code)
    }
  }

}