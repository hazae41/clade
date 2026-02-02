/// <reference types="@/libs/bytes/lib.d.ts" />

import { Lengthed } from "@/libs/lengthed/mod.ts";
import { Cursor } from "@hazae41/cursor";

export class Ed25519SeedKey {

  constructor(
    readonly seed: Uint8Array<ArrayBuffer>
  ) { }

  /**
   * Generate the master private key using SLIP-0010 (~BIP-32)
   * @returns master private key
   */
  async generate() {
    const alg = { name: "HMAC", hash: "SHA-512" }
    const ref = await crypto.subtle.importKey("raw", new TextEncoder().encode("ed25519 seed"), alg, false, ["sign"])

    const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, this.seed))

    const key = sig.slice(0, 32) as Uint8Array<ArrayBuffer> & Lengthed<32>
    const ext = sig.slice(32, 64) as Uint8Array<ArrayBuffer> & Lengthed<32>

    return new Ed25519ExtendedPrivateKey(key, ext)
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

export class Ed25519ExtendedPrivateKey {

  constructor(
    readonly key: Uint8Array<ArrayBuffer> & Lengthed<32>,
    readonly ext: Uint8Array<ArrayBuffer> & Lengthed<32>,
  ) { }

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
      throw new Error("Only Ed25519 hardened derivation is supported")
    } else {
      const cursor = new Cursor(input)
      cursor.writeUint8OrThrow(0)
      cursor.writeOrThrow(this.key)
      cursor.writeUint32OrThrow(index)
    }

    while (true) {
      const sig = new Uint8Array(await crypto.subtle.sign(alg, ref, input))

      const key = sig.slice(0, 32) as Uint8Array<ArrayBuffer> & Lengthed<32>
      const ext = sig.slice(32, 64) as Uint8Array<ArrayBuffer> & Lengthed<32>

      return new Ed25519ExtendedPrivateKey(key, ext)
    }
  }

}