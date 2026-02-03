/// <reference types="@/libs/bytes/lib.d.ts" />

import { Lengthed } from "@/libs/lengthed/mod.ts";
import { assert, test } from "@hazae41/phobos";
import { Ed25519ExtendedPrivateKey, Ed25519SeedKey } from "./mod.ts";

namespace ed25519 {

  export async function publish(key: Uint8Array<ArrayBuffer> & Lengthed<32>) {
    const asn = new Uint8Array([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32])

    const sigkeyraw = key

    const sigkeyasn = new Uint8Array(asn.length + sigkeyraw.length)
    sigkeyasn.set(asn, 0)
    sigkeyasn.set(sigkeyraw, asn.length)

    const sigkeyref = await crypto.subtle.importKey("pkcs8", sigkeyasn, { name: "Ed25519" }, true, ["sign"])
    const sigkeyjwk = await crypto.subtle.exportKey("jwk", sigkeyref)

    delete sigkeyjwk.d
    delete sigkeyjwk.key_ops

    const pubkeyref = await crypto.subtle.importKey("jwk", sigkeyjwk, { name: "Ed25519" }, true, ["verify"])
    const pubkeyraw = new Uint8Array(await crypto.subtle.exportKey("raw", pubkeyref)) as Uint8Array<ArrayBuffer> & Lengthed<32>

    return pubkeyraw
  }

}

async function check(key: Ed25519ExtendedPrivateKey, values: {
  chain_code: string
  private: string
  public: string
}) {
  const pub = await ed25519.publish(key.key)

  assert(key.ext.toHex() === values.chain_code)
  assert(key.key.toHex() === values.private)
  assert(pub.toHex().padStart(66, "00") === values.public)
}

test("test vector 1", async () => {
  const seed = new Ed25519SeedKey(Uint8Array.fromHex("000102030405060708090a0b0c0d0e0f"))

  await check(await seed.derive("m"), {
    chain_code: "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
    private: "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
    public: "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
  })

  await check(await seed.derive("m/0'"), {
    chain_code: "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
    private: "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
    public: "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
  })

  await check(await seed.derive("m/0'/1'"), {
    chain_code: "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
    private: "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
    public: "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
  })

  await check(await seed.derive("m/0'/1'/2'"), {
    chain_code: "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
    private: "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
    public: "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
  })

  await check(await seed.derive("m/0'/1'/2'/2'"), {
    chain_code: "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
    private: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
    public: "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
  })

  await check(await seed.derive("m/0'/1'/2'/2'/1000000000'"), {
    chain_code: "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
    private: "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
    public: "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
  })
})