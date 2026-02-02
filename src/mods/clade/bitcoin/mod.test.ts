import { assert, test } from "@hazae41/phobos";
import { BitcoinExtendedPrivateKey, BitcoinSeedKey } from "./mod.ts";

function check(key: BitcoinExtendedPrivateKey, values: {
  chain_code: string
  private: string
  public: string
}) {
  assert(key.ext.toHex() === values.chain_code)
  assert(key.key.toHex() === values.private)
  assert(key.publish().key.toHex() === values.public)
}

test("test vector 1", async () => {
  const seed = new BitcoinSeedKey(Uint8Array.fromHex("000102030405060708090a0b0c0d0e0f"))

  check(await seed.derive("m"), {
    chain_code: "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
    private: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    public: "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
  })

  check(await seed.derive("m/0'"), {
    chain_code: "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
    private: "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
    public: "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
  })

  check(await seed.derive("m/0'/1"), {
    chain_code: "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
    private: "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
    public: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
  })

  check(await seed.derive("m/0'/1/2'"), {
    chain_code: "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
    private: "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
    public: "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
  })

  check(await seed.derive("m/0'/1/2'/2"), {
    chain_code: "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
    private: "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
    public: "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
  })

  check(await seed.derive("m/0'/1/2'/2/1000000000"), {
    chain_code: "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
    private: "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
    public: "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
  })
})