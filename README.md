# Clade

BIP-32 and SLIP-0010 derivation for TypeScript

```bash
npm install @hazae41/clade
```

[**📦 NPM**](https://www.npmjs.com/package/@hazae41/clade)

## Features

### Current features
- 100% TypeScript and ESM
- No external dependencies
- Rust-like patterns
- Uses WebCrypto

## Usage

```tsx
const seed = new BitcoinSeed(...)

const master = await seed.generate()

const child = await master.derive(123)

const myPrivateKey = child.data
```