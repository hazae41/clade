# Clade

Account derivation (BIP-32, SLIP-0010) for TypeScript

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
- BIP-32, BIP-44, SLIP-0010

## Usage

### BIP-32

```tsx
const seed = new BitcoinSeed(...)

const master = await seed.generate()

const child = await master.derive(123)

console.log(child.key.toHex())
```

### BIP-32 + BIP-44

```tsx
const seed = new BitcoinSeed(...)

const child = await seed.derive("m/44'/0/0'/0/0")

console.log(child.key.toHex())
```

### SLIP-0010

```tsx
const seed = new Ed25519Seed(...)

const master = await seed.generate()

const child = await master.derive(123)

console.log(child.key.toHex())
```

### SLIP-0010 + BIP-44

```tsx
const seed = new Ed25519Seed(...)

const child = await seed.derive("m/44'/0/0'/0/0")

console.log(child.key.toHex())
```