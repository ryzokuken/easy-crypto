# easy-crypto

> A WIP module aimed at providing a safer, easier to use and beginner friendly
> crypto API for Node.js

![](https://img.shields.io/npm/v/easy-crypto.svg?style=plastic)
![](https://img.shields.io/travis/com/ryzokuken/easy-crypto.svg?style=plastic)
![](https://img.shields.io/badge/blessed-by%20core-green.svg)

## Goals

1. Make `crypto` **easy** to use.
2. Make `crypto` **safe** to use.
3. Require as little crypto-specific knowledge as possible.

## Features/Roadmap

- [ ] Symmetric Encryption, Decryption and AEAD
- [ ] Asymmetric Encryption and Decryption
- [X] Asymmetric Signing and Verification of signatures
- [X] Cryptographic hashing
- [X] Password-based key derivation
- [X] Password hashing and verification
- [ ] Random number generation

## Installation

```
$ npm install easy-crypto
```

## Usage

Importing the module itself will return `undefined` since the behavior of the
entire module is broken down into a set of intent-based submodules.

```js
const password = require('easy-crypto/password');

const hashedPassword = password.hashPasswordSync('correct horse battery staple');
fs.writeFileSync('myfile', hashedPassword); // Ideally, store it in a database.
```

For an exhaustive list of all submodules and their members, check out the
[API docs](https://ryzokuken.github.io/easy-crypto)

## License

[MIT](LICENSE)

`Copyright (c) 2019 Ujjwal Sharma`

## Notice

This module is currently a work-in-progress. Please do not use it in production
until before the `1.0.0` release since the API may break or might as well be
outright unusable to unsafe.
