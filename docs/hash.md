---
id: hash
title: Hash
sidebar_label: Hash
---

The `hash` "submodule" encapsulates all the hashing functionality in
easy-crypto.

## Importing

### Using CJS

```javascript
const hash = require('easy-crypto/hash');
```

### Using ESM

If you are using ECMAScript modules (perhaps by using a transpiler like Babel),
import the module by using the following instead.

```javascript
import hash from 'easy-crypto/hash';
```

## API

### Function: hash

The `hash` method can be used in order to hash an input message.

#### Parameters

| Parameter | Type | Required/Default | Note |
| --- | --- | --- | --- |
| `algorithm` | `String` | ✔ | Hashing algorithm to use |
| `message` | `String` | ✔ | The message to be hashed |
| `inputEncoding` | `String` | `'utf8'` | Encoding of the input message |
| `outputEncoding` | `String` | `undefined` | Encoding of the output message |

#### Returns

A `String` containing the hashed of the input message in the correct encoding if
`outputEncoding` was specified, otherwise a `Buffer` containing the same.

#### Errors

The errors should come here in a bulleted list.

#### Example

```javascript
const output = hash.hash('sha256', 'hello world', 'utf8', 'hex');
```

### Function: hashStream

The `hashStream` method is very much like the `hash` method, but instead of
hashing raw string data, it can be used to hash streams.

#### Parameters

| Parameter | Type | Required/Default | Note |
| --- | --- | --- | --- |
| `algorithm` | `String` | ✔ | Hashing algorithm to use |
| `input` | `Readable` | ✔ | Input stream |
| `output` | `Writable` | ✔ | Output stream |

#### Returns

`undefined`

Since the output of the hashing operation is stored in the output stream passed
into the function, the `hashStream` method does not return a value.

#### Errors

The errors should come here in a bulleted list.

#### Example

```javascript
const fs = require('fs');
const { Writable } = require('stream');

const input = fs.createReadStream('/dev/random');
const output = new Writable();
hash.hashStream('sha256', input, output);
```
