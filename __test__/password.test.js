const fs = require('fs');
const path = require('path');

const protobuf = require('protocol-buffers');

const password = require('../password');

const passphrase = 'correct horse battery staple';
const passwordPath = path.resolve(__dirname, '../password.proto');

test('hashes and verifies passwords synchronously', () => {
  const hashed = password.hashPasswordSync(passphrase);
  expect(password.verifyHashSync(hashed, passphrase)).toBe(true);
});

test('hashes passwords asynchronously', async () => {
  expect.assertions(1);

  const hashed = await password.hashPassword(passphrase);
  expect(password.verifyHashSync(hashed, passphrase)).toBe(true);
});

test('verifies passwords asynchronously', async () => {
  expect.assertions(1);

  const hashed = password.hashPasswordSync(passphrase);
  const verified = await password.verifyHash(hashed, passphrase);
  expect(verified).toBe(true);
  // expect(password.verifyHashSync(hashed, passphrase)).toBe(true);
});

test('hashes and verifies passwords asynchronously', async () => {
  expect.assertions(1);

  const hashed = await password.hashPasswordSync(passphrase);
  const verified = await password.verifyHash(hashed, passphrase);
  expect(verified).toBe(true);
});

test('fails for incorrect password', async () => {
  expect.assertions(1);

  const hashed = await password.hashPasswordSync(passphrase);
  const verified = await password.verifyHash(hashed, 'Hello, World!');
  expect(verified).toBe(false);
});

test('requires rehash', () => {
  const messages = protobuf(fs.readFileSync(passwordPath));

  const hashed = password.hashPasswordSync(passphrase);
  const { salt, length, hash } = messages.Password.decode(hashed);
  const algorithm = messages.Algorithm.INVALID;
  const encoded = messages.Password.encode({ algorithm, salt, length, hash });

  expect(() => password.verifyHashSync(encoded, passphrase)).toThrowError(
    password.InvalidHashError
  );
});
