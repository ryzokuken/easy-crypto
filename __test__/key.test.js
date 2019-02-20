const crypto = require('crypto');
const key = require('../key');

const passphrase = 'top secret';
const message = 'hello world';

function sign(key, message) {
  const sig = crypto.createSign('sha256');
  sig.update(message);
  sig.end();
  return sig.sign(key);
}

function verify(key, message, signature) {
  const ver = crypto.createVerify('sha256');
  ver.update(message);
  ver.end();
  return ver.verify(key, signature);
}

jest.setTimeout(10000);

function testKeys(description, type, format, encrypted) {
  test(`it should generate ${description} keys`, async () => {
    expect.assertions(1);

    const { publicKey, privateKey } = await key.generateKeyPair(
      type,
      format,
      encrypted ? passphrase : undefined
    );

    const signature = sign(privateKey, message);
    expect(verify(publicKey, message, signature)).toBe(true);
  });
}

// PEM
testKeys('unencrypted rsa pem', 'rsa', 'pem', false);
testKeys('encrypted rsa pem', 'rsa', 'pem', true);

testKeys('unencrypted dsa pem', 'dsa', 'pem', false);
testKeys('encrypted dsa pem', 'dsa', 'pem', true);

testKeys('unencrypted ec pem', 'ec', 'pem', false);
testKeys('encrypted ec pem', 'ec', 'pem', true);

// DER
testKeys('unencrypted rsa der', 'rsa', 'der', false);
testKeys('encrypted rsa der', 'rsa', 'der', true);

testKeys('unencrypted dsa der', 'dsa', 'der', false);
testKeys('encrypted dsa der', 'dsa', 'der', true);

testKeys('unencrypted ec der', 'ec', 'der', false);
testKeys('encrypted ec der', 'ec', 'der', true);

// KeyObject
testKeys('unencrypted rsa object', 'rsa', 'object', false);
testKeys('encrypted rsa object', 'rsa', 'object', true);

testKeys('unencrypted dsa object', 'dsa', 'object', false);
testKeys('encrypted dsa object', 'dsa', 'object', true);

testKeys('unencrypted ec object', 'ec', 'object', false);
testKeys('encrypted ec object', 'ec', 'object', true);
