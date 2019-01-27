const crypto = require('crypto');
const stream = require('stream');
const signature = require('../signature');

const message = 'Hello, World!';
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

test('it should work with simple sign and simple verify', () => {
  const signed = signature.sign(privateKey, 'sha256', message);
  expect(signature.verify(publicKey, 'sha256', message, signed)).toBe(true);
});

test('it should work with simple sign and stream verify', async () => {
  expect.assertions(1);

  const signed = signature.sign(privateKey, 'sha256', message);
  const inputStream = new stream.Readable({
    objectMode: true,
    read() {}
  });
  process.nextTick(() => {
    inputStream.push('Hello, World!');
    inputStream.push(null);
  });

  const output = await signature.verifyStream(
    publicKey,
    'sha256',
    inputStream,
    signed
  );
  expect(output).toBe(true);
});

test('it should work with stream sign and simple verify', async () => {
  expect.assertions(1);

  const inputStream = new stream.Readable({
    objectMode: true,
    read() {}
  });
  process.nextTick(() => {
    inputStream.push('Hello, World!');
    inputStream.push(null);
  });
  const signed = await signature.signStream(privateKey, 'sha256', inputStream);

  const output = await signature.verify(publicKey, 'sha256', message, signed);
  expect(output).toBe(true);
});

test('it should work with stream sign and stream verify', async () => {
  expect.assertions(1);

  const inputStreamOne = new stream.Readable({
    objectMode: true,
    read() {}
  });
  process.nextTick(() => {
    inputStreamOne.push('Hello, World!');
    inputStreamOne.push(null);
  });
  const signed = await signature.signStream(
    privateKey,
    'sha256',
    inputStreamOne
  );

  const inputStreamTwo = new stream.Readable({
    objectMode: true,
    read() {}
  });
  process.nextTick(() => {
    inputStreamTwo.push('Hello, World!');
    inputStreamTwo.push(null);
  });

  const output = await signature.verifyStream(
    publicKey,
    'sha256',
    inputStreamTwo,
    signed
  );
  expect(output).toBe(true);
});

test('it should accept string (pem) keys', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  const signed = signature.sign(privateKey, 'sha256', message);
  expect(signature.verify(publicKey, 'sha256', message, signed)).toBe(true);
});

test('it should accept buffer (der) keys', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'der'
    }
  });

  const signed = signature.sign(privateKey, 'sha256', message);
  expect(signature.verify(publicKey, 'sha256', message, signed)).toBe(true);
});

test('it should accept object (KeyObject) keys', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096
  });

  const signed = signature.sign(privateKey, 'sha256', message);
  expect(signature.verify(publicKey, 'sha256', message, signed)).toBe(true);
});

test('it should accept dsa keys', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('dsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  const signed = signature.sign(privateKey, 'sha256', message);
  expect(signature.verify(publicKey, 'sha256', message, signed)).toBe(true);
});

test('it should accept ec keys', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'sect239k1',
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  const signed = signature.sign(privateKey, 'sha256', message);
  expect(signature.verify(publicKey, 'sha256', message, signed)).toBe(true);
});
