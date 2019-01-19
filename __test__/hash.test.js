const stream = require('stream');
const hash = require('../hash');

const hashOutput =
  'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f';

test('hashes strings', () => {
  expect(hash.hash('sha256', 'Hello, World!').toString('hex')).toBe(hashOutput);
});

test('hashes buffers', () => {
  const buf = Buffer.from('Hello, World!');
  expect(hash.hash('sha256', buf).toString('hex')).toBe(hashOutput);
});

test('hashes string streams', async () => {
  expect.assertions(1);

  const inputStream = new stream.Readable({
    objectMode: true,
    read() {}
  });
  process.nextTick(() => {
    inputStream.push('Hello, World!');
    inputStream.push(null);
  });

  const output = await hash.hashStream('sha256', inputStream);
  expect(output.toString('hex')).toBe(hashOutput);
});

test('hashes buffer streams', async () => {
  expect.assertions(1);

  const inputStream = new stream.Readable({
    objectMode: true,
    read() {}
  });
  process.nextTick(() => {
    inputStream.push(Buffer.from('Hello, World!'));
    inputStream.push(null);
  });

  const output = await hash.hashStream('sha256', inputStream);
  expect(output.toString('hex')).toBe(hashOutput);
});

test('cannot hash blank streams', async () => {
  expect.assertions(1);

  const inputStream = new stream.Readable({
    objectMode: true,
    read() {}
  });
  process.nextTick(() => {
    inputStream.push(null);
  });

  try {
    await hash.hashStream('sha256', inputStream);
  } catch (err) {
    expect(err).toEqual(new Error('No data to hash.'));
  }
});
