const crypto = require('crypto');

function hash(algorithm, message, inputEncoding, outputEncoding) {
  const func = crypto.createHash(algorithm);
  func.update(message, inputEncoding);
  return func.digest(outputEncoding);
}

function hashStream(algorithm, input, inputEncoding) {
  return new Promise((resolve, reject) => {
    let data;
    let isBuffer = false;

    input.on('data', chunk => {
      if (Buffer.isBuffer(chunk)) {
        isBuffer = true;
        chunk = chunk.toString('utf8');
      }

      if (data === undefined) {
        data = chunk;
      } else {
        data += chunk;
      }
    });

    input.on('end', () => {
      if (data === undefined) {
        reject(new Error('No data to hash.'));
      } else {
        resolve(hash(algorithm, data, isBuffer ? 'utf8' : inputEncoding));
      }
    });
  });
}

module.exports = {
  hash,
  hashStream
};
