const crypto = require('crypto');

function hash(algorithm, message, inputEncoding, outputEncoding) {
  const func = crypto.createHash(algorithm);
  func.update(message, inputEncoding);
  return func.digest(outputEncoding);
}

function hashStream(algorithm, input, inputEncoding) {
  return new Promise((resolve, reject) => {
    let data;
    let wasBuffer;

    input.on('data', chunk => {
      const isBuffer = Buffer.isBuffer(chunk);
      if ((!isBuffer && wasBuffer) || (isBuffer && wasBuffer === false)) {
        reject(new Error('Inconsisent data.'));
      }

      if (isBuffer) {
        wasBuffer = true;
        chunk = chunk.toString('utf8');
      } else {
        wasBuffer = false;
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
        resolve(hash(algorithm, data, wasBuffer ? 'utf8' : inputEncoding));
      }
    });
  });
}

module.exports = {
  hash,
  hashStream
};
