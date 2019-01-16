const crypto = require('crypto');

function hash(algorithm, message, inputEncoding, outputEncoding) {
  const func = crypto.createHash(algorithm);
  func.update(message, inputEncoding);
  return func.digest(outputEncoding);
}

function hashStream(algorithm, input) {
  return new Promise((resolve, reject) => {
    let data;

    input.on('data', (chunk) => {
      data = data === undefined ? chunk : (data + chunk);
    });

    input.on('end', () => {
      resolve(data === undefined ? undefined : hash(algorithm, data));
    });

    input.on('error', (err) => reject(err));
  });
}

module.exports = {
  hash,
  hashStream
};
