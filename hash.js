const crypto = require('crypto');

function hash(algorithm, message, inputEncoding, outputEncoding) {
  const func = crypto.createHash(algorithm);
  func.update(message, inputEncoding);
  return func.digest(outputEncoding);
}

function hashStream(algorithm, input, output) {
  const func = crypto.createHash(algorithm);
  input.pipe(func).pipe(output);
}

module.exports = {
  hash,
  hashStream
};
