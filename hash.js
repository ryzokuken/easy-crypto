const crypto = require('crypto');

/**
 * The hash module contains a small set of utilities for computing hashes.
 * @module easy-crypto/hash
 */

/**
 * Hash a given message using the specified hash algorithm.
 * @since 0.1.0
 * @function hash
 * @param {string} algorithm The hashing algorithm to be used.
 * @param {Data} message The message to be hashed.
 * @param {string} inputEncoding The encoding of the `message`. If nothing is provided and `message` is a string, an encoding of `'utf8'` is enforced. If `message` is a Buffer, TypedArray, or DataView, then inputEncoding is ignored.
 * @param {string} outputEncoding The encoding of the output. If encoding is provided a string will be returned; otherwise a Buffer is returned.
 * @returns {string|Buffer} The hash of the input message.
 * @static
 */
function hash(algorithm, message, inputEncoding, outputEncoding) {
  const func = crypto.createHash(algorithm);
  func.update(message, inputEncoding);
  return func.digest(outputEncoding);
}

/**
 * Hash a message encapsulated inside a stream using the specified hash algorithm.
 * @since 0.1.0
 * @async
 * @function hashStream
 * @param {string} algorithm The hashing algorithm to be used.
 * @param {ReadableStream<Data>} input The stream containing the message to be hashed.
 * @param {string} inputEncoding The encoding of the `message`. If nothing is provided and `message` is a string, an encoding of `'utf8'` is enforced. If `message` is a Buffer, TypedArray, or DataView, then inputEncoding is ignored.
 * @param {string} outputEncoding The encoding of the output. If encoding is provided a string will be returned; otherwise a Buffer is returned.
 * @returns {Promise<string|Buffer>} The hash of the input message.
 * @static
 */
function hashStream(algorithm, input, inputEncoding, outputEncoding) {
  return new Promise((resolve, reject) => {
    let data;
    let wasBuffer;

    const dataHandler = chunk => {
      const isBuffer = Buffer.isBuffer(chunk);
      if ((!isBuffer && wasBuffer) || (isBuffer && wasBuffer === false)) {
        reject(new Error('Inconsisent data.'));
        input.removeListener('data', dataHandler);
        return;
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
    };
    input.on('data', dataHandler);

    input.on('end', () => {
      if (data === undefined) {
        reject(new Error('No data to hash.'));
      } else {
        resolve(
          hash(
            algorithm,
            data,
            wasBuffer ? 'utf8' : inputEncoding,
            outputEncoding
          )
        );
      }
    });
  });
}

module.exports = {
  hash,
  hashStream
};
