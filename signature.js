const crypto = require('crypto');

/**
 * The signature module contains a small set of basic utilities for generating
 * and verifying signatures.
 * @module easy-crypto/signature
 */

/**
 * Generate signatures for a message using a private key.
 * @param {Object|string|Buffer|KeyObject} privateKey The private key to be used for signing the message.
 * @param {string} algorithm The hashing algorithm to be used.
 * @param {Data} message The message to be signed.
 * @param {string} inputEncoding The encoding of the `message`. If `message` is a string and no value is provided, an encoding of `'utf8'` will be enforced. Ignored if message is a `Buffer`, `TypedArray` or `DataView`.
 * @param {string} outputEncoding The encoding of the output signature. If provided a `string` is returned, otherwise a `Buffer` is returned.
 * @returns {string|Buffer} The generated signature for the provided message.
 */
function sign(privateKey, algorithm, message, inputEncoding, outputEncoding) {
  const signFunc = crypto.createSign(algorithm);
  signFunc.update(message, inputEncoding);
  signFunc.end();
  return signFunc.sign(privateKey, outputEncoding);
}

/**
 * Generate signatures for a message encapsulated in a stream using a private key.
 * @param {Object|string|Buffer|KeyObject} privateKey The private key to be used for signing the message.
 * @param {string} algorithm The hashing algorithm to be used.
 * @param {ReadableStream<Data>} input The input stream containing the message to be signed.
 * @param {string} inputEncoding The encoding of the `message`. If `message` is a string and no value is provided, an encoding of `'utf8'` will be enforced. Ignored if message is a `Buffer`, `TypedArray` or `DataView`.
 * @param {string} outputEncoding The encoding of the output signature. If provided a `string` is returned, otherwise a `Buffer` is returned.
 * @returns {Promise<string|Buffer>} The generated signature for the provided message.
 */
function signStream(
  privateKey,
  algorithm,
  input,
  inputEncoding,
  outputEncoding
) {
  return new Promise((resolve, reject) => {
    let data;
    let wasBuffer;

    const dataHandler = chunk => {
      const isBuffer = Buffer.isBuffer(chunk);
      if ((!isBuffer && wasBuffer) || (isBuffer && wasBuffer === false)) {
        reject(new Error('Inconsistent data.'));
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
        reject(new Error('No data to sign.'));
      } else {
        resolve(
          sign(privateKey, algorithm, data, inputEncoding, outputEncoding)
        );
      }
    });
  });
}

/**
 * Verify if a signature is valid for a given message using the corresponding public key.
 * @param {Object|string|Buffer|KeyObject} publicKey The public key to be used for verifying the signature.
 * @param {string} algorithm The hashing algorithm to be used.
 * @param {Data} message The message for which the signature has been generated.
 * @param {string|Buffer} signature The signature to be verified.
 * @param {string} inputEncoding The encoding of the `message`. If `message` is a string and no value is provided, an encoding of `'utf8'` will be enforced. Ignored if message is a `Buffer`, `TypedArray` or `DataView`.
 * @param {string} signatureEncoding The encoding of the provided `signature`. If a signatureEncoding is specified, the signature is expected to be a string; otherwise signature is expected to be a Buffer, TypedArray, or DataView.
 * @returns {boolean} Wether the signature was valid or not.
 */
function verify(
  publicKey,
  algorithm,
  message,
  signature,
  inputEncoding,
  signatureEncoding
) {
  const verifyFunc = crypto.createVerify(algorithm);
  verifyFunc.update(message, inputEncoding);
  verifyFunc.end();
  return verifyFunc.verify(publicKey, signature, signatureEncoding);
}

/**
 * Verify if a signature is valid for a given message encapsulated in a stream using the corresponding public key.
 * @param {Object|string|Buffer|KeyObject} publicKey The public key to be used for verifying the signature.
 * @param {string} algorithm The hashing algorithm to be used.
 * @param {ReadableStream<Data>} input The stream containing the message for which the signature has been generated.
 * @param {string|Buffer} signature The signature to be verified.
 * @param {string} inputEncoding The encoding of the `message`. If `message` is a string and no value is provided, an encoding of `'utf8'` will be enforced. Ignored if message is a `Buffer`, `TypedArray` or `DataView`.
 * @param {string} signatureEncoding The encoding of the provided `signature`. If a signatureEncoding is specified, the signature is expected to be a string; otherwise signature is expected to be a Buffer, TypedArray, or DataView.
 * @returns {Promise<boolean>} Wether the signature was valid or not.
 */
function verifyStream(
  publicKey,
  algorithm,
  input,
  signature,
  inputEncoding,
  signatureEncoding
) {
  return new Promise((resolve, reject) => {
    let data;
    let wasBuffer;

    const dataHandler = chunk => {
      const isBuffer = Buffer.isBuffer(chunk);
      if ((!isBuffer && wasBuffer) || (isBuffer && wasBuffer === false)) {
        reject(new Error('Inconsistent data.'));
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
        reject(new Error('No data to sign.'));
      } else {
        resolve(
          verify(
            publicKey,
            algorithm,
            data,
            signature,
            inputEncoding,
            signatureEncoding
          )
        );
      }
    });
  });
}

module.exports = { sign, signStream, verify, verifyStream };
