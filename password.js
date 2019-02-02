'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

var protobuf = require('protocol-buffers');

/**
 * The password module provides utilities for dealing with passwords. This
 * includes hashing and verifying passwords as well as derive secure
 * cryptographic keys from passwords.
 * @module easy-crypto/password
 */

/**
 * The message format for encoding and decoding data using protobuf.
 * @constant {Object}
 * @inner
 */
const messages = protobuf(
  fs.readFileSync(path.resolve(__dirname, './password.proto'))
);

/**
 * An error that hints that the hashing algorithm used is no longer valid and a
 * rehash is required.
 * @constant {Error}
 * @since 0.2.0
 * @static
 */
const InvalidHashError = new Error('Invalid algorithm, rehash required.');

/**
 * Derive a cryptographically secure key using a password and a salt.
 * @since 0.2.0
 * @async
 * @function deriveKey
 * @param {Data} password The password to be used
 * for key derivation.
 * @param {Data} salt The salt to be applied to the
 * password. The salt should be as unique as possible. It is recommended that a
 * salt is random and at least 16 bytes long. See NIST SP 800-132 for details.
 * @param {number} iterations The number of iterations to be performed. The
 * value must be a number set as high as possible. The higher the number of
 * iterations, the more secure the derived key will be, but will take a longer
 * amount of time to complete.
 * @param {number} keylen The length of the key to be produced.
 * @param {string} digest The HMAC digest algorithm to be used.
 * @returns {Promise<Buffer>} The derived key.
 * @static
 */
function deriveKey(password, salt, iterations, keylen, digest) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keylen, digest, (err, key) => {
      if (err) reject(err);
      resolve(key);
    });
  });
}

/**
 * Derive a cryptographically secure key synchronously using a password and a salt.
 * @since 0.2.0
 * @function deriveKeySync
 * @param {Data} password The password to be used
 * for key derivation.
 * @param {Data} salt The salt to be applied to the
 * password. The salt should be as unique as possible. It is recommended that a
 * salt is random and at least 16 bytes long. See NIST SP 800-132 for details.
 * @param {number} iterations The number of iterations to be performed. The
 * value must be a number set as high as possible. The higher the number of
 * iterations, the more secure the derived key will be, but will take a longer
 * amount of time to complete.
 * @param {number} keylen The length of the key to be produced.
 * @param {string} digest The HMAC digest algorithm to be used.
 * @returns {Buffer} The derived key.
 * @static
 */
function deriveKeySync(password, salt, iterations, keylen, digest) {
  return crypto.pbkdf2Sync(password, salt, iterations, keylen, digest);
}

/**
 * Hash a password for storage.
 * @since 0.2.0
 * @async
 * @function hashPassword
 * @param {Data} password The password to be hashed.
 * @returns {Promise<Buffer>} The hashed password optimized for storage.
 * @static
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(32);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, hashedPassword) => {
      if (err) return reject(err);
      resolve(
        messages.Password.encode({
          algorithm: messages.Algorithm.SCRYPT,
          salt,
          length: 64,
          hash: hashedPassword
        })
      );
    });
  });
}

/**
 * Hash a password synchronously for storage.
 * @since 0.2.0
 * @function hashPasswordSync
 * @param {Data} password The password to be hashed.
 * @returns {Buffer} The hashed password optimized for storage.
 * @static
 */
function hashPasswordSync(password) {
  const salt = crypto.randomBytes(32);
  const hashedPassword = crypto.scryptSync(password, salt, 64);
  return messages.Password.encode({
    algorithm: messages.Algorithm.SCRYPT,
    salt,
    length: 64,
    hash: hashedPassword
  });
}

/**
 * Verify a previously hashed and stored password.
 * @since 0.2.0
 * @async
 * @function verifyHash
 * @param {Buffer} hashed The hashed password to be verified.
 * @param {Data} password The actual password.
 * @returns {Promise<boolean>} Wether the hash was valid for the given password.
 * @static
 */
function verifyHash(hashed, password) {
  return new Promise((resolve, reject) => {
    const { algorithm, salt, length, hash } = messages.Password.decode(hashed);
    if (algorithm !== messages.Algorithm.SCRYPT || hash.length !== length)
      return reject(InvalidHashError);
    crypto.scrypt(password, salt, 64, (err, recomputed) => {
      if (err) return reject(err);
      resolve(crypto.timingSafeEqual(recomputed, hash));
    });
  });
}

/**
 * Verify a previously hashed and stored password synchronously.
 * @since 0.2.0
 * @function verifyHashSync
 * @param {Buffer} hashed The hashed password to be verified.
 * @param {Data} password The actual password.
 * @returns {Promise<boolean>} Wether the hash was valid for the given password.
 * @throws {module:easy-crypto/password.InvalidHashError} The hash was produced
 * using an invalid algorithm.
 * A rehash with the currently valid algorithm is required.
 * @static
 */
function verifyHashSync(hashed, password) {
  const { algorithm, salt, length, hash } = messages.Password.decode(hashed);
  if (algorithm !== messages.Algorithm.SCRYPT || hash.length !== length)
    throw InvalidHashError;
  const recomputed = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(recomputed, hash);
}

module.exports = {
  deriveKey,
  deriveKeySync,
  hashPassword,
  hashPasswordSync,
  verifyHash,
  verifyHashSync,
  InvalidHashError
};
