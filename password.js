const crypto = require('crypto');

/**
 * The password module provides utilities for dealing with passwords. This
 * includes hashing and verifying passwords as well as derive secure
 * cryptographic keys from passwords.
 * @module easy-crypto/password
 */

/**
 * Derive a cryptographically secure key using a password and a salt.
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
 */
function deriveKeySync(password, salt, iterations, keylen, digest) {
  return crypto.pbkdf2Sync(password, salt, iterations, keylen, digest);
}

/**
 * Hash a password using the scrypt password-based.
 * @param {Data} password The password to be hashed.
 * @param {Data} salt The salt to be used while hashing. The salt should be as
 * unique as possible. It is recommended that a salt is random and at least 16
 * bytes long. See NIST SP 800-132 for details.
 * @param {number} keylen The length of the output hash.
 * @param {Object} [options]
 * @param {number} [options.cost=16384] CPU/memory cost parameter. Must be a
 * power of two greater than one.
 * @param {number} [options.blockSize=8] Block size parameter.
 * @param {number} [options.parallelization=1] Parallelization parameter.
 * @returns {Promise<Buffer>} The derived key.
 */
function hashPassword(password, salt, keylen, options) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey);
    });
  });
}

module.exports = { deriveKey, deriveKeySync, hashPassword };
