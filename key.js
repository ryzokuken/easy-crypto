const crypto = require('crypto');

/**
 * The key module exposes various utilities for generating and handling
 * symmetric and asymmetric keys.
 * @module easy-crypto/key
 */

/**
 * A cryptographic key.
 * @typedef {(string|Buffer|KeyObject)} Key
 * @inner
 */

/**
 * A pair of assymetric cryptographic keys.
 * @typedef {Object} KeyPair
 * @property {module:easy-crypto/key~Key} publicKey
 * @property {module:easy-crypto/key~Key} privateKey
 * @inner
 */

/**
 * Generate a keypair for use in asymmetric cryptographic functions.
 * @since REPLACEME
 * @async
 * @function generateKeyPair
 * @param {string} type The type of the keys to be generated.
 * @param {string} format The format of the keys to be generated.
 * @param {string} passphrase The passphrase for encrypting the private key.
 * @returns {Promise<module:easy-crypto/key~KeyPair>} A pair of keys.
 * @static
 */
function generateKeyPair(type, format, passphrase) {
  let publicKeyEncoding = {};
  let privateKeyEncoding = {};

  if (format === 'pem' || format === 'der') {
    Object.assign(privateKeyEncoding, {
      type: 'pkcs8',
      format
    });
    Object.assign(publicKeyEncoding, {
      type: 'spki',
      format
    });
  } else if (format === 'object') {
    publicKeyEncoding = undefined;
    privateKeyEncoding = undefined;
  } else {
    throw new TypeError('Invalid format.');
  }

  if (passphrase !== undefined && format !== 'object') {
    Object.assign(privateKeyEncoding, {
      cipher: 'aes-256-cbc',
      passphrase
    });
  }

  return new Promise((resolve, reject) => {
    const options = {
      publicKeyEncoding,
      privateKeyEncoding
    };
    Object.assign(
      options,
      type === 'ec' ? { namedCurve: 'sect239k1' } : { modulusLength: 4096 }
    );

    crypto.generateKeyPair(type, options, (err, publicKey, privateKey) => {
      if (err) return reject(err);

      if (format === 'object') {
        return resolve({ privateKey, publicKey });
      } else {
        const privKey = { key: privateKey };
        const pubKey = { key: publicKey };

        Object.assign(privKey, { format, type: 'pkcs8' });
        Object.assign(pubKey, { format, type: 'spki' });
        if (passphrase !== undefined) Object.assign(privKey, { passphrase });

        return resolve({ privateKey: privKey, publicKey: pubKey });
      }
    });
  });
}

module.exports = { generateKeyPair };
