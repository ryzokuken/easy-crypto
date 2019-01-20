const crypto = require('crypto');

function sign(privateKey, algorithm, message, inputEncoding, outputEncoding) {
  const signFunc = crypto.createSign(algorithm);
  signFunc.update(message, inputEncoding);
  signFunc.end();
  return signFunc.sign(privateKey, outputEncoding);
}

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

function verify(publicKey, algorithm, message, inputEncoding, outputEncoding) {
  const verifyFunc = crypto.createVerify(algorithm);
  verifyFunc.update(message, inputEncoding);
  verifyFunc.end();
  return verifyFunc.verify(publicKey, outputEncoding);
}

function verifyStream(
  publicKey,
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
          verify(publicKey, algorithm, data, inputEncoding, outputEncoding)
        );
      }
    });
  });
}

module.exports = { sign, signStream, verify, verifyStream };
