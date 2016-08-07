/**
 * Local dependencies
 */
const RsaHashedKeyAlgorithm = require('./RsaHashedKeyAlgorithm')
const RegisteredAlgorithms = require('./RegisteredAlgorithms')

/**
 * SupportedAlgorithms
 */
const supportedAlgorithms = {
  encrypt: new RegisteredAlgorithms({
    //'RSA-OAEP',
    //'AES-CTR',
    //'AES-CBC',
    //'AES-GCM',
    //'AES-CFB'
  }),
  decrypt: new RegisteredAlgorithms({
    //'RSA-OAEP',
    //'AES-CTR',
    //'AES-CBC',
    //'AES-GCM',
    //'AES-CFB'
  }),
  sign: new RegisteredAlgorithms({
    //'RSASSA-PKCS1-v1_5',
    //'RSA-PSS',
    //'ECDSA',
    //'AES-CMAC',
    //'HMAC'
  }),
  verify: new RegisteredAlgorithms({
    //'RSASSA-PKCS1-v1_5',
    //'RSA-PSS',
    //'ECDSA',
    //'AES-CMAC',
    //'HMAC'
  }),
  digest: new RegisteredAlgorithms({
    //'SHA-1',
    //'SHA-256',
    //'SHA-384',
    //'SHA-512'
  }),
  deriveKey: new RegisteredAlgorithms({
    //'ECDH',
    //'DH',
    //'CONCAT',
    //'HKDF-CTR',
    //'PBKDF2'
  }),
  deriveBits: new RegisteredAlgorithms({
    //'ECDH',
    //'DH',
    //'CONCAT',
    //'HKDF-CTR',
    //'PBKDF2'
  }),
  generateKey: new RegisteredAlgorithms({
    'RSASSA-PKCS1-v1_5': RsaHashedKeyAlgorithm,
    //'RSA-PSS',
    //'RSA-OAEP',
    //'ECDSA',
    //'ECDH',
    //'AES-CTR',
    //'AES-CBC',
    //'AES-CMAC',
    //'AES-GCM',
    //'AES-CFB',
    //'AES-KW',
    //'HMAC',
    //'DH',
    //'PBKDF2'
  }),
  importKey: new RegisteredAlgorithms({
    //'RSASSA-PKCS1-v1_5',
    //'RSA-PSS',
    //'RSA-OAEP',
    //'ECDSA',
    //'ECDH',
    //'AES-CTR',
    //'AES-CBC',
    //'AES-CMAC',
    //'AES-GCM',
    //'AES-CFB',
    //'AES-KW',
    //'HMAC',
    //'DH',
    //'CONCAT',
    //'HKDF-CTR',
    //'PBKDF2'
  }),
  exportKey: new RegisteredAlgorithms({
    //'RSASSA-PKCS1-v1_5',
    //'RSA-PSS',
    //'RSA-OAEP',
    //'ECDSA',
    //'ECDH',
    //'AES-CTR',
    //'AES-CBC',
    //'AES-CMAC',
    //'AES-GCM',
    //'AES-CFB',
    //'AES-KW',
    //'HMAC',
    //'DH'
  }),
  wrapKey: new RegisteredAlgorithms({
    //'RSA-OAEP',
    //'AES-CTR',
    //'AES-CBC',
    //'AES-GCM',
    //'AES-CFB',
    //'AES-KW'
  }),
  unwrapKey: new RegisteredAlgorithms({
    //'RSA-OAEP',
    //'AES-CTR',
    //'AES-CBC',
    //'AES-GCM',
    //'AES-CFB',
    //'AES-KW'
  })
}

/**
 * Export
 */
module.exports = supportedAlgorithms
