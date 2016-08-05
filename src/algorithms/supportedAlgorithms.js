/**
 * SupportedAlgorithms
 */
const supportedAlgorithms = {
  encrypt: [
    'RSA-OAEP', 'AES-CTR', 'AES-CBC', 'AES-GCM', 'AES-CFB'
  ],
  decrypt: [
    'RSA-OAEP', 'AES-CTR', 'AES-CBC', 'AES-GCM', 'AES-CFB'
  ],
  sign: [
    'RSASSA-PKCS1-v1_5', 'RSA-PSS', 'ECDSA', 'AES-CMAC', 'HMAC'
  ],
  verify: [
    'RSASSA-PKCS1-v1_5', 'RSA-PSS', 'ECDSA', 'AES-CMAC', 'HMAC'
  ],
  digest: [
    'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'
  ],
  deriveKey: [
    'ECDH', 'DH', 'CONCAT', 'HKDF-CTR', 'PBKDF2'
  ],
  deriveBits: [
    'ECDH', 'DH', 'CONCAT', 'HKDF-CTR', 'PBKDF2'
  ],
  generateKey: [
    'RSASSA-PKCS1-v1_5', 'RSA-PSS', 'RSA-OAEP', 'ECDSA', 'ECDH', 'AES-CTR',
    'AES-CBC', 'AES-CMAC', 'AES-GCM', 'AES-CFB', 'AES-KW', 'HMAC', 'DH',
    'PBKDF2'
  ],
  importKey: [
    'RSASSA-PKCS1-v1_5', 'RSA-PSS', 'RSA-OAEP', 'ECDSA', 'ECDH', 'AES-CTR',
    'AES-CBC', 'AES-CMAC', 'AES-GCM', 'AES-CFB', 'AES-KW', 'HMAC', 'DH',
    'CONCAT', 'HKDF-CTR', 'PBKDF2'
  ],
  exportKey: [
    'RSASSA-PKCS1-v1_5', 'RSA-PSS', 'RSA-OAEP', 'ECDSA', 'ECDH', 'AES-CTR',
    'AES-CBC', 'AES-CMAC', 'AES-GCM', 'AES-CFB', 'AES-KW', 'HMAC', 'DH'
  ],
  wrapKey: [
    'RSA-OAEP', 'AES-CTR', 'AES-CBC', 'AES-GCM', 'AES-CFB', 'AES-KW'
  ],
  unwrapKey: [
    'RSA-OAEP', 'AES-CTR', 'AES-CBC', 'AES-GCM', 'AES-CFB', 'AES-KW'
  ]
}

/**
 * Export
 */
module.exports = supportedAlgorithms
