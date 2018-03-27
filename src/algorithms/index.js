/**
 * Local dependencies
 */
const SupportedAlgorithms = require('./SupportedAlgorithms')

/**
 * Register Supported Algorithms
 */
const supportedAlgorithms = new SupportedAlgorithms()

/**
 * encrypt
 */
supportedAlgorithms.define('RSA-OAEP', 'encrypt', '../algorithms/RSA-OAEP')
supportedAlgorithms.define('AES-CTR', 'encrypt', '../algorithms/AES-CTR')
supportedAlgorithms.define('AES-CBC', 'encrypt', '../algorithms/AES-CBC')
supportedAlgorithms.define('AES-GCM', 'encrypt', '../algorithms/AES-GCM')
//supportedAlgorithms.define('AES-CFB', 'encrypt', )

/**
 * decrypt
 */
supportedAlgorithms.define('RSA-OAEP', 'decrypt', '../algorithms/RSA-OAEP')
supportedAlgorithms.define('AES-CTR', 'decrypt', '../algorithms/AES-CTR')
supportedAlgorithms.define('AES-CBC', 'decrypt', '../algorithms/AES-CBC')
supportedAlgorithms.define('AES-GCM', 'decrypt', '../algorithms/AES-GCM')
//supportedAlgorithms.define('AES-CFB', 'decrypt', )

/**
 * sign
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'sign', '../algorithms/RSASSA-PKCS1-v1_5')
supportedAlgorithms.define('RSA-PSS', 'sign', '../algorithms/RSA-PSS')
supportedAlgorithms.define('ECDSA', 'sign', '../algorithms/ECDSA')
supportedAlgorithms.define('EDDSA', 'sign', '../algorithms/EDDSA')
//supportedAlgorithms.define('AES-CMAC', 'sign', )
supportedAlgorithms.define('HMAC', 'sign', '../algorithms/HMAC')

/**
 * verify
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'verify', '../algorithms/RSASSA-PKCS1-v1_5')
supportedAlgorithms.define('RSA-PSS', 'verify', '../algorithms/RSA-PSS')
supportedAlgorithms.define('ECDSA', 'verify', '../algorithms/ECDSA')
supportedAlgorithms.define('EDDSA', 'verify', '../algorithms/EDDSA')
//supportedAlgorithms.define('AES-CMAC', 'verify', )
supportedAlgorithms.define('HMAC', 'verify', '../algorithms/HMAC')

/**
 * digest
 */
supportedAlgorithms.define('SHA-1', 'digest', '../algorithms/SHA')
supportedAlgorithms.define('SHA-256', 'digest', '../algorithms/SHA')
supportedAlgorithms.define('SHA-384', 'digest', '../algorithms/SHA')
supportedAlgorithms.define('SHA-512', 'digest', '../algorithms/SHA')

/**
 * deriveKey
 */
//supportedAlgorithms.define('ECDH', 'deriveKey', )
//supportedAlgorithms.define('DH', 'deriveKey', )
//supportedAlgorithms.define('CONCAT', 'deriveKey', )
//supportedAlgorithms.define('HKDF-CTR', 'deriveKey', )
//supportedAlgorithms.define('PBKDF2', 'deriveKey', )

/**
 * deriveBits
 */
//supportedAlgorithms.define('ECDH', 'deriveBits', )
//supportedAlgorithms.define('DH', 'deriveBits', )
//supportedAlgorithms.define('CONCAT', 'deriveBits', )
//supportedAlgorithms.define('HKDF-CTR', 'deriveBits', )
//supportedAlgorithms.define('PBKDF2', 'deriveBits', )

/**
 * generateKey
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'generateKey', '../algorithms/RSASSA-PKCS1-v1_5')
supportedAlgorithms.define('RSA-PSS', 'generateKey', '../algorithms/RSA-PSS')
supportedAlgorithms.define('RSA-OAEP', 'generateKey', '../algorithms/RSA-OAEP')
supportedAlgorithms.define('ECDSA', 'generateKey', '../algorithms/ECDSA')
supportedAlgorithms.define('EDDSA', 'generateKey', '../algorithms/EDDSA')
//supportedAlgorithms.define('ECDH', 'generateKey', )
supportedAlgorithms.define('AES-CTR', 'generateKey', '../algorithms/AES-CTR')
supportedAlgorithms.define('AES-CBC', 'generateKey', '../algorithms/AES-CBC')
//supportedAlgorithms.define('AES-CMAC', 'generateKey', )
supportedAlgorithms.define('AES-GCM', 'generateKey', '../algorithms/AES-GCM')
//supportedAlgorithms.define('AES-CFB', 'generateKey', )
supportedAlgorithms.define('AES-KW', 'generateKey', '../algorithms/AES-KW')
supportedAlgorithms.define('HMAC', 'generateKey', '../algorithms/HMAC')
//supportedAlgorithms.define('DH', 'generateKey', )
//supportedAlgorithms.define('PBKDF2', 'generateKey', )

/**
 * importKey
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'importKey', '../algorithms/RSASSA-PKCS1-v1_5')
supportedAlgorithms.define('RSA-PSS', 'importKey', '../algorithms/RSA-PSS')
supportedAlgorithms.define('RSA-OAEP', 'importKey', '../algorithms/RSA-OAEP')
supportedAlgorithms.define('ECDSA', 'importKey', '../algorithms/ECDSA')
supportedAlgorithms.define('EDDSA', 'importKey', '../algorithms/EDDSA')
//supportedAlgorithms.define('ECDH', 'importKey', )
supportedAlgorithms.define('AES-CTR', 'importKey', '../algorithms/AES-CTR')
supportedAlgorithms.define('AES-CBC', 'importKey', '../algorithms/AES-CBC')
//supportedAlgorithms.define('AES-CMAC', 'importKey', )
supportedAlgorithms.define('AES-GCM', 'importKey', '../algorithms/AES-GCM')
//supportedAlgorithms.define('AES-CFB', 'importKey', )
supportedAlgorithms.define('AES-KW', 'importKey', '../algorithms/AES-KW')
supportedAlgorithms.define('HMAC', 'importKey', '../algorithms/HMAC')
//supportedAlgorithms.define('DH', 'importKey', )
//supportedAlgorithms.define('CONCAT', 'importKey', )
//supportedAlgorithms.define('HKDF-CTR', 'importKey', )
//supportedAlgorithms.define('PBKDF2', 'importey', )

/**
 * exportKey
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'exportKey', '../algorithms/RSASSA-PKCS1-v1_5')
supportedAlgorithms.define('RSA-PSS', 'exportKey', '../algorithms/RSA-PSS')
supportedAlgorithms.define('RSA-OAEP', 'exportKey', '../algorithms/RSA-OAEP')
supportedAlgorithms.define('EDDSA', 'exportKey', '../algorithms/EDDSA')
supportedAlgorithms.define('ECDSA', 'exportKey', '../algorithms/ECDSA')
//supportedAlgorithms.define('ECDH', 'exportKey', )
supportedAlgorithms.define('AES-CTR', 'exportKey', '../algorithms/AES-CTR')
supportedAlgorithms.define('AES-CBC', 'exportKey', '../algorithms/AES-CBC')
//supportedAlgorithms.define('AES-CMAC', 'exportKey', )
supportedAlgorithms.define('AES-GCM', 'exportKey', '../algorithms/AES-GCM')
//supportedAlgorithms.define('AES-CFB', 'exportKey', )
supportedAlgorithms.define('AES-KW', 'exportKey', '../algorithms/AES-KW')
supportedAlgorithms.define('HMAC', 'exportKey', '../algorithms/HMAC')
//supportedAlgorithms.define('DH', 'exportKey', )

/**
 * wrapKey
 */
supportedAlgorithms.define('RSA-OAEP', 'wrapKey', '../algorithms/RSA-OAEP')
supportedAlgorithms.define('AES-CTR', 'wrapKey', '../algorithms/AES-CTR')
supportedAlgorithms.define('AES-CBC', 'wrapKey', '../algorithms/AES-CBC')
supportedAlgorithms.define('AES-GCM', 'wrapKey', '../algorithms/AES-GCM')
//supportedAlgorithms.define('AES-CFB', 'wrapKey', )
supportedAlgorithms.define('AES-KW', 'wrapKey', '../algorithms/AES-KW')

/**
 * unwrapKey
 */
supportedAlgorithms.define('RSA-OAEP', 'unwrapKey', '../algorithms/RSA-OAEP')
supportedAlgorithms.define('AES-CTR', 'unwrapKey', '../algorithms/AES-CTR')
supportedAlgorithms.define('AES-CBC', 'unwrapKey', '../algorithms/AES-CBC')
supportedAlgorithms.define('AES-GCM', 'unwrapKey', '../algorithms/AES-GCM')
//supportedAlgorithms.define('AES-CFB', 'unwrapKey', )
supportedAlgorithms.define('AES-KW', 'unwrapKey', '../algorithms/AES-KW')

/**
 * Export
 */
module.exports = supportedAlgorithms