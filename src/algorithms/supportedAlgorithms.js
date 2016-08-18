/**
 * Local dependencies
 */
const Algorithm = require('./Algorithm')
const KeyAlgorithm = require('./KeyAlgorithm')
const RegisteredAlgorithms = require('./RegisteredAlgorithms')
const RsaHashedKeyAlgorithm = require('./RsaHashedKeyAlgorithm')
const ShaKeyAlgorithm = require('./ShaKeyAlgorithm')
const NotSupportedError = require('../errors/NotSupportedError')

/**
 * Supported Operations
 */
const operations = [
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'deriveBits',
  'digest', // THIS WASN'T IN THE LIST. PROBABLY GETTING SOMETHING WRONG HERE
  'wrapKey',
  'unwrapKey',
  'generateKey',
  'importKey',
  'exportKey',
  'getLength'
]

/**
 * SupportedAlgorithms
 */
class SupportedAlgorithms {

  /**
   * Constructor
   */
  constructor () {
    operations.forEach(op => {
      this[op] = new RegisteredAlgorithms()
    })
  }

  /**
   * Supported Operations
   */
  static get operations () {
    return operations
  }

  /**
   * Define Algorithm
   */
  define (alg, op, type) {
    let registeredAlgorithms = this[op]
    registeredAlgorithms[alg] = type
  }

  /**
   * Normalize
   */
  normalize (op, alg) {
    if (typeof alg === 'string') {
      return this.normalize(op, new KeyAlgorithm({ name: alg }))
    }

    if (typeof alg === 'object') {
      let registeredAlgorithms = this[op]
      let initialAlg

      try {
        initialAlg = new Algorithm(alg)
      } catch (error) {
        return error
      }

      let algName = initialAlg.name
      algName = registeredAlgorithms.getCaseInsensitive(algName)

      if (algName === undefined) {
        return new NotSupportedError(algName)
      }

      let desiredType, normalizedAlgorithm

      try {
        desiredType = registeredAlgorithms[algName]
        normalizedAlgorithm = new desiredType(alg)
        normalizedAlgorithm.name = algName
      } catch (error) {
        return error
      }

      let dictionaries = desiredType.dictionaries

      for (let i = 0; i < dictionaries.length; i++) {
        let dictionary = dictionaries[i]
        let members = dictionary.members

        for (let key in members) {
          let member = members[key]
          let idlValue = normalizedAlgorithm[key]

          try {
            if (member === 'BufferSource' && idlValue !== undefined) {
              normalizedAlgorithm[key] = idlValue.slice()
            }

            if (member === 'HashAlgorithmIdentifier') {
              let hashAlgorithm = this.normalize('digest', idlValue)
              if (hashAlgorithm instanceof Error) { return hashAlgorithm }
              normalizedAlgorithm[key] = hashAlgorithm
            }

            if (member === 'AlgorithmIdentifier') {
              normalizedAlgorithm[key] = this.normalize(WTF, idlValue)
            }
          } catch (error) {
            return error
          }
        }
      }

      return normalizedAlgorithm
    }
  }
}

/**
 * Register Supported Algorithms
 */
const supportedAlgorithms = new SupportedAlgorithms()

/**
 * encrypt
 */
//supportedAlgorithms.define('RSA-OAEP', 'encrypt', )
//supportedAlgorithms.define('AES-CTR', 'encrypt', )
//supportedAlgorithms.define('AES-CBC', 'encrypt', )
//supportedAlgorithms.define('AES-GCM', 'encrypt', )
//supportedAlgorithms.define('AES-CFB', 'encrypt', )

/**
 * decrypt
 */
//supportedAlgorithms.define('RSA-OAEP', 'decrypt', )
//supportedAlgorithms.define('AES-CTR', 'decrypt', )
//supportedAlgorithms.define('AES-CBC', 'decrypt', )
//supportedAlgorithms.define('AES-GCM', 'decrypt', )
//supportedAlgorithms.define('AES-CFB', 'decrypt', )

/**
 * sign
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'sign', RsaHashedKeyAlgorithm)
//supportedAlgorithms.define('RSA-PSS', 'sign', )
//supportedAlgorithms.define('ECDSA', 'sign', )
//supportedAlgorithms.define('AES-CMAC', 'sign', )
//supportedAlgorithms.define('HMAC', 'sign', )

/**
 * verify
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'verify', RsaHashedKeyAlgorithm)
//supportedAlgorithms.define('RSA-PSS', 'verify', )
//supportedAlgorithms.define('ECDSA', 'verify', )
//supportedAlgorithms.define('AES-CMAC', 'verify', )
//supportedAlgorithms.define('HMAC', 'verify', )

/**
 * digest
 */
supportedAlgorithms.define('SHA-1', 'digest', ShaKeyAlgorithm)
supportedAlgorithms.define('SHA-256', 'digest', ShaKeyAlgorithm)
supportedAlgorithms.define('SHA-384', 'digest', ShaKeyAlgorithm)
supportedAlgorithms.define('SHA-512', 'digest', ShaKeyAlgorithm)

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
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'generateKey', RsaHashedKeyAlgorithm)
//supportedAlgorithms.define('RSA-PSS', 'generateKey', )
//supportedAlgorithms.define('RSA-OAEP', 'generateKey', )
//supportedAlgorithms.define('ECDSA', 'generateKey', )
//supportedAlgorithms.define('ECDH', 'generateKey', )
//supportedAlgorithms.define('AES-CTR', 'generateKey', )
//supportedAlgorithms.define('AES-CBC', 'generateKey', )
//supportedAlgorithms.define('AES-CMAC', 'generateKey', )
//supportedAlgorithms.define('AES-GCM', 'generateKey', )
//supportedAlgorithms.define('AES-CFB', 'generateKey', )
//supportedAlgorithms.define('AES-KW', 'generateKey', )
//supportedAlgorithms.define('HMAC', 'generateKey', )
//supportedAlgorithms.define('DH', 'generateKey', )
//supportedAlgorithms.define('PBKDF2', 'generateKey', )

/**
 * importKey
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'importKey', RsaHashedKeyAlgorithm)
//supportedAlgorithms.define('RSA-PSS', 'importKey', )
//supportedAlgorithms.define('RSA-OAEP', 'importKey', )
//supportedAlgorithms.define('ECDSA', 'importKey', )
//supportedAlgorithms.define('ECDH', 'importKey', )
//supportedAlgorithms.define('AES-CTR', 'importKey', )
//supportedAlgorithms.define('AES-CBC', 'importKey', )
//supportedAlgorithms.define('AES-CMAC', 'importKey', )
//supportedAlgorithms.define('AES-GCM', 'importKey', )
//supportedAlgorithms.define('AES-CFB', 'importKey', )
//supportedAlgorithms.define('AES-KW', 'importKey', )
//supportedAlgorithms.define('HMAC', 'importKey', )
//supportedAlgorithms.define('DH', 'importKey', )
//supportedAlgorithms.define('CONCAT', 'importKey', )
//supportedAlgorithms.define('HKDF-CTR', 'importKey', )
//supportedAlgorithms.define('PBKDF2', 'importey', )

/**
 * exportKey
 */
supportedAlgorithms.define('RSASSA-PKCS1-v1_5', 'exportKey', RsaHashedKeyAlgorithm)
//supportedAlgorithms.define('RSA-PSS', 'exportKey', )
//supportedAlgorithms.define('RSA-OAEP', 'exportKey', )
//supportedAlgorithms.define('ECDSA', 'exportKey', )
//supportedAlgorithms.define('ECDH', 'exportKey', )
//supportedAlgorithms.define('AES-CTR', 'exportKey', )
//supportedAlgorithms.define('AES-CBC', 'exportKey', )
//supportedAlgorithms.define('AES-CMAC', 'exportKey', )
//supportedAlgorithms.define('AES-GCM', 'exportKey', )
//supportedAlgorithms.define('AES-CFB', 'exportKey', )
//supportedAlgorithms.define('AES-KW', 'exportKey', )
//supportedAlgorithms.define('HMAC', 'exportKey', )
//supportedAlgorithms.define('DH', 'exportKey', )

/**
 * wrapKey
 */
//supportedAlgorithms.define('RSA-OAEP', 'wrapKey', )
//supportedAlgorithms.define('AES-CTR', 'wrapKey', )
//supportedAlgorithms.define('AES-CBC', 'wrapKey', )
//supportedAlgorithms.define('AES-GCM', 'wrapKey', )
//supportedAlgorithms.define('AES-CFB', 'wrapKey', )
//supportedAlgorithms.define('AES-KW', 'wrapKey', )

/**
 * unwrapKey
 */
//supportedAlgorithms.define('RSA-OAEP', 'unwrapKey', )
//supportedAlgorithms.define('AES-CTR', 'unwrapKey', )
//supportedAlgorithms.define('AES-CBC', 'unwrapKey', )
//supportedAlgorithms.define('AES-GCM', 'unwrapKey', )
//supportedAlgorithms.define('AES-CFB', 'unwrapKey', )
//supportedAlgorithms.define('AES-KW', 'unwrapKey', )

/**
 * Export
 */
module.exports = supportedAlgorithms
