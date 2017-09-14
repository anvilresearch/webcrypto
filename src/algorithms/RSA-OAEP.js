/**
 * Package dependencies
 */
const crypto = require('crypto')
const base64url = require('base64url') 
const keyto = require('@trust/keyto')
const {spawnSync} = require('child_process')
const {TextEncoder, TextDecoder} = require('text-encoding')

/**
 * Local dependencies
 */
const KeyAlgorithm = require('../dictionaries/KeyAlgorithm')
const AesKeyAlgorithm = require('../dictionaries/AesKeyAlgorithm') 
const Algorithm = require ('../algorithms/Algorithm')
const CryptoKey = require('../keys/CryptoKey')
const CryptoKeyPair = require('../keys/CryptoKeyPair')
const JsonWebKey = require('../keys/JsonWebKey')
const RsaKeyAlgorithm = require('../dictionaries/RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('../dictionaries/RsaHashedKeyAlgorithm')
const supportedAlgorithms = require('../algorithms')

/**
 * Errors
 */
const {
  DataError,
  OperationError,
  InvalidAccessError,
  KeyFormatNotSupportedError,
  CurrentlyNotSupportedError
} = require('../errors')

/**
 * RSA-OAEP
 */
class RSA_OAEP extends Algorithm {


    /**
     * Constructor
     */
    constructor (algorithm) {
      super(algorithm)
      if (typeof algorithm === "object" && algorithm !== null ){
        if (!algorithm.hash || !algorithm.hash.name){
          throw new Error('Algorithm requires a valid hash object.')
        } 
      } else {
        throw new Error('Algorithm must be an object with a name and hash.')
      }

    }

    /**
     * dictionaries
     */
    static get dictionaries () {
      return [
        KeyAlgorithm,
        AesKeyAlgorithm
      ]
    }

    /**
     * members
     */
    static get members () {
      return {
        name: String,
        modulusLength: Number,
        publicExponent: 'BufferSource'
      }
    }

    /**
     * encrypt
     *
     * @description
     * Encrypts an RSA-OAEP digital signature
     *
     * @param {RsaOaepParams} algorithm
     * @param {CryptoKey} key
     * @param {BufferSource} data
     *
     * @returns {Array}
     */
    encrypt (algorithm, key, data) {
      let result
      // 1. Ensure the key is a public type only
      if (key.type !== 'public') {
        throw new InvalidAccessError('Encrypt requires a public key')
      }

      // 2. Assign label
      // TODO Investigate use for label within context
      let label
      if (algorithm.label !== undefined){
        label = algorithm.label
      } else {
        label = ""
      }

      // TODO Remove this error once additional Node support is available.
      if (key.algorithm.hash.name !== 'SHA-1'){
        throw new CurrentlyNotSupportedError(key.algorithm.hash.name,'SHA-1')
      }
      
      // 3-5. Attempt to encrypt using crypto lib
      try {
        data = Buffer.from(data)
        result = crypto.publicEncrypt(
          {
            key: key.handle, 
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
          },
          data)
      } catch (error) {
        throw new OperationError(error.message)
      }
      // 7. Return resulting buffer
      return result.buffer
    }

    /**
     * decrypt
     *
     * @description
     * Decrypts an RSA-OAEP digital signature
     *
     * @param {AesKeyAlgorithm} algorithm
     * @param {CryptoKey} key
     * @param {BufferSource} data
     *
     * @returns {Array}
     */
    decrypt (algorithm, key, data) {
      let result
      // 1. Ensure the key is a private type only
      if (key.type !== 'private') {
        throw new InvalidAccessError('Decrypt requires a private key')
      }

      // 2. Assign label
      let label
      if (algorithm.label !== undefined){
        label = algorithm.label
      } else {
        label = ""
      }

      // TODO Remove this error once additional Node support is available.
      if (key.algorithm.hash.name !== 'SHA-1'){
        throw new CurrentlyNotSupportedError(key.algorithm.hash.name,'SHA-1')
      }
      
      // 3-5. Attempt to decrypt using crypto lib
      try {
        data = Buffer.from(data)
        result = crypto.privateDecrypt({
          key: key.handle, 
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        data)
      } catch (error) {
        throw new OperationError(error.message)
      }
      // 7. Return resulting buffer
      return result.buffer
    }

    /**
     * generateKey
     *
     * @description
     * Generate an RSA-OAEP key pair
     *
     * @param {RsaOaepParams} params
     * @returns {CryptoKeyPair}
     */
    generateKey (params, extractable, usages) {
      // 1. Validate usages
      usages.forEach(usage => {
        if (usage !== 'encrypt' && usage !== 'decrypt' && usage !== 'wrapKey' && usage !== 'unwrapKey') {
          throw new SyntaxError('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
        }
      })
      
      // 2. Generate RSA key pair 
      let keypair = {}
      try {
        let {modulusLength,publicExponent} = params

        // Get the keypairs from openssl spawns
        let privateKey = spawnSync('openssl', ['genrsa', modulusLength || 4096]).stdout
        let publicKey = spawnSync('openssl', ['rsa', '-pubout'], { input: privateKey }).stdout
        
        // Convert to ascii strings
        keypair.privateKey = privateKey.toString('ascii')
        keypair.publicKey = publicKey.toString('ascii')

      } catch (error) {
        throw new OperationError(error.message)
      }
      
      // 4-8. Set new RSA-OAEP object with params carried over
      let algorithm = new RSA_OAEP(params)

      // 9-13. Create publicKey object
      let publicKey = new CryptoKey({
        type: 'public',
        algorithm,
        extractable: true,
        usages: ['encrypt','wrapKey'],
        handle: keypair.publicKey
      })

      // 14-18. Create privateKey object
      let privateKey = new CryptoKey({
        type: 'private',
        algorithm,
        extractable: extractable,
        usages: ['decrypt','unwrapKey'],
        handle: keypair.privateKey
      })

      // 19-22. Return Key CryptoKeyPair
      return new CryptoKeyPair({publicKey,privateKey})
  }

    /**
     * importKey
     *
     * @description
     *
     * @param {string} format
     * @param {string|JsonWebKey} keyData
     * @param {KeyAlgorithm} algorithm
     * @param {Boolean} extractable
     * @param {Array} keyUsages
     *
     * @returns {CryptoKey}
     */
    importKey (format, keyData, algorithm, extractable, keyUsages) {
      let data, key, jwk, hash, normalizedHash
      // 1. Assignment of keyData is done in function param
      // 2.1. "spki" format
      if (format === 'spki') {
        // TODO Add support for spki
        throw new CurrentlyNotSupportedError(format,'jwk')
      } 
      // 2.2. "pkcs8" format
      else if (format === 'pkcs8') {
        // TODO Add support for pkcs8
        throw new CurrentlyNotSupportedError(format,'jwk')
      } 
      // 2.3. "jwk" format
      else if (format === 'jwk') {
        // 2.3.1. Create new JWK using data
        jwk = new JsonWebKey(keyData)

        // 2.3.2. Validate present 'd' field and allowed usages
        if (jwk.d) 
        {
          keyUsages.forEach(usage => {
            if (usage !== 'decrypt' && usage !== 'unwrapKey') {
              throw new SyntaxError('Key usages can only include "decrypt" or "unwrapKey"')
            }
          })
        }

        // 2.3.3. Validate absent 'd' field and allowed usages
        if (jwk.d === undefined) {
          keyUsages.forEach(usage => {
            if (usage !== 'encrypt' && usage !== 'wrapKey') {
              throw new SyntaxError('Key usages can only include "encrypt" or "wrapKey"')
            }
          })
        }

        // 2.3.4. Validate 'kty' field and allowed string match
        if (jwk.kty !== 'RSA') {
          throw new DataError('Key type must be RSA')
        }

        // 2.3.5. Validate present 'use' field and allowed string match
        if (jwk.use !== undefined && jwk.use !== 'sig') {
          throw new DataError('Key use must be "sig"')
        }

        // 2.3.6. Validate present 'key_ops' field 
        if (jwk.key_ops !== undefined) {
          jwk.key_ops.forEach(op => {
             if (op !== 'encrypt'
              && op !== 'decrypt'
              && op !== 'wrapKey'
              && op !== 'unwrapKey' ) {
                throw new DataError('Key operation can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey".')
            }
          })
        }

        // 2.3.7. Validate present 'ext' field
        if (jwk.ext !== undefined && jwk.ext === false && extractable === true){
          throw new DataError('Cannot be extractable when "ext" is set to false')
        }

        // 2.3.8.1. 'alg' field is not present
        if (jwk.alg === undefined){
          // Leave undefined
        } 
        // 2.3.8.2. 'alg' field is "RSA-OAEP"
        else if (jwk.alg === 'RSA-OAEP'){
          hash = 'SHA-1'
        } 
        // 2.3.8.3. 'alg' field is "RSA-OAEP-256"
        else if (jwk.alg === 'RSA-OAEP-256'){
          hash = 'SHA-256'
        } 
        // 2.3.8.4. 'alg' field is "RSA-OAEP-384"
        else if (jwk.alg === 'RSA-OAEP-384'){
          hash = 'SHA-384'
        } 
        // 2.3.8.5. 'alg' field is "RSA-OAEP-512"
        else if (jwk.alg === 'RSA-OAEP-512'){
          hash = 'SHA-512'
        } 
        // 2.3.8.6. Otherwise...
        else {
          // TODO Perform alternative key import steps defined by other applicable specifications
          throw new CurrentlyNotSupportedError(jwk.alg,'RSA-OAEP')
        }

        // 2.3.9. If hash not undefined then...
        if (hash !== undefined){
          // 2.3.9.1. Normalize the hash with alg set to 'hash', and op to 'digest'
          normalizedHash = supportedAlgorithms.normalize('digest', hash)

          // 2.3.9.2. Validate hash member of normalizedAlgorithm
          if (!normalizedHash || normalizedHash.name !== this.hash.name) {
            throw new DataError("Unknown hash or mismatched hash name.")
          }
        }

        // 2.3.10. Validate 'd' field...
        if (jwk.d) {
          // 2.3.10.1.1. TODO jwk validation here...
          // 2.3.10.1.2-5 Generate new private CryptoKeyObject
          key = new CryptoKey({
              type: 'private',
              extractable,
              usages: ['decrypt'],
              handle: keyto.from(jwk, 'jwk').toString('pem', 'private_pkcs1')
          })
        }
        // 2.3.10.2. Otherwise...
        else {
          // 2.3.10.2.1 TODO jwk validation here...
          // 2.3.10.2.2-5 Generate new public CryptoKeyObject
          key = new CryptoKey({
            type: 'public',
            extractable: true,
            usages: ['encrypt'],
            handle: keyto.from(jwk, 'jwk').toString('pem', 'public_pkcs8')
          })
        }      
      }
    // 2.4. Otherwise...
    else {
      throw new KeyFormatNotSupportedError(format)
    }

    // 3-7. Create RsaHashedKeyAlgorithm
    let alg = new RSA_OAEP({
      name: 'RSA-OAEP',
      modulusLength: (new Buffer(jwk.n, 'base64').length / 2) * 8,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: normalizedHash
    })

    // 8. Set key.algorthm to alg
    key.algorithm = alg

    // 9. Return key
    return key
  }

  /**
   * exportKey
   *
   * @description
   *
   * @param {string} format
   * @param {CryptoKey} key
   *
   * @returns {*}
   */
  exportKey (format, key) {
    // 1. Setup resulting var
    let result

    // 2. Validate handle slot
    if (!key.handle) {
      throw new OperationError('Missing key material')
    }

    // 3.1. "spki" format
    if (format === 'spki') {
      throw new CurrentlyNotSupportedError(format,"jwk")
    }
    // 3.2. "pkcs8" format
    else if (format === 'pkcs8') {
      throw new CurrentlyNotSupportedError(format,"jwk")
    }
    // 2.3. "jwk" format
    else if (format === 'jwk') {
      // 2.3.1. Create new jwk
      let jwk = keyto.from(key.handle, 'pem').toJwk(key.type)

      // 2.3.2. Setting 'kty' value
      jwk.kty = "RSA"

      // 2.3.3. Determine alg from hash
      let hash = key.algorithm.hash.name

      // 2.3.3.1. Hash is "SHA-1"
      if (hash === 'SHA-1') {
        jwk.alg = 'RSA-OAEP'
      } 
      // 2.3.3.2. Hash is "SHA-256"
      else if (hash === 'SHA-256') {
        jwk.alg = 'RSA-OAEP-256'
      } 
      // 2.3.3.3. Hash is "SHA-384"
      else if (hash === 'SHA-384') {
        jwk.alg = 'RSA-OAEP-384'
      } 
      // 2.3.3.4. Hash is "SHA-512"
      else if (hash === 'SHA-512') {
        jwk.alg = 'RSA-OAEP-512'
      } 
      // 2.3.3.5. Hash is other value
      else {
        // TODO other applicable specifications
        throw new CurrentlyNotSupportedError(format,"SHA-1")
      }
      // 2.3.4-5. Assign corresponding field from JWA specification
      Object.assign(jwk, keyto.from(key.handle, 'pem').toJwk(key.type))

      // 2.3.6. Set "key_ops" field
      jwk.key_ops = key.usages

      // 2.3.7. Set "ext" field
      jwk.ext = key.extractable

      // 2.3.8. Set result to jwk object
      result = jwk
    }
    // 3.4. Otherwise bad format
    else {
      throw new KeyFormatNotSupportedError(format)
    }

    // 4. Result result
    return result
  }
}

/**
 * Export
 */
module.exports = RSA_OAEP