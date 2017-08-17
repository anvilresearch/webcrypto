/**
 * Package dependencies
 */
const crypto = require('crypto')
const base64url = require('base64url') 
const {TextEncoder, TextDecoder} = require('text-encoding')

/**
 * Local dependencies
 */
const KeyAlgorithm = require('../dictionaries/KeyAlgorithm')
const AesKeyAlgorithm = require('../dictionaries/AesKeyAlgorithm') 
const Algorithm = require ('../algorithms/Algorithm')
const CryptoKey = require('../keys/CryptoKey')
const JsonWebKey = require('../keys/JsonWebKey')


/**
 * Errors
 */
const {
  DataError,
  OperationError,
  InvalidAccessError,
  KeyFormatNotSupportedError
} = require('../errors')

/**
 * AES-CBC
 */
class AES_CBC extends Algorithm {

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
     * Encrypts an AES-CBC digital signature
     *
     * @param {AesKeyAlgorithm} algorithm
     * @param {CryptoKey} key
     * @param {BufferSource} data
     *
     * @returns {Array}
     */
    encrypt (algorithm, key, data) {
      // 1. Ensure correct iv length
      if (algorithm.iv.byteLength !== 16) {
        throw new OperationError('IV Length must be exactly 16 bytes')
      }
      
      // 2. Add padding to erronuous length text as described here:
      // https://tools.ietf.org/html/rfc2315#section-10.3
      let paddedPlaintext = data

      // 3. Do the encryption
      let cipherName
      if (key.algorithm.name === 'AES-CBC' && [128,192,256].includes(key.algorithm.length)){
        cipherName = 'AES-' + key.algorithm.length + '-CBC'
      } else {
        throw new DataError('Invalid AES-CBC and length pair.')
      }
      let cipher = crypto.createCipheriv(cipherName,key.handle,Buffer.from(algorithm.iv))
      let ciphertext = cipher.update(Buffer.from(data))
      
      // 4. Return result
      return Uint8Array.from(Buffer.concat([ciphertext,cipher.final()])).buffer
    }

    /**
     * decrypt
     *
     * @description
     * Decrypts an AES-CBC digital signature
     *
     * @param {AesKeyAlgorithm} algorithm
     * @param {CryptoKey} key
     * @param {BufferSource} data
     *
     * @returns {Array}
     */
    decrypt (algorithm, key, data) {
      // 1. Ensure correct iv length
      if (algorithm.iv.byteLength !== 16){
        throw new OperationError('IV Length must be exactly 16 bytes')
      }
      
      // 2. Perform the decryption 
      let cipherName
      if (key.algorithm.name === 'AES-CBC' && [128,192,256].includes(key.algorithm.length)){
        cipherName = 'AES-' + key.algorithm.length + '-CBC'
      } else {
        throw new DataError('Invalid AES-CBC and length pair.')
      }
      let decipher = crypto.createDecipheriv(cipherName,key.handle,Buffer.from(algorithm.iv))
      let ciphertext = decipher.update(Buffer.from(data))
      let plaintext = Array.from(Buffer.concat([ciphertext,decipher.final()]))

      // 3-5. Text de-padding performed by crypto.decipher

      // 6. Return resulting ArrayBuffer
      return Uint8Array.from(plaintext).buffer
    }

    /**
     * generateKey
     *
     * @description
     * Generate an AES-CBC key pair
     *
     * @param {AesCbcParams} params
     * @returns {CryptoKeyPair}
     */
    generateKey (params, extractable, usages) {
      // 1. Validate usages
      usages.forEach(usage => {
        if (usage !== 'encrypt' && usage !== 'decrypt' && usage !== 'wrapKey' && usage !== 'unwrapKey') {
          throw new SyntaxError('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
        }
      })
      
      // 2. Validate length
      if (![128,192,256].includes(params.length)) {
          throw new OperationError('Member length must be 128, 192, or 256.')
      }

      // 3. Generate AES Key
      let symmetricKey
      try {
        symmetricKey = crypto.randomBytes(params.length/8)
      // 4. Validate key generation
      } catch (error) {
        throw new OperationError(error.message)
      }
      
      // 6. Set new AesKeyAlgorithm
      let algorithm = new AES_CBC(params)

      // 5. Define new CryptoKey names key
      let key = new CryptoKey({
        type: 'secret',
        algorithm,
        extractable,
        usages,
        handle: symmetricKey
      })

      // 12. Return Key
      return key
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
      let data, jwk
      
      // 1. Validate keyUsages
      keyUsages.forEach(usage => {
        if (usage !== 'encrypt' 
         && usage !== 'decrypt' 
         && usage !== 'wrapKey' 
         && usage !== 'unwrapKey') {
           throw new SyntaxError('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
        }
      })

      // 2.1 "raw" format
      if (format === 'raw'){
          // 2.1.1 Let data be the octet string contained in keyData
          data = Buffer.from(keyData)

          // 2.1.2 Ensure data length is 128, 192 or 256
          if (![16,24,32].includes(data.length)){
            throw new DataError('Length of data bits must be 128, 192 or 256.')
          }
      }

      // 2.2 "jwk" format
      else if (format === 'jwk'){
        // 2.2.1 Ensure data is JsonWebKey dictionary 
        if (typeof keyData === 'object' && !Array.isArray(keyData)){
          jwk = new JsonWebKey(keyData)
        } else {
          throw new DataError('Invalid jwk format')
        }
        
        // 2.2.2 Validate "kty" field heuristic
        if (jwk.kty !== "oct"){
          throw new DataError('kty property must be "oct"')
        }
        
        // 2.2.3 Ensure jwk meets these requirements: 
        // https://tools.ietf.org/html/rfc7518#section-6.4 
        if (!jwk.k){
          throw new DataError('k property must not be empty')
        }
        
        // 2.2.4 Assign data 
        data = base64url.toBuffer(jwk.k)
        
        // 2.2.5 Validate data lengths
        if (data.length === 16) {
          if (jwk.alg && jwk.alg !== 'A128CBC'){
            throw new DataError('Algorithm "A128CBC" must be 128 bits in length')
          }
        } else if (data.length === 24) {
          if (jwk.alg && jwk.alg !== 'A192CBC'){
            throw new DataError('Algorithm "A192CBC" must be 192 bits in length')
          }
        } else if (data.length === 32) {
          if (jwk.alg && jwk.alg !== 'A256CBC'){
            throw new DataError('Algorithm "A256CBC" must be 256 bits in length')
          }
        } else {
          throw new DataError('Algorithm and data length mismatch')
        }
       
        // 2.2.6 Validate "use" field
        if (keyUsages && jwk.use && jwk.use !== 'enc'){
          throw new DataError('Key use must be "enc"')
        }
        
        // 2.2.7 Validate "key_ops" field
        if (jwk.key_ops){
          jwk.key_ops.forEach(op => {
            if (op !== 'encrypt' 
             && op !== 'decrypt' 
             && op !== 'wrapKey' 
             && op !== 'unwrapKey') {
              throw new DataError('Key operation can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
            }
          })
        }
        
        // 2.2.8 validate "ext" field
        if (jwk.ext === false && extractable === true){
          throw new DataError('Cannot be extractable when "ext" is set to false')
        }
      }
      
      // 2.3 Otherwise...
      else {
        throw new KeyFormatNotSupportedError(format)
      }
      
      // 3. Generate new key
      let key = new CryptoKey({
            type: 'secret',
            extractable,
            usages: keyUsages,
            handle: data 
        })
      
      // 4-6. Generate algorithm
      let aesAlgorithm = new AES_CBC(
        { name: 'AES-CBC',
          length: data.length * 8
        })
      
      // 7. Set algorithm to internal algorithm property of key
      key.algorithm = aesAlgorithm
      
      // 8. Return key
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
      let result, data

      // 1. Validate handle slot
      if (!key.handle) {
        throw new OperationError('Missing key material')
      }
      
      // 2.1 "raw" format
      if (format === 'raw'){
          // 2.1.1 Let data be the raw octets of the key
          data = key.handle 
          // 2.1.2 Let result be containing data
          result = Buffer.from(data) 
      }
      
      // 2.2 "jwk" format
      else if (format === 'jwk'){
        // 2.2.1 Validate JsonWebKey
        let jwk = new JsonWebKey()
        
        // 2.2.2 Set kty property 
        jwk.kty = 'oct'
        
        // 2.2.3 Set k property
        jwk.k = base64url(key.handle)
        data = key.handle 
        
        // 2.2.4 Validate length 
        if (data.length === 16) {
            jwk.alg = 'A128CBC'
        } else if (data.length === 24) {
            jwk.alg = 'A192CBC'
        } else if (data.length === 32) {
            jwk.alg = 'A256CBC'
        }
        // 2.2.5 Set keyops property 
        jwk.key_ops = key.usages 

        // 2.2.6 Set ext property 
        jwk.ext = key.extractable
        
        // 2.2.7 Set result to the result of converting jwk to an ECMAScript object
        result = jwk
      }
      
      // 2.3 Otherwise...
      else {
        throw new KeyFormatNotSupportedError(format)
      }

      // 3. Return result
      return result
  }
}

/**
 * Export
 */
module.exports = AES_CBC