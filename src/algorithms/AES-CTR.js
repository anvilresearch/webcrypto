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
 * AES-CTR
 */
class AES_CTR extends Algorithm {

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
     * Encrypts an AES-CTR digital signature
     *
     * @param {AesKeyAlgorithm} algorithm
     * @param {CryptoKey} key
     * @param {BufferSource} data
     *
     * @returns {Array}
     */
    encrypt (algorithm, key, data) {
      // 1. Ensure correct counter length
      if (algorithm.counter === undefined || algorithm.counter.byteLength !== 16){
        throw new OperationError('Counter must be exactly 16 bytes')
      }
      
      // 2. Ensure correct length size
      if (algorithm.length === undefined || algorithm.length === 0 || algorithm.length > 128){
        throw new OperationError('Length must be non zero and less than or equal to 128')
      }

      // 3. Do the encryption
      let cipherName
      if (key.algorithm.name === 'AES-CTR' && [128,192,256].includes(key.algorithm.length)){
        cipherName = 'AES-' + key.algorithm.length + '-CTR'
      } else {
        throw new DataError('Invalid AES-CTR and length pair.')
      }
      let cipher = crypto.createCipheriv(cipherName,key.handle,Buffer.from(algorithm.counter))
      
      // 4. Return result
      return Uint8Array.from(Buffer.concat([cipher.update(data),cipher.final()])).buffer
    }

    /**
     * decrypt
     *
     * @description
     * Decrypts an AES-CTR digital signature
     *
     * @param {AesKeyAlgorithm} algorithm
     * @param {CryptoKey} key
     * @param {BufferSource} data
     *
     * @returns {Array}
     */
    decrypt (algorithm, key, data) {
      // 1. Ensure correct counter length
      if (algorithm.counter === undefined || algorithm.counter.byteLength !== 16) {
        throw new OperationError('Counter must be exactly 16 bytes')
      }
      
      // 2. Ensure correct length size
      if (algorithm.length === undefined || algorithm.length === 0 || algorithm.length > 128){
        throw new OperationError('Length must be non zero and less than or equal to 128')
      }
      
      // 3. Perform the decryption 
      let cipherName
      if (key.algorithm.name === 'AES-CTR' && [128,192,256].includes(key.algorithm.length)){
        cipherName = 'AES-' + key.algorithm.length + '-CTR'
      } else {
        throw new DataError('Invalid AES-CTR and length pair.')
      }
      let decipher = crypto.createDecipheriv(cipherName,key.handle,algorithm.counter)
      let plaintext = Array.from(Buffer.concat([decipher.update(Buffer.from(data)),decipher.final()]))

      // 4. Return resulting ArrayBuffer
      return Uint8Array.from(plaintext).buffer
    }

    /**
     * generateKey
     *
     * @description
     * Generate an AES-CTR key pair
     *
     * @param {AesCtrParams} params
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
      
      // Set new AesKeyAlgorithm
      let algorithm = new AES_CTR(params)

      // 5-11. Define new CryptoKey names key
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
          if (jwk.alg && jwk.alg !== 'A128CTR'){
            throw new DataError('Algorithm "A128CTR" must be 128 bits in length')
          }
        } else if (data.length === 24) {
          if (jwk.alg && jwk.alg !== 'A192CTR'){
            throw new DataError('Algorithm "A192CTR" must be 192 bits in length')
          }
        } else if (data.length === 32) {
          if (jwk.alg && jwk.alg !== 'A256CTR'){
            throw new DataError('Algorithm "A256CTR" must be 256 bits in length')
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
      let aesAlgorithm = new AES_CTR({ 
          name: 'AES-CTR',
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
        let jwk = new JsonWebKey(key)
        
        // 2.2.2 Set kty property 
        jwk.kty = 'oct'
        
        // 2.2.3 Set k property
        jwk.k = base64url(key.handle)
        data = key.handle 
        
        // 2.2.4 Validate length 
        if (data.length === 16) {
            jwk.alg = 'A128CTR'
        } else if (data.length === 24) {
            jwk.alg = 'A192CTR'
        } else if (data.length === 32) {
            jwk.alg = 'A256CTR'
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
module.exports = AES_CTR

