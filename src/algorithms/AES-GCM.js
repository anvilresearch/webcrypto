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
  KeyFormatNotSupportedError,
  CurrentlyNotSupportedError
} = require('../errors')

/**
 * AES-GCM
 */
class AES_GCM extends Algorithm {

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
     * Encrypts an AES-GCM digital signature
     *
     * @param {AesKeyAlgorithm} algorithm
     * @param {CryptoKey} key
     * @param {BufferSource} data
     *
     * @returns {Array}
     */
    encrypt (algorithm, key, data) {
      // 1. Ensure correct data length
      if (data.byteLength === undefined || data.byteLength > 549755813632) { // 2^39-256
        throw new OperationError('Data must have a length less than 549755813632.')
      }

      // 2. Ensure correct iv length
      if (algorithm.iv.byteLength === undefined || algorithm.iv.byteLength > 18446744073709551615) { // 2^64-1
        throw new OperationError('IV Length must be less than 18446744073709551615 in length.')
      }

      // 3. Ensure correct additionalData
      if (algorithm.additionalData !== undefined
          && (algorithm.additionalData.length === undefined
          || algorithm.additionalData.length > 18446744073709551615)) { // 2^64-1
        throw new OperationError('AdditionalData must be less than 18446744073709551615 in length.')
      }

      // 4. Verify tagLength
      // Note: node only support tag length up to 128, so there is some discrepancy between
      // this, and the spec outline: https://www.w3.org/TR/WebCryptoAPI/#aes-gcm
      let tagLength
      if (algorithm.tagLength === undefined){
        tagLength = 128
      } else if ([32,64,96,104,112,120].includes(algorithm.tagLength)) {
        throw new CurrentlyNotSupportedError('Node currently only supports 128 tagLength.', '128')
      } else if (algorithm.tagLength !== 128) {
        throw new OperationError('TagLength is an invalid size.')
      } else {
        tagLength = algorithm.tagLength
      }

      // 5. Assign additionalData
      let additionalData
      if (algorithm.additionalData !== undefined){
        additionalData = Buffer.from(algorithm.additionalData)
      } else {
        additionalData = Buffer.from('')
      }

      // 6. Do the encryption
      let cipherName
      if (key.algorithm.name === 'AES-GCM' && [128,192,256].includes(key.algorithm.length)){
        cipherName = 'aes-' + key.algorithm.length + '-gcm'
      } else {
        throw new DataError('Invalid AES-GCM and length pair.')
      }
      let cipher = crypto.createCipheriv(cipherName,key.handle,Buffer.from(algorithm.iv))
      cipher.setAAD(additionalData)
      let ciphertext = cipher.update(Buffer.from(data))
      ciphertext = Buffer.concat([ciphertext,cipher.final()])

      // 7. Concat C and T
      let authTag = cipher.getAuthTag()
      ciphertext = Buffer.concat([ciphertext,authTag])

      // 8. Return result
      return Uint8Array.from(ciphertext).buffer
    }

    /**
     * decrypt
     *
     * @description
     * Decrypts an AES-GCM digital signature
     *
     * @param {AesKeyAlgorithm} algorithm
     * @param {CryptoKey} key
     * @param {BufferSource} data
     *
     * @returns {Array}
     */
    decrypt (algorithm, key, data) {
      // 1. Verify tagLength
      let tagLength
      if (algorithm.tagLength === undefined){
        tagLength = 128
      } else if ([32,64,96,104,112,120].includes(algorithm.tagLength)) {
        throw new CurrentlyNotSupportedError('Node currently only supports 128 tagLength.', '128')
      } else if (algorithm.tagLength !== 128) {
        throw new OperationError('TagLength is an invalid size.')
      } else {
        tagLength = algorithm.tagLength
      }

      // 2. Verify data length
      if ((data.length * 8) < tagLength){
        throw new OperationError('Data length cannot be less than tagLength.')
      }

      // 3. Ensure correct iv length
      if (algorithm.iv.byteLength === undefined || algorithm.iv.byteLength > 18446744073709551615) { // 2^64-1
        throw new OperationError('IV Length must be less than 18446744073709551615 in length.')
      }

      // 4 & 7. Ensure correct additionalData
      let additionalData
      if (algorithm.additionalData !== undefined){
           if (algorithm.additionalData.length === undefined
              || algorithm.additionalData.length > 18446744073709551615) { // 2^64-1
            throw new OperationError('AdditionalData must be less than 18446744073709551615 in length.')
          } else {
            additionalData = Buffer.from(algorithm.additionalData)
          }
      } else{
        additionalData = Buffer.from('')
      }

      // 5. Get the AuthTag
      data = Buffer.from(data)
      let tagLengthBytes = tagLength/8
      let tag = data.slice(-tagLengthBytes)

      // 6. Get the actualCiphertext
      let actualCiphertext = data.slice(0,-tagLengthBytes)

      // 8. Perform the decryption
      let cipherName
      if (key.algorithm.name === 'AES-GCM' && [128,192,256].includes(key.algorithm.length)){
        cipherName = 'aes-' + key.algorithm.length + '-gcm'
      } else {
        throw new DataError('Invalid AES-GCM and length pair.')
      }
      let decipher = crypto.createDecipheriv(cipherName,key.handle,Buffer.from(algorithm.iv))
      decipher.setAAD(additionalData)
      decipher.setAuthTag(tag)
      let plaintext = decipher.update(Buffer.from(actualCiphertext))
      plaintext = Buffer.concat([plaintext,decipher.final()])

      // 9. Return resulting ArrayBuffer
      return Uint8Array.from(plaintext).buffer
    }

    /**
     * generateKey
     *
     * @description
     * Generate an AES-GCM key pair
     *
     * @param {AesGcmParams} params
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
      let algorithm = new AES_GCM(params)

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
          if (jwk.alg && jwk.alg !== 'A128GCM'){
            throw new DataError('Algorithm "A128GCM" must be 128 bits in length')
          }
        } else if (data.length === 24) {
          if (jwk.alg && jwk.alg !== 'A192GCM'){
            throw new DataError('Algorithm "A192GCM" must be 192 bits in length')
          }
        } else if (data.length === 32) {
          if (jwk.alg && jwk.alg !== 'A256GCM'){
            throw new DataError('Algorithm "A256GCM" must be 256 bits in length')
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
      let aesAlgorithm = new AES_GCM(
        { name: 'AES-GCM',
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
            jwk.alg = 'A128GCM'
        } else if (data.length === 24) {
            jwk.alg = 'A192GCM'
        } else if (data.length === 32) {
            jwk.alg = 'A256GCM'
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
module.exports = AES_GCM
