/**
 * Package dependencies
 */
const crypto = require('crypto')
const {spawnSync} = require('child_process')

const AesKeyAlgorithm = require('../dictionaries/AesKeyAlgorithm') 
const Algorithm = require ('../algorithms/Algorithm')
const CryptoKey = require('../keys/CryptoKey')

// https://github.com/diafygi/webcrypto-examples
// https://tools.ietf.org/html/rfc7518#section-5.2.3
// https://www.w3.org/TR/WebCryptoAPI/#aes-cbc 

var ivbytes = crypto.randomBytes(16)

  /**
   * generateKey
   *
   * @description
   * Generate an AES-CBC key pair
   *
   * @param {AesCbcParams} params
   * @returns {CryptoKeyPair}
   */
function generateKey (params,extractable,usages) {
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
      symmetricKey = crypto.randomBytes(params.length/4)

    // 4. Validate key generation
    } catch (error) {
      throw new OperationError(error.message)
    }
    
    // 6. Set new AesKeyAlgorithm
    let algorithm = new AesKeyAlgorithm(params)

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
function importKey (format, keyData, algorithm, extractable, keyUsages) {
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
      // TODO Double check with Christian
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
      data = Buffer.from(jwk.k)
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
      // TODO recheck this
      if (jwk.key_ops){
        key_ops.forEach(op => {
          if (op !== 'encrypt' 
           && op !== 'decrypt' 
           && op !== 'wrapKey' 
           && op !== 'unwrapKey') {
            throw new DataError('Key operation can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
          }
        })
      }
      // 2.2.8 validate "ext" field
      if (jwk.ext && jwk.ext === false && extractable === true ){
        throw new DataError('Cannot be extractable when "ext" is set to false')
      }
    }
    // 2.3 Othwerwise...
    else {
      throw new KeyFormatNotSupportedError(format)
    }

    // 4. Generate algorithm
    let aesAlgorithm = new AesKeyAlgorithm()

    // 3. Generate new key
    let key = new CryptoKey({
      // TODO HERE
      })

}

let result = generateKey(
    {
        name: "AES-CBC",
        length: 128, //can be  128, 192, or 256
    },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] //can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
)

console.log(result)
console.log(result.handle.length)