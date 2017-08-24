/**
 * Package dependencies
 */
const crypto = require('crypto')
const base64url = require('base64url') 
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
      // // 1. Ensure correct iv length
      // if (algorithm.iv.byteLength !== 16) {
      //   throw new OperationError('IV Length must be exactly 16 bytes')
      // }
      
      // // 2. Add padding to erronuous length text as described here:
      // // https://tools.ietf.org/html/rfc2315#section-10.3
      // let paddedPlaintext = data

      // // 3. Do the encryption
      // let cipherName
      // if (key.algorithm.name === 'RSA-OAEP' && [128,192,256].includes(key.algorithm.length)){
      //   cipherName = 'AES-' + key.algorithm.length + '-CBC'
      // } else {
      //   throw new DataError('Invalid RSA-OAEP and length pair.')
      // }
      // let cipher = crypto.createCipheriv(cipherName,key.handle,Buffer.from(algorithm.iv))
      // let ciphertext = cipher.update(Buffer.from(data))
      
      // // 4. Return result
      // return Uint8Array.from(Buffer.concat([ciphertext,cipher.final()])).buffer
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
      // // 1. Ensure correct iv length
      // if (algorithm.iv.byteLength !== 16){
      //   throw new OperationError('IV Length must be exactly 16 bytes')
      // }
      
      // // 2. Perform the decryption 
      // let cipherName
      // if (key.algorithm.name === 'RSA-OAEP' && [128,192,256].includes(key.algorithm.length)){
      //   cipherName = 'AES-' + key.algorithm.length + '-CBC'
      // } else {
      //   throw new DataError('Invalid RSA-OAEP and length pair.')
      // }
      // let decipher = crypto.createDecipheriv(cipherName,key.handle,Buffer.from(algorithm.iv))
      // let ciphertext = decipher.update(Buffer.from(data))
      // let plaintext = Array.from(Buffer.concat([ciphertext,decipher.final()]))

      // // 3-5. Text de-padding performed by crypto.decipher

      // // 6. Return resulting ArrayBuffer
      // return Uint8Array.from(plaintext).buffer
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
      let data, jwk, hash, normalizedHash
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
        let jwk = new JsonWebKey(keyData)

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
              throw new SyntaxError('Key usages can only include "encrypt" or "unwrapKey"')
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
          
          console.log("normalizedHash",normalizedHash)

          // 2.3.9.2. Validate hash member of normalizedAlgorithm
          if (!normalizedHash || normalizedHash.name !== this.hash.name) {
            throw new DataError("Unknown hash or mismatched hash name.")
          }
        }

        // TODO Continue here
      
      }
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
module.exports = RSA_OAEP

let rsa = new RSA_OAEP({name:"RSA-OAEP",hash:{name: "SHA-256"}})
let kp = rsa.generateKey(
  {
        name: "RSA-OAEP",
        modulusLength: 2048, //can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"]
  )
// console.log("kp",kp)

let imp = rsa.importKey(
  "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
    {   //this is an example jwk key, other key types are Uint8Array objects
        kty: "RSA",
        e: "AQAB",
        n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
        alg: "RSA-OAEP-256",
        ext: true,
    },
    {   //these are the algorithm options
        name: "RSA-OAEP",
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt"]
)