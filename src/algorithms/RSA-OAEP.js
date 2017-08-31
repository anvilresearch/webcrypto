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
      
      // 3-5. Attempt to encrypt using crypto lib
      try {
        data = Buffer.from(data)
        result = crypto.publicEncrypt({key: key.handle, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING},data)
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
              usages: ['sign'],
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
            usages: ['verify'],
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


/*
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

let imp_priv = rsa.importKey(
  "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
{"alg":"RSA-OAEP-256","d":"mp3ziE80B79bku3FTVEDmvB2thL3AiMnzcU-Fx83HuJqbzMSeMGie75GiDjLDH_Q8ty3VRXUTQdoOoTcDatkhkqxY34omugejZ9jmfpwBaGgygYbYMdScYj-Nq6NgdN5iidjieEeT1hcy8htVqWJTawcLhyZ-TCRIMCvPHzGlrL63B4jK7nZkDOYnugXUs342DpkkocrGwUhMLDnjn4pliMtHa8YAD22GjOwiSMQnZipLkULGlT-vNc5yReovMeZ8YEeminOSDsnvsr2G8mHbC-9Py8RKbsR0HVz7R4Mc11iiG4b22WaruMfYDmfNhT_xbnAVqhwuef2KaBkAL8IAQ","dp":"nDnoGbRIIhJNN-1Ahe6NjGtYQSp9pSO7W9Zj_49sX6McVXK11Y3dNBzi8ipZNS5qjfRBfYXpP-jqyUJWiOG336XWrjoLCmn7OGV8XlGO5VX_a8Rq1soWv00ZyW5BjqsDN8LuWfysyTjQ8kVbagAIkopk_KeO1Monv-w6RIIyYDs","dq":"jg5PYhX9Fhfrjzcvk2JEDPMWvYhYsKip5CaWj7bON4emqQr2DawH9E5sR_1LXI9soBji2x65C-iXodgUKswIVuGKgOTX3DH9fKsjduwsoE5Kfui2eHO6mQrhcTyCtHu2vOiRV58qln5y_RnCaRTzNBqpfVpOMUBFr5XAx1QRlgE","e":"AQAB","ext":true,"key_ops":["decrypt"],"kty":"RSA","n":"q5vBmLlVYveWFgeqhKhbwWEEbuQRJ-VEb1JbEEFEWm1LPF-YaqKlSngVq7c_dZcJRatYw2U2gBpQIKjMkzrMXQSlbuG0Skumv8qpb3_aQ7WqhUjTC4-1VG9VWuROUTu9Zalra7aBlIJ2kRHVDsDFgKpFIlcXTD7kOV_mdeg4aSOrV-7LH4vQOPbb42Y3boBjTPX4RuqimuwAt91zO8czRu0veVJRnWLynQ82dil3SRla88rIkXFYm9pVCWBgsczcHOyqAdhPVD8tP62aisks9T3vs1OMDo680j454yO3hOsx6szdiVf1Q9YDMTxzkTZtG3ys6U1yNd4sAwRJ3-hK_w","p":"1kpspcHYpxjUnhMF-ETQvgVfUPVC9PxoTqozkK3VrW4v6gxqf0A9vBqXkqOvAYOpKNOz0ZizrJ6h--xYgpCuStxHq0L_dhcqgc6HPuLweNEottXqiBZnmVx9hPhDUqk0gdi8trlenc0_-Zqq8vCI1fNBkk2c_ydCzzGfGV9krH8","q":"zQKUJl0fhixAK316nS16dbOUTxjclL3VLxAMNkiNJeSdfKNXM3I-MTz0G5BbEFGW35U5XW4KYy4iBI2ka_db2-MOBEfYf_Q9JUb2eS1Gq-5KzVmpu9LrQlkJsl_bHYIDhWtNJD1BffFObFpIq1MSkFjrjEykUBX08zvqPwePIYE","qi":"OuvFJGnC_4GonCVZl9cP89p3KhPIbqzCuOcqIp_7Bz3ElE7ZfFvgy1XYmyo5tr0XKowGH9eEh9Ymd6lfxP5gqxgVvfuMjCJhdBLAIKFI9ggyzbaCl0PNvSpcZYNLYDjPuxOgSKjxrd9HgX-zSKNah0nGu4OxEYlhzl7KWX5bV6c"},
    {   //these are the algorithm options
        name: "RSA-OAEP",
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["decrypt"]
  )

let imp_pub = rsa.importKey(
  "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
{"alg":"RSA-OAEP-256","e":"AQAB","ext":true,"key_ops":["encrypt"],"kty":"RSA","n":"q5vBmLlVYveWFgeqhKhbwWEEbuQRJ-VEb1JbEEFEWm1LPF-YaqKlSngVq7c_dZcJRatYw2U2gBpQIKjMkzrMXQSlbuG0Skumv8qpb3_aQ7WqhUjTC4-1VG9VWuROUTu9Zalra7aBlIJ2kRHVDsDFgKpFIlcXTD7kOV_mdeg4aSOrV-7LH4vQOPbb42Y3boBjTPX4RuqimuwAt91zO8czRu0veVJRnWLynQ82dil3SRla88rIkXFYm9pVCWBgsczcHOyqAdhPVD8tP62aisks9T3vs1OMDo680j454yO3hOsx6szdiVf1Q9YDMTxzkTZtG3ys6U1yNd4sAwRJ3-hK_w"},
    {   //these are the algorithm options
        name: "RSA-OAEP",
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt"]
  )


// console.log("imp",imp)

// let exp = rsa.exportKey(
//   "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
//   imp //can be a publicKey or privateKey, as long as extractable was true
// )
// console.log("exp",exp)

// console.log(rsa.exportKey("jwk",kp.privateKey))


let enc = rsa.encrypt(
  {
        name: "RSA-OAEP",
        //label: Uint8Array([...]) //optional
  },
  imp_pub, //from generateKey or importKey above
  new TextEncoder().encode("helloworld")
)
console.log(JSON.stringify(Array.from(new Uint8Array(enc))))

// console.log(imp.handle)

// let webenc = new Uint8Array([76,104,42,180,203,222,7,52,186,119,142,78,16,83,159,204,66,26,79,138,1,178,37,190,6,212,9,43,216,235,85,30,47,24,187,88,110,26,15,93,83,135,50,71,142,252,121,193,59,146,48,41,236,88,30,55,113,206,116,10,229,87,131,123,233,118,234,52,164,225,253,154,91,184,210,203,35,50,246,55,88,184,83,20,31,238,174,70,178,5,104,143,249,212,57,178,68,79,92,164,107,203,82,1,3,149,215,241,227,34,82,116,0,77,177,182,79,236,215,230,205,246,27,166,90,159,132,219,82,212,108,31,255,203,9,142,227,30,241,252,233,136,168,166,210,7,122,40,78,21,86,203,15,52,125,156,82,93,204,140,124,63,57,249,225,100,64,199,177,3,171,240,71,82,87,208,18,127,81,22,73,27,168,177,119,93,73,76,102,60,242,247,76,122,104,79,102,154,133,193,143,119,61,125,84,245,138,161,115,162,42,175,227,199,74,185,231,92,45,246,170,211,172,161,190,193,239,49,131,133,243,72,8,85,55,6,171,184,145,8,42,138,250,133,219,243,201,78,72,215,176,149,241,42,80,115])
// // console.log("webenc",webenc)
let dec = rsa.decrypt(
   {
        name: "RSA-OAEP",
        //label: Uint8Array([...]) //optional
    },
    imp_priv, //from generateKey or importKey above
    enc //ArrayBuffer of the data
)
// console.log("dec",new TextDecoder().decode(dec))

*/
