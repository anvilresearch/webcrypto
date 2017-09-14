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
      if  (key.algorithm.hash.name !== 'SHA-1'){
        throw new CurrentlyNotSupportedError(format,'SHA-1')
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
      if  (key.algorithm.hash.name !== 'SHA-1'){
        throw new CurrentlyNotSupportedError(format,'SHA-1')
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

let rsa = new RSA_OAEP({name:"RSA-OAEP",hash:{name: "SHA-1"}})
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
{"alg":"RSA-OAEP","d":"OONqS6vhPhdw_a5PZ7e0dIQNk8k2x8S_4wdsGcw5LVKRnsm07IDSb6JgsSBrM16tpthXbdAqFp5Lbcuc8clkRN0RUlH5aBCuFHQDRit5c7hvhDKbR5Tjuu8i6ZfGNCXzU-oFeaPBAP6aiclmJZO0wyRvTYNtvRcjELix11MWfhxulAiMayEXG47AvLycBOim1hui28R3WYwH8Yfc7-BoXITjy8V9ViMRCU2cVnPtXQYnz27KAYFmV7wcAhWgB5T97abSVWwgk_ZIhjfieNjOLuG2veVuDOni-mzMjg_5DwWAtMkx2G9fysSaHJiarcb071BEIurD5uZ3EPKxSksE4Q","dp":"YU25IwbEb_BVTCYkd01iVZQBCPrkHMEUt0SDkWuFHmOiIfaDgbnIy9euDffwNglJMTDuxmKsXqiOnnJ4Q4Vjxm3v4gKNGsvckhfTxbX9Y_XIyxXTASRCBUDpyGQ2JllgUT3IAMBC4H7sb6c-fuwrGqQurNGSIcrTng3v-jHoedE","dq":"csjKDq30kz-zoTs9e4YMuZ_h4NmZy9b-X3-oLHsMmA_TU4D2_bWqVaN4j8zURKOutrkepnYzOgacN2oR9dBj_Z8PLyPIgM03EuuFU5InkzAQ-DnUzJQU6gH1RgaWiG2lswLDEHQc3-d2fohveFxM90zAjP0Dhe-BTbt07GpE9sU","e":"AQAB","ext":true,"key_ops":["decrypt"],"kty":"RSA","n":"q6kM0z9Faa2BHYSakuzZKirz3o7dNG83nq3Yw5KC1FOUkQStDtYz8EMkYV99WfHMCaRA_q_WBjRVnweQawFtR4zwNcmEhU-fUEIZCZ17ArKoNOy45Ep8NVuYJG3-OyYHuwnz5xLIvW9GVk2UqAJKaLSatuT2utU6JKeLu-4C0cb4eYUGT_RT-qsTF_NSWyyzdHrZzp9FX7ly-UTZw3inyjZYp5Ps1Ka5HzByzCTHhs_tatzLwG0FgjS7msPmwzE9RZFr1-J9exvIqhCmhvj5LSIdFmm5MEXC_b47fYCqSCE81bBofD2Ee0k72qOA-JfKNhrNXoLzuR7_1Ig1xJ8Ahw","p":"0ca0ebRJqK1jhNd9e0dRMrl5_cJhxMZAH3jyHNgC-vqSmFjobkNOwvUxzyf-kXLvrNCuJbkQqQHN87saSGunAHpDdFPV1lsymnemLJjsfMNy1Qf5yw6r277gz1mVDcgfJbP_4vcps0v-VmIgaBwtkPNJVTv-PjVAY3PAXpqwSjE","q":"0XxDaEvgA5ECPsFMiqsuhWajiv8I-nzi3EUeq25Za0PR_9S7HF0TXxk84-EPmCU1WxeilFhL96--g4fmypBjVaszL-nP7Thq4MBBPM5cviPuUoQXmYVOtD1q8rmVmc0HbtuzM5fmBbSfGn9sLhu6DE1ymlabHjvn-FWuIWLcEDc","qi":"W-VEZ0hgjSA4qFjAkfaBK58NAV9rY45MP4n2MauCSoR9uqjkrYJQm74774G8tILIsw72eKejfObh6mmZUSPvOKRn-femd7KCH6x54sdNExvP3kAbXDVH9NhxgEjNjpsPjoyKXJGGZrAwPV6sncgea-h79gRXKRFYhXSK2cIk6Xk"},
    {   //these are the algorithm options
        name: "RSA-OAEP",
        hash: {name: "SHA-1"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["decrypt"]
  )

let imp_pub = rsa.importKey(
  "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
{"alg":"RSA-OAEP","e":"AQAB","ext":true,"key_ops":["encrypt"],"kty":"RSA","n":"q6kM0z9Faa2BHYSakuzZKirz3o7dNG83nq3Yw5KC1FOUkQStDtYz8EMkYV99WfHMCaRA_q_WBjRVnweQawFtR4zwNcmEhU-fUEIZCZ17ArKoNOy45Ep8NVuYJG3-OyYHuwnz5xLIvW9GVk2UqAJKaLSatuT2utU6JKeLu-4C0cb4eYUGT_RT-qsTF_NSWyyzdHrZzp9FX7ly-UTZw3inyjZYp5Ps1Ka5HzByzCTHhs_tatzLwG0FgjS7msPmwzE9RZFr1-J9exvIqhCmhvj5LSIdFmm5MEXC_b47fYCqSCE81bBofD2Ee0k72qOA-JfKNhrNXoLzuR7_1Ig1xJ8Ahw"},
    {   //these are the algorithm options
        name: "RSA-OAEP",
        hash: {name: "SHA-1"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt"]
  )


// console.log("imp_priv",imp_priv)
// console.log("imp_pub",imp_pub)

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
// console.log(JSON.stringify(Array.from(new Uint8Array(enc))))

// console.log(imp.handle)

let webenc = new Uint8Array([8,163,209,236,43,219,90,197,157,58,25,1,82,177,77,182,136,49,133,104,3,1,232,190,162,139,172,32,148,24,73,228,152,133,1,244,183,146,116,122,56,149,54,191,6,186,237,12,118,53,208,240,128,205,112,239,94,91,74,73,13,127,108,100,247,125,59,158,29,247,22,198,28,175,154,103,142,187,57,53,55,14,158,234,217,60,96,134,224,135,220,119,14,239,189,182,94,106,244,241,163,216,244,104,141,199,5,172,29,207,27,238,169,247,178,215,228,183,16,214,190,215,65,176,77,189,32,38,236,217,235,120,213,150,26,131,189,164,33,209,177,234,178,200,213,119,153,22,214,104,85,115,208,108,232,170,47,35,2,73,25,188,210,78,86,20,80,201,151,227,130,227,29,98,138,31,36,128,55,67,200,118,45,198,128,230,101,90,100,47,252,91,145,238,137,110,27,239,245,42,5,131,168,147,209,211,231,131,160,129,92,240,53,221,224,39,226,71,69,105,136,67,40,131,25,62,78,53,140,19,193,218,20,9,95,47,243,241,53,59,12,52,211,149,223,149,248,73,103,124,24,214,203,176,202,231])
// // console.log("webenc",webenc)
let dec = rsa.decrypt(
   {
        name: "RSA-OAEP",
        //label: Uint8Array([...]) //optional
    },
    imp_priv, //from generateKey or importKey above
    webenc //ArrayBuffer of the data
)
// console.log("dec",new TextDecoder().decode(dec))
*/


