/**
 * Package dependencies
 */
const base64url = require('base64url')
const crypto = require('crypto')
const {spawnSync} = require('child_process')
const {TextEncoder, TextDecoder} = require('text-encoding')
const keyto = require('@trust/keyto')
const elEdDSA = require('elliptic').eddsa;
const elliptic = require('elliptic')

/**
 * Local dependencies
 */
const Algorithm = require ('../algorithms/Algorithm')
const CryptoKey = require('../keys/CryptoKey')
const CryptoKeyPair = require('../keys/CryptoKeyPair')
const JsonWebKey = require('../keys/JsonWebKey')
const KeyAlgorithm = require('../dictionaries/KeyAlgorithm')
const EcKeyAlgorithm = require('../dictionaries/EcKeyAlgorithm')


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
 * EDDSA
 */
class EDDSA extends Algorithm {

  /**
   * dictionaries
   */
  static get dictionaries () {
    return [
      KeyAlgorithm,
      EcKeyAlgorithm
    ]
  }

  /**
   * members
   */
  static get members () {
    return {
      name: String
    }
  }


  /**
   * sign
   *
   * @description
   * Create a digital signature
   *
   * @param {CryptoKey} key
   * @param {BufferSource} data
   *
   * @returns {ArrayBuffer}
   */
  sign (key, data) {
    let result
    // Ensure the key is a private type only
    if (key.type !== 'private'){
      throw new InvalidAccessError('Signing requires a private key')
    }

    // Ensure data is hex string, array or Buffer
    if (!Array.isArray(data) && !Buffer.isBuffer(data) && typeof data !== 'string'){
      throw new DataError('Data must be an Array, Buffer or hex string')
    }

    // Ensure key.handle is hex string, array or Buffer
    if (!Array.isArray(key.handle) && !Buffer.isBuffer(key.handle) && typeof key.handle !== 'string' ){
      throw DataError('Key handle must be an Array, Buffer or hex string')
    }

    try {
      // Create curve via elliptic
      let ec = new elEdDSA('ed25519')
      
      // Generate keypair from private key
      let ecKey 
      if (typeof key.handle === 'string'){
        ecKey = ec.keyFromSecret(key.handle, 'hex')
      } else { 
        ecKey = ec.keyFromSecret(key.handle)
      }

      // Perform the signing
      result = ecKey.sign(data).toHex()
    } catch (error) {
      throw new OperationError(error.message)
    }
    // Return resulting buffer
    return Uint8Array.from(Buffer.from(result,'hex')).buffer
  }//sign


  /**
   * verify
   *
   * @description
   * Verifies a digital signature
   *
   * @param {CryptoKey} key
   * @param {BufferSource} signature
   * @param {BufferSource} data
   *
   * @returns {Boolean}
   */
  verify (key, signature, data) {
    let result
    // Ensure the key is a public or secret type
    if (key.type !== 'secret' && key.type !== 'public') {
      throw new InvalidAccessError('Verifying requires a public or secret key')
    }

    // Ensure data is hex string, array or Buffer
    if (!Array.isArray(data) && !Buffer.isBuffer(data) && typeof data !== 'string'){
      throw new DataError('Data must be an Array, Buffer or hex string')
    }

    // Ensure key.handle is hex string, array or Buffer
    if (!Array.isArray(key.handle) && !Buffer.isBuffer(key.handle) && typeof key.handle !== 'string' ){
      throw DataError('Key handle must be an Array, Buffer or hex string')
    }

    // Ensure signature is ArrayBuffer or hex string
    if (!signature instanceof ArrayBuffer && typeof signature !== 'string'){
      throw DataError('Signature must be an ArrayBuffer or hex string')
    }

    try {
      // Create curve via elliptic
      let ec = new elEdDSA('ed25519')
      
      // Generate keypair from key
      let ecKey 
      if (key.type === 'private' && key.extractable){
        if (typeof key.handle === 'string'){
          ecKey = ec.keyFromSecret(key.handle, 'hex')
        } else { 
          ecKey = ec.keyFromSecret(key.handle)
        }
      } else 
      if (key.type === 'public'){
        if (typeof key.handle === 'string'){
          ecKey = ec.keyFromPublic(key.handle, 'hex')
        } else { 
          ecKey = ec.keyFromPublic(key.handle.toString('hex'),'hex')
        }
      } else {
        throw new OperationError("Invalid key type")
      }

      // Convert ArrayBuffer back to hex
      if (signature instanceof ArrayBuffer){
        signature = Buffer.from(signature).toString('hex')
      }

      // Perform the verification
      result = ecKey.verify(data,signature)
    } catch (error) {
      throw new OperationError(error.message)
    }
    // Return boolean result
    return result
  }//verify


  /**
   * generateKey
   *
   * @description
   * Generate an EDDSA key pair
   *
   * @param {EcKeyGenParams} params
   * @returns {CryptoKey}
   */
  generateKey (params, extractable, usages) {
    // Validate usages
    usages.forEach(usage => {
        if (usage !== 'sign' && usage !== 'verify') {
          throw new SyntaxError('Key usages can only include "sign", or "verify"')
        }
    })
    // Generate random key for scret portion
    let secretBytes = crypto.randomBytes(32)

    // Derive public bytes
    let ec = new elEdDSA('ed25519')
    let ecKey = ec.keyFromSecret(secretBytes)
    let pubKey = Buffer.from(ecKey.pubBytes())

    // Set algorithm be a new EDDSA
    let algorithm = new EDDSA(params)

    // Create private key object
    let privateKey = new CryptoKey({
      type: 'private',
      algorithm,
      extractable,
      usages: ['sign'],
      handle: secretBytes
    })
    
    // Create public key object
    let publicKey = new CryptoKey({
      type: 'public',
      algorithm,
      extractable: true,
      usages: ['verify'],
      handle: pubKey
    })

    // Return the generated Key
    return new CryptoKeyPair({publicKey,privateKey})
  }//generateKey

  /**
   * importKey
   *
   * @description
   *
   * @param {string} format
   * @param {string|JsonWebKey} keyData
   * @param {KeyAlgorithm} algorithm
   * @param {Boolean} extractable
   * @param {Array} keyUsage
   *
   * @returns {CryptoKey}
   */
  importKey (format, keyData, algorithm, extractable, keyUsages) {
    let key, hash, normalizedHash, jwk, privateKeyInfo
    // Check formatting
    // "spki" format
    if (format === 'spki') {
      throw new CurrentlyNotSupportedError(format,'jwk')
    }

    // "pkcs8" format
    else if (format === 'pkcs8') {
      throw new CurrentlyNotSupportedError(format,'jwk')
    }

    // "jwk" format
    else if (format === 'jwk') {
      // Ensure data is JsonWebKey dictionary
      if (typeof keyData === 'object' && !Array.isArray(keyData)){
        jwk = new JsonWebKey(keyData)
      } else {
        throw new DataError('Invalid jwk format')
      }

      // Ensure 'd' field and keyUsages match up
      if (jwk.d !== undefined && keyUsages.some(usage => usage !== 'sign')) {
        throw new SyntaxError('Key usages must include "sign"')
      }

      if (jwk.d === undefined && !keyUsages.some(usage => usage === 'verify')) {
        throw new SyntaxError('Key usages must include "verify"')
      }

      // Validate 'kty' field
      if (jwk.kty !== 'OKP'){
        throw new DataError('Key type must be "OKP".')
      }

      // Validate 'crv' field
      if (jwk.crv !== 'Ed25519'){
        throw new DataError('Crv type must be "Ed25519".')
      }

      // Validate 'key_ops' field
      if (jwk.key_ops !== undefined){
        jwk.key_ops.forEach(op => {
          if (op !== 'sign'
            && op !== 'verify' ) {
            throw new DataError('Key operation can only include "sign", or "verify".')
          }
        })
      } 

      // Validate 'd' property
      if (jwk.d && jwk.x){
        try {
          // Generate new private CryptoKeyObject
          key = new CryptoKey({
              type: 'private',
              extractable,
              usages: ['sign'],
              handle: base64url.toBuffer(jwk.d)
          })
        } catch (error) {
          throw new DataError('Invalid "d" field value.')
        }
      }
      // Validate 'x' property 
      else if(jwk.x){
        // Generate new public CryptoKeyObject
        try {
          key = new CryptoKey({
            type: 'public',
            extractable: true,
            usages: ['verify'],
            handle: base64url.toBuffer(jwk.x)
          })
        } catch (error) {
          throw new DataError('Invalid "x" field value.')
        }
      }
      else {
        throw new DataError('Unknown jwk format, missing "x" and "d" fields.')
      }

      // Ensure the key length 
      if (key.handle.length !== 32){
        throw new DataError('Key handle must be 32 bytes in length.')
      }

      // Set new alg object
      key.algorithm = new EDDSA(algorithm)
    }
    // "raw" format
    else if (format === 'raw') {
      throw new CurrentlyNotSupportedError(format,'jwk')
    }
    // Otherwise bad format
    else {
      throw new KeyFormatNotSupportedError(format)
    }

    // Return key
    return key
  }//importKey


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
    // Setup resulting var
    let result

    // Validate handle slot
    if (!key.handle) {
      throw new OperationError('Missing key material')
    }

    // Ensure data is accessible
    if (key.extractable !== true){
      throw new InvalidAccessError('Key handle is not extractable.')
    }

    // "spki" format
    if (format === 'spki'){
      throw new CurrentlyNotSupportedError(format,"jwk' or 'raw")
    }
    // "pkcs8" format
    else if (format === 'pkcs8'){
      throw new CurrentlyNotSupportedError(format,"jwk' or 'raw")
    }
    // "jwk" format
    else if (format === 'jwk'){
      // Create new jwk
      let jwk = new JsonWebKey({
        "kty": "OKP",
        "crv": "Ed25519"
      })

      // If the key is Private then derive 'd' and 'x'
      let ec = new elEdDSA('ed25519')
      if (key.type === 'private'){
        let ecKey = ec.keyFromSecret(key.handle)
        jwk.d = base64url(key.handle)
        jwk.x = base64url(ecKey.pubBytes())
      } 
      // If the key is Public then derive 'x'
      else if (key.type === 'public'){
        let ecKey = ec.keyFromPublic(key.handle)
        jwk.x = base64url(ecKey.pubBytes())
      } 
      // Otherwise throw error
      else {
        throw new DataError ("Unknown key type.")
      }

      // Set "key_ops" field
      jwk.key_ops = key.usages

      // Set "ext" field
      jwk.ext = key.extractable

      // Set result to jwk object
      result = jwk
    }
    // "raw" format
    else if (format === 'raw'){
      // Let resulting data be Buffer containing data
      result = Buffer.from(key.handle)
    }
    // "hex" format
    else if (format === 'hex'){
      // Let resulting data be Buffer containing data
      result = base64url(key.handle)
    }
    // Otherwise throw bad format
    else {
      throw new KeyFormatNotSupportedError(format)
    }

    // Result result
    return result
  }

}//EDDSA

/**
 * Export
 */
module.exports = EDDSA

/*
let ed = new EDDSA({name: 'ED25519'})
let secretKey = {
  type : 'private',
  handle : Buffer.from(`4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb`,'hex')
}
let pubKey = {
  type : 'public',
  handle : Buffer.from(`3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c`,'hex')
}


let msg = (Buffer.from('72','hex'))

let sig = `92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00`
let enc = ed.sign(secretKey,'72')
let dec = ed.verify(pubKey,enc,msg)
// console.log("enc",enc)
// console.log("dec",dec)

let gennedKey = ed.generateKey({name: "EDDSA"},true,['sign','verify'])
// console.log("gennedKey",gennedKey.publicKey.handle,gennedKey.privateKey.handle)

let ec = new elEdDSA('ed25519')
let kty = "OKP"
let crv = "Ed25519"
let d = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
let x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"

let hexD = base64url.toBuffer(d)
let hexX = base64url.toBuffer(x)

// console.log('hexD',hexD)
// console.log('hexX',hexX)

let sk = ec.keyFromSecret(secretKey.handle)
// console.log(sk)
// console.log(Buffer.from(sk.pubBytes()))

let enc1 = ed.sign(gennedKey.privateKey,msg)
let dec1 = ed.verify(gennedKey.publicKey,enc1,msg)
// console.log("enc1",enc1)
// console.log("dec1",dec1)
 
// let testKey = ec.keyFromSecret(`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`,'hex')
// console.log( testKey )

let impPrivateKey = ed.importKey(
  "jwk",
  {
    "kty":"OKP",
    "crv":"Ed25519",
    "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
  },
  { 
    name: "EDDSA"
  },
  true,
  ['sign']
)
let impPublicKey = ed.importKey(
  "jwk",
  {
    "kty":"OKP",
    "crv":"Ed25519",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
  },
  { 
    name: "EDDSA"
  },
  true,
  ['verify']
)

let enc2 = ed.sign(impPrivateKey,msg)
let dec2 = ed.verify(impPublicKey,enc2,msg)
// console.log("enc2",enc2)
// console.log("dec2",dec2)

let expPrvKey = ed.exportKey('jwk',impPrivateKey)
let expPubKey = ed.exportKey('jwk',impPublicKey)

console.log('expPrvKey',expPrvKey)
console.log('expPubKey',expPubKey)

let expPrvKeyR = ed.exportKey('raw',impPrivateKey)
let expPubKeyR = ed.exportKey('raw',impPublicKey)

console.log('expPrvKeyR',expPrvKeyR)
console.log('expPubKeyR',expPubKeyR)

let expPrvKeyH = ed.exportKey('hex',impPrivateKey)
let expPubKeyH = ed.exportKey('hex',impPublicKey)

console.log('expPrvKeyH',expPrvKeyH)
console.log('expPubKeyH',expPubKeyH)
*/