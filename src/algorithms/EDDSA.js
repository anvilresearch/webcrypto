/**
 * Package dependencies
 */
const base64url = require('base64url')
const crypto = require('crypto')
const {spawnSync} = require('child_process')
const {TextEncoder, TextDecoder} = require('text-encoding')
const keyto = require('@trust/keyto')
const elEdDSA = require('elliptic').eddsa;

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
    // Ensure the key is a secret type only
    if (key.type !== 'secret'){
      throw new InvalidAccessError('Signing requires a secret key')
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
      
      // Generate keypair from secret key
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
      if (key.type === 'secret'){
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
          ecKey = ec.keyFromPublic(key.handle)
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
   * @returns {CryptoKeyPair}
   */
  generateKey (params, extractable, usages) {
    // 1. Validate usages
    usages.forEach(usage => {
        if (usage !== 'sign' && usage !== 'verify') {
          throw new SyntaxError('Key usages can only include "sign", or "verify"')
        }
    })

    // 2. Generate a keypair
    let keypair = {}
    let { namedCurve } = params

    if (!namedCurve) {
      throw new DataError('namedCurve is a required parameter for EDDSA')
    }

    if (!EcKeyAlgorithm.mapping.map(alg => alg.namedCurve).includes(namedCurve)) {
      throw new DataError('namedCurve is not valid')
    }

    let osslCurveName = EcKeyAlgorithm.mapping.find(alg => alg.namedCurve === namedCurve)

    try {
        // TODO may need to remove -noout if ec params is needed
        let privateKey = spawnSync('openssl', ['ecparam','-name',osslCurveName.name,'-genkey','-noout']).stdout
        let publicKey = spawnSync('openssl', ['ec', '-pubout'], { input: privateKey }).stdout
        try {
          keypair.privateKey = privateKey.toString('ascii').trim()
          keypair.publicKey = publicKey.toString('ascii').trim()
        } catch(error){
          throw new OperationError(error.message)
        }
    } catch (error) {
    // 3. If any operation fails then throw error
      throw new OperationError(error.message)
    }

    // 4. Set algorithm be a new EDDSA
    let algorithm = new EDDSA(params)

    // 5-6. Set name to EDDSA
    // Defined in class header so it will be passed down via params

    // 7-11. Create publicKey object
    let publicKey = new CryptoKey({
      type: 'public',
      algorithm,
      extractable: true,
      usages: ['verify'],
      handle: keypair.publicKey
    })

    // 12-16. Create privateKey object
    let privateKey = new CryptoKey({
      type: 'private',
      algorithm,
      extractable,
      usages: ['sign'],
      handle: keypair.privateKey
    })

    // 17-20. Create and return a new CryptoKeyPair
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
   * @param {Array} keyUsages
   *
   * @returns {CryptoKey}
   */
  importKey (format, keyData, algorithm, extractable, keyUsages) {
    let key, hash, normalizedHash, jwk, privateKeyInfo
    // 1-2. Check formatting
    // 2.1. "spki" format
    if (format === 'spki') {
      throw new CurrentlyNotSupportedError(format,'jwk')
    }

    // 2.2. "pkcs8" format
    else if (format === 'pkcs8') {
      throw new CurrentlyNotSupportedError(format,'jwk')
    }

    // 2.3. "jwk" format
    else if (format === 'jwk') {
      // 2.3.1 Ensure data is JsonWebKey dictionary
      if (typeof keyData === 'object' && !Array.isArray(keyData)){
        jwk = new JsonWebKey(keyData)
      } else {
        throw new DataError('Invalid jwk format')
      }

      // 2.3.2. Ensure 'd' field and keyUsages match up
      if (jwk.d !== undefined && keyUsages.some(usage => usage !== 'sign')) {
        throw new SyntaxError('Key usages must include "sign"')
      }

      if (jwk.d === undefined && !keyUsages.some(usage => usage === 'verify')) {
        throw new SyntaxError('Key usages must include "verify"')
      }

      // 2.3.3 Validate 'kty' field
      if (jwk.kty !== 'EC'){
        throw new DataError('Key type must be "EC".')
      }

      // 2.3.4. Validate 'use' field
      if (keyUsages !== undefined && jwk.use !== undefined && jwk.use !== 'sig'){
        throw new DataError('Key use must be "sig".')
      }

      // 2.3.5. Validate 'key_ops' field
      if (jwk.key_ops !== undefined) {
        jwk.key_ops.forEach(op => {
          if (op !== 'sign'
            && op !== 'verify' ) {
            throw new DataError('Key operation can only include "sign", or "verify".')
          }
        })
      }

      // 2.3.6. Validate 'ext' field
      if (jwk.ext !== undefined && jwk.ext === false && extractable === true){
        throw new DataError('Cannot be extractable when "ext" is set to false')
      }

      // 2.3.7. Set namedCurve
      let namedCurve = jwk.crv

      // 2.3.8. Ommitted due to redundancy

      // 2.3.9.1. If namedCurve is equal to 'secp256k1' then...
      if (EcKeyAlgorithm.mapping.map(alg => alg.namedCurve).includes(namedCurve)){
        // 2.3.9.1.1-3 Ommited due to redundancy
        // 2.3.9.1.4.1. Validate 'd' property
        if (jwk.d) {
          // 2.3.9.1.4.1.1. TODO jwk validation here...
          // 2.3.9.1.4.1.2-3 Generate new private CryptoKeyObject
          key = new CryptoKey({
              type: 'private',
              extractable,
              usages: ['sign'],
              handle: keyto.from(jwk, 'jwk').toString('pem', 'private_pkcs1')
          })
        }
        // 2.3.9.1.4.2. Otherwise...
        else {
          // 2.3.9.1.4.2.1. TODO jwk validation here...
          // 2.3.9.1.4.2.2-3 Generate new public CryptoKeyObject
          key = new CryptoKey({
            type: 'public',
            extractable: true,
            usages: ['verify'],
            handle: keyto.from(jwk, 'jwk').toString('pem', 'public_pkcs8')
          })
        }
      }
      // 2.3.9.2. Otherwise...
      else {
        // 2.3.9.2.1. TODO Implement further key import steps from other specs
        // 2.3.9.2.1. Throw error because there are currently no further specs
        throw new DataError ('Not a valid jwk specification')
      }
      // 2.3.10. Ommitted due to redudancy
      // 2.3.11-14 Set new alg object
      key.algorithm = new EDDSA(algorithm)
    }
    // 2.4. "raw" format
    else if (format === 'raw') {
      throw new CurrentlyNotSupportedError(format,'jwk')
    }
    // 2.5. Otherwise bad format
    else {
      throw new KeyFormatNotSupportedError(format)
    }
    // 3. Return key
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
    // 1. Setup resulting var
    let result

    // 2. Validate handle slot
    if (!key.handle) {
      throw new OperationError('Missing key material')
    }

    // 3.1. "spki" format
    if (format === 'spki') {
      throw new CurrentlyNotSupportedError(format,"jwk' or 'raw")
    }
    // 3.2. "pkcs8" format
    else if (format === 'pkcs8') {
      throw new CurrentlyNotSupportedError(format,"jwk' or 'raw")
    }
    // 2.3. "jwk" format
    else if (format === 'jwk') {
      // 2.3.1-3 Create new jwk
      let jwk = keyto.from(key.handle, 'pem').toJwk(key.type)

      // 2.3.4. Set "key_ops" field
      jwk.key_ops = key.usages

      // 2.3.5. Set "ext" field
      jwk.ext = key.extractable

      // 2.3.6. Set result to jwk object
      result = jwk
    }
    // 3.4. "raw" format
    else if (format === 'raw') {
      // 3.4.1. Validate that the internal use is public
      if (key.type !== 'public'){
        throw new InvalidAccessError('Can only access public key data.')
      }
      // 3.4.2. Omitted due to redundancy
      // 3.4.3. Let resulting data be Buffer containing data
      result = Buffer.from(key.handle)
    }
    // 3.5. Otherwise bad format
    else {
      throw new KeyFormatNotSupportedError(format)
    }

    // 4. Result result
    return result
  }

}//EDDSA

/**
 * Export
 */
module.exports = EDDSA

let ed = new EDDSA({name: 'ED25519'})
let secretKey = {
  type : 'secret',
  handle : `4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb`
}
let pubKey = {
  type : 'public',
  handle : `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c`
}
let msg = (Buffer.from('72','hex'))

let sig = `92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00`
let enc = ed.sign(secretKey,'72')
let dec = ed.verify(pubKey,enc,msg)
console.log("enc",enc)
console.log("dec",dec)