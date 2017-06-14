/**
 * Package dependencies
 */
const base64url = require('base64url')
const crypto = require('crypto')
const {spawnSync} = require('child_process')
const {TextEncoder, TextDecoder} = require('text-encoding')
const keyto = require('@trust/keyto')

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
 * ECDSA
 */
class ECDSA extends Algorithm {

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
      name: String,
      modulusLength: Number,
      publicExponent: 'BufferSource'
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
    // 1. Ensure the key is a private type only
    if (key.type !== 'private') {
      throw new InvalidAccessError('Signing requires a private key')
    }
    // 2-5. Ommitted due to support by Crypto
    // 6. Attempt to sign using Crypto lib
    try {
        data = Buffer.from(data)

        let signer = crypto.createSign('sha256')
        signer.update(data)

        result = signer.sign(key.handle)
    } catch (error) {
      throw new OperationError(error.message)
    }
    // 7. Return resulting buffer
    return result.buffer
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
    // 1. Ensure the key is a public type only
    if (key.type !== 'public') {
      throw new InvalidAccessError('Verifying requires a public key')
    }
    // 2-5. Ommitted due to support by Crypto
    // 6. Attempt to verify using Crypto lib
    try {
      data = Buffer.from(data)
      signature = Buffer.from(signature)

      let verifier = crypto.createVerify('sha256')
      verifier.update(data)

      result = verifier.verify(key.handle, signature)
    } catch (error) {
      throw new OperationError(error.message)
    }
    return result
  }//verify


  /**
   * generateKey
   *
   * @description
   * Generate an ECDSA key pair
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
      throw new DataError('namedCurve is a required parameter for ECDSA')
    }

    if (namedCurve === 'P-256'
      || namedCurve === 'P-384'
      || namedCurve === 'P-512') {
      throw new CurrentlyNotSupportedError(namedCurve, 'jwk')
    }

    let osslCurveName = EcKeyAlgorithm.mapping.find(alg => alg.namedCurve === namedCurve)

    try {
        // TODO may need to remove -noout if ec params is needed
        let privateKey = spawnSync('openssl', ['ecparam','-name',osslCurveName.name,'-genkey','-noout']).stdout
        let publicKey = spawnSync('openssl', ['ec', '-pubout'], { input: privateKey }).stdout
        keypair.privateKey = privateKey.toString('ascii').trim()
        keypair.publicKey = publicKey.toString('ascii').trim()
    } catch (error) {
    // 3. If any operation fails then throw error
      throw new OperationError(error.message)
    }

    // 4. Set algorithm be a new ECDSA
    let algorithm = new ECDSA(params)

    // 5-6. Set name to ECDSA
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
      if (keyUsages !== undefined && jwk.use !== undefined && jwk.use === 'sig'){
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
      if (namedCurve === 'K-256'){
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
      key.algorithm = new ECDSA(algorithm)
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

}//ECDSA

/**
 * Export
 */
module.exports = ECDSA

// TODO Clean me -- still WIP
/*
let secp256k1 = new ECDSA({name:"K-256"})
// --------------------------------------------------------------
console.log("secp256k1: generateKey Test")
let keys = secp256k1.generateKey({name:"K-256"},true,['sign','verify'])
console.log("genrated keys:",keys)
console.log('\n')
// --------------------------------------------------------------
console.log("secp256k1: importKey Test")
// console.log(keyto.from(keys.privateKey.handle,'pem').toJwk('private'))
// console.log(keyto.from(keys.publicKey.handle,'pem').toJwk('public'))
let pvKey = secp256k1.importKey(
    'jwk',
    {
        kty: 'EC',
        crv: 'K-256',
        d: 'PR587JJiuSE3aFthaonYf3VJtB9WXaZcN7Vi0OmBUtw',
        x: 'L_yAQbK4Kg95AknFkfVO8V5rWkN1shsz7jrEyDZ3McA',
        y: '2Na7_YUSHDMn68XsnIGOfo3TwiIqfbaTXvavUKzT6qo'
    },
    {
        name: 'K-256'
    },
    true,
    ['sign']
)
console.log('imported private Key:',pvKey)
let pbKey = secp256k1.importKey(
    'jwk',
    {
        kty: 'EC',
        crv: 'K-256',
        x: 'L_yAQbK4Kg95AknFkfVO8V5rWkN1shsz7jrEyDZ3McA',
        y: '2Na7_YUSHDMn68XsnIGOfo3TwiIqfbaTXvavUKzT6qo'
    },
    {
        name: 'K-256'
    },
    true,
    ['verify']
)
console.log('imported public Key:',pbKey)
console.log('\n')
// --------------------------------------------------------------
console.log("secp256k1: exportKey Test")
let pvKey2jwk = secp256k1.exportKey(
    'jwk',
    keys.privateKey
)
console.log('exported private Key:',pvKey2jwk)
let pbKey2jwk = secp256k1.exportKey(
    'jwk',
    keys.publicKey
)
console.log('exported public Key (jwk):',pbKey2jwk)
let pbKey2raw = secp256k1.exportKey(
    'raw',
    keys.publicKey
)
console.log('exported public Key (raw):',pbKey2raw)
console.log('\n')
// --------------------------------------------------------------
console.log("secp256k1: sign Test")
let signed = secp256k1.sign(
    pvKey,
    new TextEncoder().encode("Testing this sample text")
)
console.log(signed)
console.log('\n')
// --------------------------------------------------------------
console.log("secp256k1: verify Test")
let verified = secp256k1.verify(
    pbKey,
    new Uint8Array(signed),
    new TextEncoder().encode("Testing this sample text")
)
console.log(verified)*/
