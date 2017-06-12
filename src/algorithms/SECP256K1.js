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
const Secp256k1KeyAlgorithm = require('../dictionaries/Secp256k1KeyAlgorithm') 


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
 * SECP256K1
 */
class SECP256K1 extends Algorithm {

    /**
     * dictionaries
     */
    static get dictionaries () {
      return [
        KeyAlgorithm,
        Secp256k1KeyAlgorithm
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
   * generateKey
   *
   * @description
   * Generate an SECP256K1 key pair
   *
   * @param {Secp256k1Params} params
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

    try {
        // TODO may need to remove -noout if ec params is needed
        let privateKey = spawnSync('openssl', ['ecparam','-name','secp256k1','-genkey','-noout']).stdout
        let publicKey = spawnSync('openssl', ['ec', '-pubout'], { input: privateKey }).stdout
        keypair.privateKey = privateKey.toString('ascii')
        keypair.publicKey = publicKey.toString('ascii')
    } catch (error) {
    // 3. If any operation fails then throw error
      throw new OperationError(error.message)
    }
    // TODO Clean me
    // console.log(keyto.from(keypair.publicKey, 'pem').toString('pem', 'public_pkcs8'))
    // console.log(keypair.publicKey)
    // console.log(keyto.from(keypair.publicKey , 'pem').toJwk('public'))
    // console.log(keyto.from(keypair.privateKey , 'pem').toJwk('public'))

    // 4. Set algorithm be a new SECP256K1
    let algorithm = new SECP256K1(params)

    // 5-6. Set name to SECP256K1
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

    importKey (format, keyData, algorithm, extractable, keyUsages) {
        let key, hash, normalizedHash, jwk, privateKeyInfo
        // 1-2. Check formatting
        // 2.1. "spki" format
        if (format === 'spki') {
            
        }
        // 2.2. "pkcs8" format
        else if (format === 'pkcs8') {          
            
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
            if (jwk.key_ops !== undefined){
            key_ops.forEach(op => {
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
                        handle: keyto.from(jwk, 'jwk').toString('pem', 'private_pkcs8')
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
            let alg = new SECP256K1({
                name: 'K-256'
            })
            key.algorithm = alg
        }
        // 2.4. "raw" format
        else if (format === 'raw') {
        
        } 
        // 2.5. Otherwise bad format
        else {
            throw new KeyFormatNotSupportedError(format)
        }
        // 3. Return key
        return key
    }//importKey


}//SECP256K1


// TODO Clean me
let secp256k1 = new SECP256K1({name:"K-256"})

console.log("secp256k1: generateKey Test")
let keys = secp256k1.generateKey({name:"K-256"},true,['sign','verify'])
console.log("genrated keys:",keys,'\n')

console.log("secp256k1: importKey Test")
// console.log(keyto.from(keys.publicKey.handle,'pem').toJwk('public'))
let pvKey = secp256k1.importKey(
    'jwk',
    { 
        kty: 'EC',
        crv: 'K-256',
        d: 'O9uFxQ3tJp0Kb8lRhwX47CJVClpsHJDsGeH4aEsKW8w',
        x: 'z_w_IzNCnWUYLQKXfw6RYJaC2PvlD7xaBVm4-RAAEEA',
        y: '1sNwYlenam_6vcFOZ0jY4Ud7EbGoP2PVAlYAWCx0Sr0'
    },
    {
        name: 'K-256'
    },
    true,
    ['sign']
)
console.log('imported private Key:',pvKey.handle)
let pbKey = secp256k1.importKey(
    'jwk',
    {
        kty: 'EC',
        crv: 'K-256',
        x: '5mM2bJEnLy41gJohQoSanAUgYsWFJQjr4toNEEgNVbw',
        y: 'rGGYPDp0FbzcBQWu-yqzUDMpjgd1T22iqbkEKMIz_dQ' 
    },
    {
        name: 'K-256'
    },
    true,
    ['verify']
)
console.log('imported public Key:',pbKey.handle,'\n')