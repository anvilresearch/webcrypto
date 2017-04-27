/**
 * Package dependencies
 */
const crypto = require('crypto')
const {spawnSync} = require('child_process')

const AesKeyAlgorithm = require('../dictionaries/AesKeyAlgorithm') 
const Algorithm = require ('../algorithms/Algorithm')
const CryptoKey = require('../keys/CryptoKey')


  /**
   * generateKey
   *
   * @description
   * Generate an AES-CBC key pair
   *
   * @param {RsaHashedKeyGenParams} params
   * @returns {CryptoKeyPair}
   */
var ivbytes = crypto.randomBytes(16)

function generateKey (params,extractable,usages) {
    // 1. Validate usages
    usages.forEach(usage => {
      if (usage !== 'encrypt' && usage !== 'decrypt' && usage !== 'wrapKey' && usage !== 'unwrapKey') {
        throw new SyntaxError('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
      }
    })
    // 2. Validate length
    if (![128,192,256].includes(params.length)) {
        throw new OperationError('Member length must 128, 192, 256.')
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

let result = generateKey(
    {
        name: "AES-CBC",
        length: 256, //can be  128, 192, or 256
    },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] //can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
)

console.log(result)
console.log(result.handle.length)