/**
 * Local dependencies
 */
const CryptoKey = require('./keys/CryptoKey')
const CryptoKeyPair = require('./keys/CryptoKeyPair')
const JsonWebKey = require('./keys/JsonWebKey')
const recognizedKeyUsages = require('./keys/recognizedKeyUsages')
const supportedAlgorithms = require('./algorithms')
const {InvalidAccessError, NotSupportedError} = require('./errors')
const {TextEncoder,TextDecoder} = require('text-encoding')

/**
 * SubtleCrypto
 */
class SubtleCrypto {

  /**
   * encrypt
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {CryptoKey} key
   * @param {BufferSource} data
   *
   * @returns {Promise}
   */
  encrypt (algorithm, key, data) {
    data = data.slice()

    let normalizedAlgorithm = supportedAlgorithms.normalize('encrypt', algorithm)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    return new Promise((resolve, reject) => {
      if (normalizedAlgorithm.name !== key.algorithm.name) {
        throw new InvalidAccessError('Algorithm does not match key')
      }

      if (!key.usages.includes('encrypt')) {
        throw new InvalidAccessError('Key usages must include "encrypt"')
      }

      let ciphertext = normalizedAlgorithm.encrypt(algorithm,key, data)

      resolve(ciphertext)
    })
  }

  /**
   * decrypt
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {CryptoKey} key
   * @param {BufferSource} data
   *
   * @returns {Promise}
   */
  decrypt (algorithm, key, data) {
    let normalizedAlgorithm = supportedAlgorithms.normalize('decrypt', algorithm)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    data = data.slice()

    return new Promise((resolve, reject) => {
      if (normalizedAlgorithm.name !== key.algorithm.name) {
        throw new InvalidAccessError('Algorithm does not match key')
      }

      if (!key.usages.includes('decrypt')) {
        throw new InvalidAccessError('Key usages must include "decrypt"')
      }

      let plaintext = normalizedAlgorithm.decrypt(algorithm, key, data)
      resolve(plaintext)
    })
  }

  /**
   * sign
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {CryptoKey} key
   * @param {BufferSource} data
   *
   * @returns {Promise}
   */
  sign (algorithm, key, data) {
    data = data.slice()

    let normalizedAlgorithm = supportedAlgorithms.normalize('sign', algorithm)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    return new Promise((resolve, reject) => {
      if (normalizedAlgorithm.name !== key.algorithm.name) {
        throw new InvalidAccessError('Algorithm does not match key')
      }

      if (!key.usages.includes('sign')) {
        throw new InvalidAccessError('Key usages must include "sign"')
      }

      let result = normalizedAlgorithm.sign(key, data)

      resolve(result)
    })
  }

  /**
   * verify
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {CryptoKey} key
   * @param {BufferSource} signature
   * @param {BufferSource} data
   *
   * @returns {Promise}
   */
  verify (alg, key, signature, data) {
    signature = signature.slice()

    let normalizedAlgorithm = supportedAlgorithms.normalize('verify', alg)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    data = data.slice()

    return new Promise((resolve, reject) => {
      if (normalizedAlgorithm.name !== key.algorithm.name) {
        throw new InvalidAccessError('Algorithm does not match key')
      }

      if (!key.usages.includes('verify')) {
        throw new InvalidAccessError('Key usages must include "verify"')
      }

      let result = normalizedAlgorithm.verify(key, signature, data)
      resolve(result)
    })
  }

  /**
   * digest
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {BufferSource} data
   *
   * @returns {Promise.<ArrayBuffer>}
   */
  digest (algorithm, data) {
    data = data.slice()

    let normalizedAlgorithm = supportedAlgorithms.normalize('digest', algorithm)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    return new Promise((resolve, reject) => {
      try {
        let result = normalizedAlgorithm.digest(algorithm, data)
        return resolve(result)
      } catch (error) {
        return reject(error)
      }
    })
  }

  /**
   * generateKey
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {Boolean} extractable
   * @param {Array} keyUsages
   *
   * @returns {Promise}
   */
  generateKey (algorithm, extractable, keyUsages) {
    let normalizedAlgorithm = supportedAlgorithms.normalize('generateKey', algorithm)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    return new Promise((resolve, reject) => {
      try {
        let result = normalizedAlgorithm.generateKey(algorithm, extractable, keyUsages)

        if (result instanceof CryptoKey) {
          let {type,usages} = result
          let restricted = (type === 'secret' || type === 'private')
          let emptyUsages = (!usages || usages.length === 0)

          if (restricted && emptyUsages) {
            throw new SyntaxError()
          }
        }

        if (result instanceof CryptoKeyPair) {
          let {privateKey:{usages}} = result

          if (!usages || usages.length === 0) {
            throw new SyntaxError()
          }
        }

        resolve(result)
      } catch (error) {
        return reject(error)
      }
    })
  }

  /**
   * deriveKey
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {CryptoKey} baseKey
   * @param {AlgorithmIdentifier} derivedKeyType
   * @param {Boolean} extractable
   * @param {Array} keyUsages
   * @returns {Promise}
   */
  deriveKey (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
    return new Promise()
  }

  /**
   * deriveBits
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {CryptoKey} baseKey
   * @param {number} length
   *
   * @returns {Promise}
   */
  deriveBits (algorithm, baseKey, length) {
    return new Promise()
  }

  /**
   * importKey
   *
   * @description
   *
   * @param {KeyFormat} format
   * @param {BufferSource|JWK} keyData
   * @param {AlgorithmIdentifier} algorithm
   * @param {Boolean} extractable
   * @param {Array} keyUsages
   *
   * @returns {Promise}
   */
  importKey (format, keyData, algorithm, extractable, keyUsages) {
    let normalizedAlgorithm = supportedAlgorithms.normalize('importKey', algorithm)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    return new Promise((resolve, reject) => {
      if (format === 'raw' || format === 'pkcs8' || format === 'spki') {
        if (keyData instanceof JsonWebKey) {
          throw new TypeError()
        }

        keyData = keyData.slice()
      }

      if (format === 'jwk') {
        keyData = new JsonWebKey(keyData)

        if (!(keyData instanceof JsonWebKey)) {
          throw new TypeError('key is not a JSON Web Key')
        }
      }

      try {
        let result = normalizedAlgorithm
          .importKey(format, keyData, algorithm, extractable, keyUsages)

        if (result.type === 'secret' || result.type === 'private') {
          if (!result.usages || result.usages.length === 0) {
            throw new SyntaxError()
          }
        }

        result.extractable = extractable
        result.usages = recognizedKeyUsages.normalize(keyUsages)

        resolve(result)
      } catch (error) {
        return reject(error)
      }
    })
  }

  /**
   * exportKey
   *
   * @description
   *
   * @param {KeyFormat} format
   * @param {CryptoKey} key
   *
   * @returns {Promise}
   */
  exportKey (format, key) {
    return new Promise((resolve, reject) => {
      try {
        let registeredAlgorithms = supportedAlgorithms['exportKey']

        if (!registeredAlgorithms[key.algorithm.name]) {
          throw new NotSupportedError(key.algorithm.name)
        }

        if (key.extractable === false) {
          throw new InvalidAccessError('Key is not extractable')
        }

        let result = key.algorithm.exportKey(format, key)

        resolve(result)
      } catch (error) {
        return reject(error)
      }
    })
  }

  /**
   * wrapKey
   *
   * @description
   *
   * @param {KeyFormat} format
   * @param {CryptoKey} key
   * @param {CryptoKey} wrappingKey
   * @param {AlgorithmIdentifier} wrapAlgorithm
   *
   * @returns {Promise}
   */
  wrapKey (format, key, wrappingKey, wrapAlgorithm) {
    // 1. Parameters
    // 2. Setup normalizedAlgorithm with op as 'unwrap'
    let normalizedAlgorithm = supportedAlgorithms.normalize('wrapKey', wrapAlgorithm)
    if (normalizedAlgorithm instanceof Error) {
      // 3. If failed, then try again with op as 'encrypt'
      normalizedAlgorithm = supportedAlgorithms.normalize('encrypt', wrapAlgorithm)
    }
    // 4. Otherwise reject outright
    if (normalizedAlgorithm instanceof Error)  {
      return Promise.reject(normalizedAlgorithm)
    }
    // 5-6. Setup and asynchronously return a new promise
    return new Promise((resolve, reject) => {
      // 7. Try catch the following step...
      // if anything goes wrong then reject the promise outright
      try {
          // 8. Validate normalizedAlgorithm name property
          if (normalizedAlgorithm.name !== wrappingKey.algorithm.name) {
            throw new InvalidAccessError('NormalizedAlgorthm name must be same as wrappingKey algorithm name')
          } 

          // 9. Validate usages property contains wrap
          if (!wrappingKey.usages.includes('wrapKey')) {
            throw new InvalidAccessError('Wrapping key usages must include "wrapKey"')
          }

          // 10. Validate algorithm contains exportKey
          let exportKeyAlgorithms = supportedAlgorithms['exportKey']
          if (!exportKeyAlgorithms[key.algorithm.name]) {
            throw new NotSupportedError(key.algorithm.name)
          }

          // 11. Validate extractable property
          if (key.extractable === false) {
            throw new InvalidAccessError('Key is not extractable')
          }

          // 12. Generate extracted key
          return this.exportKey(format,key)
                .then(exportedKey => { 
                  let bytes
                  // 13.1. If format is "raw", "pkcs8", or "spki":
                   if (["raw", "pkcs8","spki"].includes(format)) {
                    bytes = exportedKey
                  }
                  // 13.2. If format is "jwk"
                  else if (format === "jwk"){
                    let json = JSON.stringify(exportedKey)
                    bytes = new TextEncoder().encode(json)
                  } 
                  // 14.1. If the normalizedAlgorithm supports wrapKey then use it
                  if (normalizedAlgorithm['wrapKey']){
                    return normalizedAlgorithm.wrapKey(format,bytes,wrappingKey,wrapAlgorithm)
                  }
                  // 14.2. Otherwise try with encrypt
                  else if (normalizedAlgorithm['encrypt']){
                    return normalizedAlgorithm.encrypt(wrapAlgorithm,wrappingKey,new Uint8Array(bytes))
                  } 
                  // 14.3. Otherwise throw error
                  else {
                    return reject (new NotSupportedError(normalizedAlgorithm.name))
                  }
                })
                // 15. Return the resulting promise
                .then(resolve)
      } catch (error) {
        return reject(error)
      }
    })
  }

  /**
   * unwrapKey
   *
   * @description
   *
   * @param {KeyFormat} format
   * @param {BufferSource} wrappedKey
   * @param {CryptoKey} unwrappingKey
   * @param {AlgorithmIdentifier} unwrapAlgorithm
   * @param {AlgorithmIdentifier} unwrappedKeyAlgorithm
   * @param {Boolean} extractable
   * @param {Array} keyUsages
   *
   * @returns {Promise}
   */
  unwrapKey (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
    // 1. Parameters
    // 2. Ommited due to redundancy
    
    // 3. Setup normalizedAlgorithm with op as 'unwrap'
    let normalizedAlgorithm = supportedAlgorithms.normalize('unwrapKey', unwrapAlgorithm)
    if (normalizedAlgorithm instanceof Error) {
    // 4. If failed, then try again with op as 'encrypt'
      normalizedAlgorithm = supportedAlgorithms.normalize('decrypt', unwrapAlgorithm)
    }

    // 5. Otherwise reject outright
    if (normalizedAlgorithm instanceof Error)  {
      return Promise.reject(normalizedAlgorithm)
    }

    // 6. Setup normalizedKeyAlgorithm
    let normalizedKeyAlgorithm = supportedAlgorithms.normalize('importKey', unwrappedKeyAlgorithm)
    if (normalizedKeyAlgorithm instanceof Error) {
    // 7. If failed, then try again with op as 'encrypt'
      return Promise.reject(normalizedKeyAlgorithm)
    }

    // 8-9. Setup and asynchronously return a new promise
    return new Promise((resolve, reject) => {
      // 10. Try catch the following step...
      // if anything goes wrong then reject the promise outright
      try {
          // 11. Validate normalizedAlgorithm name property
          if (normalizedAlgorithm.name !== unwrappingKey.algorithm.name) {
            throw new InvalidAccessError('NormalizedAlgorthm name must be same as unwrappingKey algorithm name')
          } 

          // 12. Validate usages property contains unwrap
          if (!unwrappingKey.usages.includes('unwrapKey')) {
            throw new InvalidAccessError('Unwrapping key usages must include "unwrapKey"')
          }
          
          let key
          // 13.1. If the normalizedAlgorithm supports unwrapKey then use it
          if (normalizedAlgorithm['unwrapKey']){
            key = normalizedAlgorithm.unwrapKey(format,wrappedKey,unwrappingKey,unwrapAlgorithm,unwrappedKeyAlgorithm,extractable,keyUsages)
          }

          // 13.2. Otherwise try with decrypt
          else if (normalizedAlgorithm['decrypt']){
            key = normalizedAlgorithm.decrypt(unwrapAlgorithm,unwrappingKey,wrappedKey)
          } 

          // 13.3. Otherwise throw error
          else {
            return reject (new NotSupportedError(normalizedAlgorithm.name))
          }
        
          let bytes
          // 14.1. If format is "raw", "pkcs8", or "spki":
            if (["raw", "pkcs8","spki"].includes(format)) {
            bytes = key
          }

          // 14.2. If format is "jwk"
          else if (format === "jwk"){
            bytes = JSON.parse(new TextDecoder().decode(key))
          } 

          // 15. Import the resulting unwrapped content
          // 16-18. Ommitted because it is handled by importKey interface
          let result = normalizedKeyAlgorithm.importKey(format,
                                                        bytes,
                                                        unwrappedKeyAlgorithm,
                                                        extractable,
                                                        keyUsages)
          // 19. Resolve the result
          return resolve(result)
      } catch (error) {
        return reject(error)
      }
    })
  }
}

/**
 * Export
 */
module.exports = SubtleCrypto