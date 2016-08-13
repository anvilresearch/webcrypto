/**
 * Local dependencies
 */
const normalize = require('./algorithms/normalize')
const CryptoKey = require('./CryptoKey')
const CryptoKeyPair = require('./CryptoKeyPair')
const InvalidAccessError = require('./errors/InvalidAccessError')

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
    return new Promise()
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
    return new Promise()
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

    let normalizedAlgorithm = normalize.algorithm('sign', algorithm)

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

    let normalizedAlgorithm = normalize.algorithm('verify', alg)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(normalizedAlgorithm)
    }

    data = data.slice()

    return new Promise((resolve, reject) => {
      if (normalizedAlgorithm.name !== key.algorithm.name) {
        throw new InvalidAccessError()
      }

      if (!key.usages.includes('verify')) {
        throw new InvalidAccessError()
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
   * @returns {Promise}
   */
  digest (algorithm, data) {
    return new Promise()
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
    let normalizedAlgorithm = normalize.algorithm('generateKey', algorithm)

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
    let normalizedAlgorithm = normalize.algorithm('importKey', algorithm)

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
        if (!(keyData instanceof JsonWebKey)) {
          throw new TypeError()
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
        result.usages = normalize.usages(usages)

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
        if (!registeredAlgorithms[key.algorithm.name]) {
          throw new NotSupportedError()
        }

        if (key.extractable === false) {
          throw new InvalidAccessError()
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
    return new Promise()
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
  unwrapKey (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, exractable, keyUsages) {
    return new Promise()
  }
}

/**
 * Export
 */
module.exports = SubtleCrypto
