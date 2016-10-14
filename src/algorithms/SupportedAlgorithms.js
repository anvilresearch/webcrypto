/**
 * Local dependencies
 */
const Algorithm = require('../dictionaries/Algorithm')
const KeyAlgorithm = require('../dictionaries/KeyAlgorithm')
const RegisteredAlgorithms = require('./RegisteredAlgorithms')
const {NotSupportedError} = require('../errors')

/**
 * Supported Operations
 */
const operations = [
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'deriveBits',
  'digest', // THIS WASN'T IN THE LIST. PROBABLY GETTING SOMETHING WRONG HERE
  'wrapKey',
  'unwrapKey',
  'generateKey',
  'importKey',
  'exportKey',
  'getLength'
]

/**
 * SupportedAlgorithms
 */
class SupportedAlgorithms {

  /**
   * Constructor
   */
  constructor () {
    operations.forEach(op => {
      this[op] = new RegisteredAlgorithms()
    })
  }

  /**
   * Supported Operations
   */
  static get operations () {
    return operations
  }

  /**
   * Define Algorithm
   */
  define (alg, op, type) {
    let registeredAlgorithms = this[op]
    registeredAlgorithms[alg] = type
  }

  /**
   * Normalize
   */
  normalize (op, alg) {
    if (typeof alg === 'string') {
      return this.normalize(op, new KeyAlgorithm({ name: alg }))
    }

    if (typeof alg === 'object') {
      let registeredAlgorithms = this[op]
      let initialAlg

      try {
        initialAlg = new Algorithm(alg)
      } catch (error) {
        return error
      }

      let algName = initialAlg.name
      algName = registeredAlgorithms.getCaseInsensitive(algName)

      if (algName === undefined) {
        return new NotSupportedError(alg.name)
      }

      let desiredType, normalizedAlgorithm

      try {
        desiredType = require(registeredAlgorithms[algName])
        normalizedAlgorithm = new desiredType(alg)
        normalizedAlgorithm.name = algName
      } catch (error) {
        return error
      }

      let dictionaries = desiredType.dictionaries

      for (let i = 0; i < dictionaries.length; i++) {
        let dictionary = dictionaries[i]
        let members = dictionary.members

        for (let key in members) {
          let member = members[key]
          let idlValue = normalizedAlgorithm[key]

          try {
            if (member === 'BufferSource' && idlValue !== undefined) {
              normalizedAlgorithm[key] = idlValue.slice()
            }

            if (member === 'HashAlgorithmIdentifier') {
              let hashAlgorithm = this.normalize('digest', idlValue)
              if (hashAlgorithm instanceof Error) { return hashAlgorithm }
              normalizedAlgorithm[key] = hashAlgorithm
            }

            if (member === 'AlgorithmIdentifier') {
              normalizedAlgorithm[key] = this.normalize(WTF, idlValue)
            }
          } catch (error) {
            return error
          }
        }
      }

      return normalizedAlgorithm
    }
  }
}

/**
 * Export
 */
module.exports = SupportedAlgorithms
