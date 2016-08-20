/**
 * KeyUsage
 */
class KeyUsage extends Array {

  /**
   * constructor
   */
  constructor (collection) {
    super()
    collection.forEach(item => this.push(item))
  }

  /**
   * normalize
   */
  normalize (usages) {
    let result = []

    for (let i = 0; i < this.length; i++) {
      let usage = this[i]

      if (usages.includes(usage)) {
        result.push(usage)
      }
    }

    return result
  }
}

/**
 * Export
 */
module.exports = new KeyUsage([
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'deriveBits',
  'wrapKey',
  'unwrapKey'
])
