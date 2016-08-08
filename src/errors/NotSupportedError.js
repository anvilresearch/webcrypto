/**
 * NotSupportedError
 */
class NotSupportedError extends Error {
  constructor (alg) {
    super()
    this.message = `${alg} is not a supported algorithm`
  }
}

/**
 * Export
 */
module.exports = NotSupportedError
