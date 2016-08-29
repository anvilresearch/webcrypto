/**
 * Local dependencies
 */
const NotSupportedError = require('./NotSupportedError')

/**
 * KeyFormatNotSupportedError
 */
class KeyFormatNotSupportedError extends NotSupportedError {
  constructor (format) {
    super()
    this.message = `${format} is not a supported key format`
  }
}

/**
 * Export
 */
module.exports = KeyFormatNotSupportedError
