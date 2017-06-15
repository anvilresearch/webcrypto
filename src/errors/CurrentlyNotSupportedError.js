/**
 * Local dependencies
 */
const NotSupportedError = require('./NotSupportedError')

/**
 * CurrentlyNotSupportedError
 */
class CurrentlyNotSupportedError extends NotSupportedError {
  constructor (format,available) {
    super()
    this.message = `Currently '${format}' is not a supported format. Please use '${available}' in the interim.`
  }
}

/**
 * Export
 */
module.exports = CurrentlyNotSupportedError
