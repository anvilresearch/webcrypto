/**
 * QuotaExceededError
 */
class QuotaExceededError extends Error {
  constructor (message) {
    super(message)
  }
}

/**
 * Export
 */
module.exports = QuotaExceededError
