/**
 * OperationError
 */
class OperationError extends Error {
  constructor (message) {
    super(message)
  }
}

/**
 * Export
 */
module.exports = OperationError
