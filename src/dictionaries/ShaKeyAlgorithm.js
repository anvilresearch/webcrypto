/**
 * Module dependencies
 */
const crypto = require('crypto')
const KeyAlgorithm = require('./KeyAlgorithm')
const {OperationError} = require('../errors')

/**
 * ShaKeyAlgorithm
 */
class ShaKeyAlgorithm extends KeyAlgorithm {
}

/**
 * Export
 */
module.exports = ShaKeyAlgorithm
