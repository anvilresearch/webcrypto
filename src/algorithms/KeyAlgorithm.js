/**
 * KeyAlgorithm dictionary
 */
class KeyAlgorithm {
  constructor (name, op) {
    // validate and set name
    if (name === undefined) { throw new Error() }
    this.name = name

    // set op
    this.op = op
  }
}

/**
 * Export
 */
module.exports = KeyAlgorithm
