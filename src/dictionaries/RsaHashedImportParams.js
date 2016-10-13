/**
 * RsaHashedImportParams
 */
class RsaHashedImportParams {
  constructor (hash) {
    // validate and set hash
    //if (!(hash instanceof HashAlgorithmIdentifier)) { throw new Error() }
    this.hash = hash
  }
}

/**
 * Export
 */
module.exports = RsaHashedImportParams
