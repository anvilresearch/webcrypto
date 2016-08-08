/**
 * Encodings
 */
const encodings = {

  /**
   * buf2ab
   *
   * @description
   * Convert a Buffer instance to an ArrayBuffer instance
   *
   * @param {Buffer} buffer
   * @returns {ArrayBuffer}
   */
  buf2ab (buffer) {
    let ab = new ArrayBuffer(buffer.length)
    let view = new Uint8Array(ab)

    for (let i = 0; i < buffer.length; i++) {
      view[i] = buffer[i]
    }

    return ab
  },

  /**
   * str2ab
   *
   * @description
   * Convert a String instance to an ArrayBuffer instance
   *
   * @param {string} str
   * @returns {ArrayBuffer}
   */
  str2ab (str) {
    let buf = new ArrayBuffer(str.length * 2)
    let view = new Uint16Array(buf)

    for (let i = 0, strLen = str.length; i < strLen; i++) {
      view[i] = str.charCodeAt(i)
    }

    return buf
  },

  /**
   * ab2str
   *
   * @description
   * Convert an ArrayBuffer instance to a String instance
   *
   * @param {ArrayBuffer} ab
   * @returns {string}
   */
  ab2str (buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf))
  }
}

/**
 * Export
 */
module.exports = encodings
