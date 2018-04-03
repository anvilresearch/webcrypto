/**
 * Test dependencies
 */
const chai = require('chai')
const expect = chai.expect
const {TextEncoder} = require('text-encoding')

/**
 * Assertions
 */
chai.should()

/**
 * Code under test
 */
const {
  RsaPrivateKey,
  RsaPrivateJwk,
  RsaPrivateCryptoKeySHA1,
  RsaPrivateCryptoKeySHA256,
  RsaPrivateCryptoKeySHA384,
  RsaPrivateCryptoKeySHA512,
  RsaPublicKey,
  RsaPublicJwk,
  RsaPublicCryptoKeySHA1,
  RsaPublicCryptoKeySHA256,
  RsaPublicCryptoKeySHA384,
  RsaPublicCryptoKeySHA512
} = require('../RsaKeyPairForTesting')

const crypto = require('../../src')
const CryptoKey = require('../../src/keys/CryptoKey')
const CryptoKeyPair = require('../../src/keys/CryptoKeyPair')
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const RsaKeyAlgorithm = require('../../src/dictionaries/RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('../../src/dictionaries/RsaHashedKeyAlgorithm')
const RSASSA_PKCS1_v1_5 = require('../../src/algorithms/RSASSA-PKCS1-v1_5')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')

/**
 * Tests
 */
  /**
   * dictionaries getter
   */
  describe.skip('dictionaries getter', () => {
    it('should return an array', () => {
      RSASSA_PKCS1_v1_5.dictionaries.should.eql([
        KeyAlgorithm,
        RsaKeyAlgorithm,
        RsaHashedKeyAlgorithm
      ])
    })
  })

  /**
   * members getter
   */
  describe.skip('members getter', () => {
    it('should return an object', () => {
      RSASSA_PKCS1_v1_5.members.publicExponent.should.equal('BufferSource')
      RSASSA_PKCS1_v1_5.members.hash.should.equal('HashAlgorithmIdentifier')
    })
  })

  /**
   * sign
   */
  describe('sign', () => {
      let data, 
        rsa1,
        rsa256,
        rsa384,
        rsa512,
        signatureSHA1, 
        signatureSHA256, 
        signatureSHA384,
        signatureSHA512

    before(() => {
      rsa1 = new RSASSA_PKCS1_v1_5({ name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-1' }})
      rsa256 = new RSASSA_PKCS1_v1_5({ name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' }})
      rsa384 = new RSASSA_PKCS1_v1_5({ name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-384' }})
      rsa512 = new RSASSA_PKCS1_v1_5({ name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-512' }})

      data = new TextEncoder().encode('signed with Chrome webcrypto')

      signatureSHA1 = new Uint8Array([
        127,216,28,63,83,35,34,208,245,91,207,119,10,184,129,202,
        139,66,206,41,38,172,58,191,191,192,170,0,50,252,203,79,122,
        189,47,152,221,146,48,67,138,202,133,8,129,52,124,23,54,221,
        74,255,46,115,31,175,254,168,16,54,106,148,120,155,95,209,
        239,49,224,192,150,248,194,219,147,147,125,115,196,40,254,
        13,36,115,150,178,102,249,182,214,61,30,134,186,50,187,244,
        120,160,29,208,130,92,192,213,98,166,182,109,179,67,120,99,
        142,173,192,83,1,151,56,236,123,92,232,170,145,139,7,170,135,
        54,18,177,153,63,6,130,239,175,165,64,78,154,125,150,185,47,
        92,113,83,169,254,192,127,102,214,36,173,94,39,123,58,137,2,
        108,12,202,141,26,72,95,4,235,54,187,254,90,7,4,202,109,197,
        16,16,98,205,96,250,74,234,136,108,154,231,19,213,145,97,166,
        68,145,210,203,141,107,42,86,116,111,28,68,211,252,202,204,
        219,96,183,3,98,113,51,196,140,164,123,226,223,194,186,161,
        194,39,115,227,85,167,219,182,201,34,84,63,69,139,198,150,
        141,163,227,34,215,156,56,98,21
      ])
      signatureSHA256 = new Uint8Array([
        84, 181, 186, 121, 235, 76, 199, 102, 174, 125, 176, 216, 94, 190,
        243, 201, 219, 114, 227, 61, 54, 194, 237, 14, 248, 204, 120, 109,
        249, 220, 229, 80, 44, 48, 86, 133, 96, 129, 85, 213, 70, 19, 126,
        0, 160, 91, 18, 185, 200, 102, 180, 181, 69, 27, 162, 181, 189, 110,
        188, 112, 124, 93, 57, 208, 91, 142, 182, 192, 87, 167, 193, 111,
        88, 5, 244, 108, 200, 150, 133, 68, 144, 208, 27, 155, 222, 213, 189,
        224, 156, 226, 124, 65, 178, 69, 71, 63, 243, 141, 3, 126, 209, 237,
        45, 179, 240, 255, 194, 245, 43, 148, 123, 97, 172, 239, 168, 221,
        44, 186, 72, 194, 29, 9, 171, 103, 125, 182, 39, 95, 163, 80, 3, 208,
        184, 184, 48, 114, 135, 7, 111, 114, 38, 25, 28, 234, 82, 18, 49, 113,
        20, 251, 59, 147, 206, 7, 134, 15, 189, 201, 253, 241, 120, 236, 58,
        235, 148, 27, 204, 233, 165, 31, 27, 223, 28, 10, 214, 159, 109, 186,
        239, 71, 126, 18, 63, 111, 198, 115, 226, 237, 145, 26, 12, 120, 56,
        166, 13, 195, 65, 11, 114, 149, 145, 255, 242, 97, 190, 255, 202, 219,
        144, 83, 238, 240, 182, 82, 165, 229, 118, 146, 29, 95, 127, 76, 188,
        247, 138, 254, 72, 18, 251, 42, 118, 156, 229, 66, 8, 106, 55, 106,
        83, 232, 234, 23, 195, 160, 167, 133, 14, 181, 126, 5, 36, 157, 2, 81,
        144, 83
      ])
      signatureSHA384 = new Uint8Array([
        21,153,55,225,112,89,64,99,7,223,198,5,88,40,109,185,100,147,36,
        146,188,103,131,247,20,84,227,185,14,55,5,48,253,39,179,227,168,
        118,94,230,243,115,28,153,185,140,129,238,38,185,168,43,113,4,48,
        112,236,65,242,19,60,56,250,127,20,116,45,137,123,24,81,88,219,
        181,124,87,139,60,107,74,2,192,19,155,225,115,169,246,76,168,24,
        45,111,53,231,173,213,3,187,168,216,37,47,116,133,180,76,184,88,
        251,156,96,197,159,127,215,166,244,39,195,169,103,15,139,182,206,
        192,181,32,35,18,197,99,90,48,45,33,237,89,186,201,46,147,122,30,
        78,246,173,98,47,34,92,7,197,159,205,121,150,238,169,89,212,66,
        134,141,194,237,214,81,171,30,159,15,35,117,39,34,47,78,122,161,
        160,21,212,112,153,129,74,79,206,117,95,161,15,66,106,48,247,199,
        96,230,136,139,87,144,239,64,234,218,143,78,145,85,3,157,135,245,
        38,155,7,174,78,157,2,20,36,160,151,205,4,172,238,20,130,129,229,
        130,26,7,177,210,20,72,39,74,66,240,168,224,121,142,128,14,204,
        114,190
      ])
      signatureSHA512 = new Uint8Array([
        4,158,87,2,1,45,7,135,46,182,165,62,255,35,13,36,73,13,129,70,162,
        147,210,17,218,88,16,176,243,63,97,255,26,184,128,7,148,56,46,63,
        113,52,71,149,189,255,91,195,209,1,129,39,128,24,255,109,250,80,16,
        240,38,152,10,227,38,153,110,14,32,153,103,222,48,215,89,48,118,46,
        172,245,13,200,125,196,27,101,13,251,223,91,128,245,30,158,22,233,
        78,129,125,168,49,211,195,50,120,189,250,29,54,102,58,5,168,81,241,
        252,9,168,138,36,92,233,24,246,103,82,39,200,10,142,168,83,150,243,
        91,83,120,149,109,163,184,155,155,116,72,251,120,146,62,119,134,194,
        12,250,195,21,92,49,196,120,100,85,125,26,5,86,89,83,102,89,249,228,
        251,50,181,101,109,130,199,222,237,198,195,190,142,166,94,78,71,24,
        145,101,199,239,212,125,235,110,43,191,235,176,233,97,52,24,205,93,
        101,144,107,122,14,27,108,202,20,43,227,151,8,181,209,3,181,68,35,
        14,171,17,142,67,215,135,65,39,245,152,103,106,26,53,56,207,78,93,
        181,160,196,6,25,200,4,59,48,83
      ])
    })

    it('should throw with non-private key', () => {
      expect(() => {
        rsa256.sign(RsaPublicCryptoKeySHA256, new Uint8Array())
      }).to.throw('Signing requires a private key')
    })

    it('should return an ArrayBuffer', () => {
      rsa256.sign(RsaPrivateCryptoKeySHA256, data).should.be.instanceof(ArrayBuffer)
    })

    it('should return a RSASSA-PKCS1-v1_5 SHA-1 signature', () => {
      Buffer.from(rsa1.sign(RsaPrivateCryptoKeySHA1, data))
        .should.eql(Buffer.from(signatureSHA1.buffer))
    })

    it('should return a RSASSA-PKCS1-v1_5 SHA-256 signature', () => {
      Buffer.from(rsa256.sign(RsaPrivateCryptoKeySHA256, data))
        .should.eql(Buffer.from(signatureSHA256.buffer))
    })

    it('should return a RSASSA-PKCS1-v1_5 SHA-384 signature', () => {
      Buffer.from(rsa384.sign(RsaPrivateCryptoKeySHA384, data))
        .should.eql(Buffer.from(signatureSHA384.buffer))
    })

    it('should return a RSASSA-PKCS1-v1_5 SHA-512 signature', () => {
      Buffer.from(rsa512.sign(RsaPrivateCryptoKeySHA512, data))
        .should.eql(Buffer.from(signatureSHA512.buffer))
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
      let data, 
        rsa1,
        rsa256,
        rsa384,
        rsa512,
        signatureSHA1, 
        signatureSHA256, 
        signatureSHA384,
        signatureSHA512

    before(() => {
      rsa1 = new RSASSA_PKCS1_v1_5({ name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-1' }})
      rsa256 = new RSASSA_PKCS1_v1_5({ name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' }})
      rsa384 = new RSASSA_PKCS1_v1_5({ name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-384' }})
      rsa512 = new RSASSA_PKCS1_v1_5({ name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-512' }})

      data = new TextEncoder().encode('signed with Chrome webcrypto')

      signatureSHA1 = new Uint8Array([
        127,216,28,63,83,35,34,208,245,91,207,119,10,184,129,202,
        139,66,206,41,38,172,58,191,191,192,170,0,50,252,203,79,122,
        189,47,152,221,146,48,67,138,202,133,8,129,52,124,23,54,221,
        74,255,46,115,31,175,254,168,16,54,106,148,120,155,95,209,
        239,49,224,192,150,248,194,219,147,147,125,115,196,40,254,
        13,36,115,150,178,102,249,182,214,61,30,134,186,50,187,244,
        120,160,29,208,130,92,192,213,98,166,182,109,179,67,120,99,
        142,173,192,83,1,151,56,236,123,92,232,170,145,139,7,170,135,
        54,18,177,153,63,6,130,239,175,165,64,78,154,125,150,185,47,
        92,113,83,169,254,192,127,102,214,36,173,94,39,123,58,137,2,
        108,12,202,141,26,72,95,4,235,54,187,254,90,7,4,202,109,197,
        16,16,98,205,96,250,74,234,136,108,154,231,19,213,145,97,166,
        68,145,210,203,141,107,42,86,116,111,28,68,211,252,202,204,
        219,96,183,3,98,113,51,196,140,164,123,226,223,194,186,161,
        194,39,115,227,85,167,219,182,201,34,84,63,69,139,198,150,
        141,163,227,34,215,156,56,98,21
      ])
      signatureSHA256 = new Uint8Array([
        84, 181, 186, 121, 235, 76, 199, 102, 174, 125, 176, 216, 94, 190,
        243, 201, 219, 114, 227, 61, 54, 194, 237, 14, 248, 204, 120, 109,
        249, 220, 229, 80, 44, 48, 86, 133, 96, 129, 85, 213, 70, 19, 126,
        0, 160, 91, 18, 185, 200, 102, 180, 181, 69, 27, 162, 181, 189, 110,
        188, 112, 124, 93, 57, 208, 91, 142, 182, 192, 87, 167, 193, 111,
        88, 5, 244, 108, 200, 150, 133, 68, 144, 208, 27, 155, 222, 213, 189,
        224, 156, 226, 124, 65, 178, 69, 71, 63, 243, 141, 3, 126, 209, 237,
        45, 179, 240, 255, 194, 245, 43, 148, 123, 97, 172, 239, 168, 221,
        44, 186, 72, 194, 29, 9, 171, 103, 125, 182, 39, 95, 163, 80, 3, 208,
        184, 184, 48, 114, 135, 7, 111, 114, 38, 25, 28, 234, 82, 18, 49, 113,
        20, 251, 59, 147, 206, 7, 134, 15, 189, 201, 253, 241, 120, 236, 58,
        235, 148, 27, 204, 233, 165, 31, 27, 223, 28, 10, 214, 159, 109, 186,
        239, 71, 126, 18, 63, 111, 198, 115, 226, 237, 145, 26, 12, 120, 56,
        166, 13, 195, 65, 11, 114, 149, 145, 255, 242, 97, 190, 255, 202, 219,
        144, 83, 238, 240, 182, 82, 165, 229, 118, 146, 29, 95, 127, 76, 188,
        247, 138, 254, 72, 18, 251, 42, 118, 156, 229, 66, 8, 106, 55, 106,
        83, 232, 234, 23, 195, 160, 167, 133, 14, 181, 126, 5, 36, 157, 2, 81,
        144, 83
      ])
      signatureSHA384 = new Uint8Array([
        21,153,55,225,112,89,64,99,7,223,198,5,88,40,109,185,100,147,36,
        146,188,103,131,247,20,84,227,185,14,55,5,48,253,39,179,227,168,
        118,94,230,243,115,28,153,185,140,129,238,38,185,168,43,113,4,48,
        112,236,65,242,19,60,56,250,127,20,116,45,137,123,24,81,88,219,
        181,124,87,139,60,107,74,2,192,19,155,225,115,169,246,76,168,24,
        45,111,53,231,173,213,3,187,168,216,37,47,116,133,180,76,184,88,
        251,156,96,197,159,127,215,166,244,39,195,169,103,15,139,182,206,
        192,181,32,35,18,197,99,90,48,45,33,237,89,186,201,46,147,122,30,
        78,246,173,98,47,34,92,7,197,159,205,121,150,238,169,89,212,66,
        134,141,194,237,214,81,171,30,159,15,35,117,39,34,47,78,122,161,
        160,21,212,112,153,129,74,79,206,117,95,161,15,66,106,48,247,199,
        96,230,136,139,87,144,239,64,234,218,143,78,145,85,3,157,135,245,
        38,155,7,174,78,157,2,20,36,160,151,205,4,172,238,20,130,129,229,
        130,26,7,177,210,20,72,39,74,66,240,168,224,121,142,128,14,204,
        114,190
      ])
      signatureSHA512 = new Uint8Array([
        4,158,87,2,1,45,7,135,46,182,165,62,255,35,13,36,73,13,129,70,162,
        147,210,17,218,88,16,176,243,63,97,255,26,184,128,7,148,56,46,63,
        113,52,71,149,189,255,91,195,209,1,129,39,128,24,255,109,250,80,16,
        240,38,152,10,227,38,153,110,14,32,153,103,222,48,215,89,48,118,46,
        172,245,13,200,125,196,27,101,13,251,223,91,128,245,30,158,22,233,
        78,129,125,168,49,211,195,50,120,189,250,29,54,102,58,5,168,81,241,
        252,9,168,138,36,92,233,24,246,103,82,39,200,10,142,168,83,150,243,
        91,83,120,149,109,163,184,155,155,116,72,251,120,146,62,119,134,194,
        12,250,195,21,92,49,196,120,100,85,125,26,5,86,89,83,102,89,249,228,
        251,50,181,101,109,130,199,222,237,198,195,190,142,166,94,78,71,24,
        145,101,199,239,212,125,235,110,43,191,235,176,233,97,52,24,205,93,
        101,144,107,122,14,27,108,202,20,43,227,151,8,181,209,3,181,68,35,
        14,171,17,142,67,215,135,65,39,245,152,103,106,26,53,56,207,78,93,
        181,160,196,6,25,200,4,59,48,83
      ])
    })

    it('should throw with non-private key', () => {
      expect(() => {
        rsa256.verify(RsaPrivateCryptoKeySHA256, new Uint8Array())
      }).to.throw('Verifying requires a public key')
    })

    it('should return false with invalid signature', () => {
      let invalidData = new TextEncoder().encode('invalid signature')
      rsa256.verify(RsaPublicCryptoKeySHA256, signatureSHA256, invalidData).should.equal(false)
    })

    it('should return true with valid SHA-1 signature', () => {
      rsa1.verify(RsaPublicCryptoKeySHA1, signatureSHA1, data).should.equal(true)
    })

    it('should return true with valid SHA-256 signature', () => {
      rsa256.verify(RsaPublicCryptoKeySHA256, signatureSHA256, data).should.equal(true)
    })

    it('should return true with valid SHA-384 signature', () => {
      rsa384.verify(RsaPublicCryptoKeySHA384, signatureSHA384, data).should.equal(true)
    })

    it('should return true with valid SHA-512 signature', () => {
      rsa512.verify(RsaPublicCryptoKeySHA512, signatureSHA512, data).should.equal(true)
    })
  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    let alg, rsa, cryptoKeyPair

    before(() => {
      alg = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, hash: { name: 'SHA-256' } }
      rsa = new RSASSA_PKCS1_v1_5(alg)
      return Promise.resolve()
        .then(() => cryptoKeyPair = rsa.generateKey(alg, true, ['sign', 'verify']))

    })

    it('should throw with invalid usages', () => {
      expect(() => {
        rsa.generateKey(alg, true, ['sign', 'verify', 'wrong'])
      }).to.throw('Key usages can only include "sign" and "verify"')
    })

    it('should return CryptoKey', () => {
      cryptoKeyPair.should.be.instanceof(CryptoKeyPair)
    })

    it('should set public key type', () => {
      cryptoKeyPair.publicKey.type.should.equal('public')
    })

    it('should set private key type', () => {
      cryptoKeyPair.privateKey.type.should.equal('private')
    })

    it('should set public key algorithm', () => {
      cryptoKeyPair.publicKey.algorithm
        .should.be.instanceof(RSASSA_PKCS1_v1_5)
    })

    it('should set private key algorithm', () => {
      cryptoKeyPair.privateKey.algorithm
        .should.be.instanceof(RSASSA_PKCS1_v1_5)
    })

    it('should set public key algorithm name', () => {
      cryptoKeyPair.publicKey.algorithm.name
        .should.equal('RSASSA-PKCS1-v1_5')
    })

    it('should set private key algorithm name', () => {
      cryptoKeyPair.privateKey.algorithm.name
        .should.equal('RSASSA-PKCS1-v1_5')
    })

    //it('should set public key algorithm hash', () => {
    //  cryptoKeyPair.publicKey.algorithm.hash
    //    .should.be.instanceof(KeyAlgorithm)
    //})

    //it('should set private key algorithm hash', () => {
    //  cryptoKeyPair.privateKey.algorithm.hash
    //    .should.be.instanceof(KeyAlgorithm)
    //})

    it('should set public key algorithm hash name', () => {
      cryptoKeyPair.publicKey.algorithm.hash.name
        .should.equal('SHA-256')
    })

    it('should set private key algorithm hash name', () => {
      cryptoKeyPair.privateKey.algorithm.hash.name
        .should.equal('SHA-256')
    })

    it('should set public key extractable', () => {
      cryptoKeyPair.publicKey.extractable.should.equal(true)
    })

    it('should set private key extractable', () => {
      cryptoKeyPair.privateKey.extractable.should.equal(true)
    })

    it('should set public key usages', () => {
      cryptoKeyPair.publicKey.usages.should.eql(['verify'])
    })

    it('should set private key usages', () => {
      cryptoKeyPair.privateKey.usages.should.eql(['sign'])
    })

    it('should set public key handle', () => {
      cryptoKeyPair.publicKey.handle
        .should.include('-----BEGIN PUBLIC KEY-----')
    })

    it('should set private key handle', () => {
      cryptoKeyPair.privateKey.handle
        .should.include('-----BEGIN RSA PRIVATE KEY-----')
    })
  })

  /**
   * importKey
   */
  describe('importKey', () => {
    describe('with "spki" format', () => {})
    describe('with "pkcs8 format"', () => {})

    describe('with "jwk" format', () => {
      describe('private key and invalid usages', () => {
        let key, alg

        before(() => {
          key = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            d: "FAKE",
            alg: "RS256",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw SyntaxError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['bad'])
          }).to.throw('Key usages must include "sign"')
        })
      })

      describe('non-private key and invalid usages', () => {
        let key, alg

        before(() => {
          key = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS256",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw SyntaxError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['bad'])
          }).to.throw('Key usages must include "verify"')
        })
      })

      describe('invalid key type', () => {
        let key, alg

        before(() => {
          key = {
            kty: "WRONG",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS256",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['verify'])
          }).to.throw('Key type must be RSA')
        })
      })

      describe('invalid key use', () => {
        let key, alg

        before(() => {
          key = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS256",
            use: "WRONG",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['verify'])
          }).to.throw('Key use must be "sig"')
        })
      })

      describe('RS1 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS1",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-1 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-1')
        })
      })

      describe('RS256 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS256",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-256 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-256')
        })
      })

      describe('RS384 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS384",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-384 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-384')
        })
      })

      describe('RS512 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS512",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-512 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-512')
        })
      })

      describe('invalid key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "WTF",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', jwk, alg, false, ['verify'])
          }).to.throw('Key alg must be "RS1", "RS256", "RS384", or "RS512"')
        })
      })

      describe.skip('undefined key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            ext: true
          }

          alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should not define hash', () => {
          expect(key.algorithm.hash).to.be.undefined
        })
      })

      describe('private RSA key', () => {
        let key, alg

        before(() => {
          alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', RsaPrivateJwk, alg, false, ['sign'])
        })

        it('should define type', () => {
          key.type.should.equal('private')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(RSASSA_PKCS1_v1_5)
        })

        it('should define modulusLength', () => {
          key.algorithm.modulusLength.should.eql(2048)
        })

        it('should define publicExponent', () => {
          key.algorithm.publicExponent.should.eql(new Uint8Array([0x01, 0x00, 0x01]))
        })

        it('should define extractable', () => {
          key.extractable.should.equal(false)
        })

        it('should define usages', () => {
          key.usages.should.eql(['sign'])
        })

        it('should define handle', () => {
          key.handle.should.contain('-----BEGIN RSA PRIVATE KEY-----')
        })
      })

      describe('public RSA key', () => {
        let key, alg

        before(() => {
          alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', RsaPublicJwk, alg, false, ['verify'])
        })

        it('should define type', () => {
          key.type.should.equal('public')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(RSASSA_PKCS1_v1_5)
        })

        it('should define modulusLength', () => {
          key.algorithm.modulusLength.should.eql(2048)
        })

        it('should define publicExponent', () => {
          key.algorithm.publicExponent.should.eql(new Uint8Array([0x01, 0x00, 0x01]))
        })

        it('should define extractable', () => {
          key.extractable.should.equal(true)
        })

        it('should define usages', () => {
          key.usages.should.eql(['verify'])
        })

        it('should define handle', () => {
          key.handle.should.contain('-----BEGIN PUBLIC KEY-----')
        })
      })
    })

    describe('with other format', () => {
      it('should throw NotSupportedError', () => {
        let alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })

        let caller = () => {
          alg.importKey('WRONG', RsaPublicJwk, alg, false, ['verify'])
        }

        expect(caller).to.throw(NotSupportedError)
        expect(caller).to.throw('is not a supported key format')
      })
    })
  })

  /**
   * exportKey
   */
  describe('exportKey', () => {
    describe('with missing key material', () => {
      it('should throw OperationError', () => {
        expect(() => {
          let alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          alg.exportKey('format', {})
        }).to.throw('Missing key material')
      })
    })

    describe('with "spki" format', () => {})
    describe('with "pkcs8 format"', () => {})

    describe('with "jwk" format', () => {
      describe('SHA-1 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-1' } },
            extractable: true,
            usages: ['verify'],
            handle: RsaPublicKey
          })

          let alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RS1"', () => {
          jwk.alg.should.equal('RS1')
        })
      })

      describe('SHA-256 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-256' } },
            extractable: true,
            usages: ['verify'],
            handle: RsaPublicKey
          })

          let alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RS256"', () => {
          jwk.alg.should.equal('RS256')
        })
      })

      describe('SHA-384 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-384' } },
            extractable: true,
            usages: ['verify'],
            handle: RsaPublicKey
          })

          let alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RS384"', () => {
          jwk.alg.should.equal('RS384')
        })
      })

      describe('SHA-512 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-512' } },
            extractable: true,
            usages: ['verify'],
            handle: RsaPublicKey
          })

          let alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RS512"', () => {
          jwk.alg.should.equal('RS512')
        })
      })

      describe('other hash', () => {})
    })

    describe('with other format', () => {
      it('should throw NotSupportedError', () => {
        let key = new CryptoKey({
          type: 'public',
          algorithm: {},
          extractable: true,
          usages: ['verify'],
          handle: RsaPublicKey

        })

        let alg = new RSASSA_PKCS1_v1_5({ name: 'RSASSA-PKCS1-v1_5' })

        let caller = () => {
          alg.exportKey('WRONG', key)
        }

        expect(caller).to.throw(NotSupportedError)
        expect(caller).to.throw('is not a supported key format')
      })
    })
  })