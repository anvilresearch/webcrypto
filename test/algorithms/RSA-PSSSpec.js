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
} = require('../RsaKeyPairForPSSTesting')

const crypto = require('../../src')
const CryptoKey = require('../../src/keys/CryptoKey')
const CryptoKeyPair = require('../../src/keys/CryptoKeyPair')
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const RsaKeyAlgorithm = require('../../src/dictionaries/RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('../../src/dictionaries/RsaHashedKeyAlgorithm')
const RSA_PSS = require('../../src/algorithms/RSA-PSS')
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
      RSA_PSS.dictionaries.should.eql([
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
      RSA_PSS.members.publicExponent.should.equal('BufferSource')
      RSA_PSS.members.hash.should.equal('HashAlgorithmIdentifier')
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
      rsa1 = new RSA_PSS({ name: "RSA-PSS", hash: { name: 'SHA-1' }, saltLength:128 })
      rsa256 = new RSA_PSS({ name: "RSA-PSS", hash: { name: 'SHA-256' }, saltLength:128 })
      rsa384 = new RSA_PSS({ name: "RSA-PSS", hash: { name: 'SHA-384' }, saltLength:128 })
      rsa512 = new RSA_PSS({ name: "RSA-PSS", hash: { name: 'SHA-512' }, saltLength:128 })

      data = new TextEncoder().encode('signed with Chrome webcrypto')

      signatureSHA1 = new Uint8Array([
        106,72,85,203,236,250,251,24,235,182,101,41,84,69,124,31,49,152,145,7,136,
        189,121,111,124,89,102,33,83,247,172,99,104,241,202,99,139,60,16,215,205,
        211,158,56,183,2,36,126,25,230,117,110,176,14,13,215,204,218,140,160,166,
        148,149,191,60,244,179,23,124,34,194,4,32,62,118,27,241,42,19,9,226,176,
        230,104,15,144,17,229,182,43,10,89,154,221,181,222,120,114,168,23,86,4,
        114,45,73,72,96,160,237,51,136,131,4,145,54,144,192,191,123,225,23,213,235,
        121,198,61,54,162,28,126,104,20,123,70,39,173,201,41,232,231,211,113,74,
        116,179,108,241,168,131,89,99,187,201,6,80,18,204,230,150,102,55,126,29,
        224,252,26,66,49,244,164,163,187,182,118,251,228,107,81,199,151,206,223,
        236,82,146,41,145,175,160,64,21,158,119,205,228,169,2,201,14,46,75,237,157,
        22,83,128,43,83,140,14,133,125,234,253,243,83,232,145,192,22,121,173,194,
        179,64,134,217,52,79,164,29,117,229,231,201,1,161,233,148,143,45,170,115,
        151,188,110,40,201,7,19,167,206,66,179,157,166
      ]) 

      signatureSHA256 = new Uint8Array([
        125,62,110,162,81,189,84,124,6,128,24,121,105,62,151,102,224,113,59,
        113,147,64,65,194,190,53,225,5,97,158,120,193,192,12,216,137,232,192,
        22,184,142,237,44,1,111,108,183,0,1,216,215,114,11,145,224,178,122,
        227,99,151,107,40,17,22,207,108,234,141,44,155,82,214,129,234,248,
        75,77,242,201,11,240,157,167,151,61,213,120,255,15,28,232,161,209,
        229,81,79,83,108,48,141,157,12,55,53,43,223,119,196,127,227,230,255,
        240,51,207,55,197,73,195,86,249,130,179,173,102,187,210,70,199,202,
        20,53,83,200,175,197,137,224,70,18,35,231,59,219,119,185,180,64,186,
        140,54,188,200,105,15,142,181,148,187,30,115,90,17,169,58,128,180,77,
        93,37,215,216,135,139,134,190,176,185,233,112,35,82,64,158,250,165,11,
        40,140,26,21,148,57,129,207,169,52,70,158,87,55,38,47,189,17,81,187,
        195,127,142,161,205,127,44,168,53,75,85,14,49,160,227,156,130,210,159,
        8,159,238,192,105,165,195,150,217,118,64,167,113,215,136,7,110,231,224,
        111,127,34,48,243,216,233,37,95,240,20
      ])

      signatureSHA384 = new Uint8Array([
        7,209,224,125,70,61,157,196,171,235,111,163,88,171,190,70,134,216,253,62,
        163,124,28,174,136,175,191,198,238,213,65,4,172,152,202,42,101,190,87,159,
        165,5,107,252,28,45,147,190,98,91,128,115,232,206,33,238,23,245,122,86,167,
        16,239,21,188,28,58,208,248,92,147,164,245,254,76,83,8,41,72,96,222,230,
        140,28,248,120,111,228,69,229,5,21,210,35,108,40,145,159,142,133,75,226,
        134,54,182,156,35,112,108,44,20,14,8,94,160,250,79,116,57,226,32,109,211,
        80,68,160,55,39,152,189,118,195,212,241,183,199,195,190,71,78,178,70,22,
        76,128,224,104,234,128,40,104,37,148,166,34,158,154,225,179,38,197,123,
        246,167,137,226,44,242,90,179,53,164,242,76,235,247,235,215,78,198,9,191,
        253,137,46,213,121,83,38,160,168,229,129,21,140,204,205,37,61,144,27,254,
        175,189,44,230,26,69,228,182,57,51,32,63,108,123,227,139,113,38,229,173,
        121,98,193,76,220,95,235,89,122,120,182,112,20,121,167,249,48,132,80,52,
        40,153,60,133,175,132,118,184,0,233,49,155,39,121
      ])

      signatureSHA512 = new Uint8Array([
        75,151,232,209,207,40,6,156,129,0,77,63,171,160,14,6,186,187,192,149,244,120,
        136,30,25,69,16,155,35,174,28,43,216,85,71,145,36,242,35,248,239,44,223,71,
        252,129,22,202,184,156,114,88,56,57,7,171,37,64,170,30,98,53,96,164,149,124,
        212,224,87,184,182,147,241,203,219,138,15,229,9,45,42,86,224,72,52,23,126,
        148,53,40,137,61,40,162,97,203,138,146,49,60,65,99,68,240,107,253,4,127,16,
        30,241,248,22,87,77,117,167,150,159,67,250,194,151,80,106,172,110,125,148,
        198,30,179,15,69,187,14,127,195,139,165,140,216,138,178,75,27,246,164,115,
        88,15,105,66,59,7,185,56,92,176,21,39,10,178,133,40,114,138,37,227,180,241,
        160,90,156,173,155,156,73,77,39,200,147,175,151,165,70,62,103,151,70,27,87,
        146,203,162,242,15,102,117,72,178,145,49,211,77,171,130,19,110,182,154,212,
        115,211,64,198,111,254,9,23,61,128,119,9,24,80,129,26,251,0,37,142,205,134,
        143,144,97,175,37,200,93,64,58,106,230,4,77,233,131,80,168,107,173,11,177,128
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

    /*
    // These tests will not result in matching signatures since the data is salted by a random generated
    // salt of specified saltLength. Hence the resulting signatures will (or should) always differ
    // Unless these is a way to specificy the exact salt there is no way to consistantly test this
    // use case except through generating the signature natively, and verifying it in Chrome
    // (Which is manually tested before each npm release)

    it('should return a RSA-PSS SHA-1 signature', () => {
      Buffer.from(rsa1.sign(RsaPrivateCryptoKeySHA1, data))
        .should.eql(Buffer.from(signatureSHA1.buffer))
    })

    it('should return a RSA-PSS SHA-256 signature', () => {
      Buffer.from(rsa256.sign(RsaPrivateCryptoKeySHA256, data))
        .should.eql(Buffer.from(signatureSHA256.buffer))
    })

    it('should return a RSA-PSS SHA-384 signature', () => {
      Buffer.from(rsa384.sign(RsaPrivateCryptoKeySHA384, data))
        .should.eql(Buffer.from(signatureSHA384.buffer))
    })

    it('should return a RSA-PSS SHA-512 signature', () => {
      Buffer.from(rsa512.sign(RsaPrivateCryptoKeySHA512, data))
        .should.eql(Buffer.from(signatureSHA512.buffer))
    })*/

    it('should return a correct length RSA-PSS SHA-1 signature', () => {
      Buffer.from(rsa1.sign(RsaPrivateCryptoKeySHA1, data)).length
        .should.eql(256)
    })

    it('should return a correct length RSA-PSS SHA-256 signature', () => {
      Buffer.from(rsa256.sign(RsaPrivateCryptoKeySHA256, data)).length
        .should.eql(256)
    })

    it('should return a correct length RSA-PSS SHA-384 signature', () => {
      Buffer.from(rsa384.sign(RsaPrivateCryptoKeySHA384, data)).length
        .should.eql(256)
    })

    it('should return a correct length RSA-PSS SHA-512 signature', () => {
      Buffer.from(rsa512.sign(RsaPrivateCryptoKeySHA512, data)).length
        .should.eql(256)
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
      rsa1 = new RSA_PSS({ name: "RSA-PSS", hash: { name: 'SHA-1' }, saltLength:128 })
      rsa256 = new RSA_PSS({ name: "RSA-PSS", hash: { name: 'SHA-256' }, saltLength:128 })
      rsa384 = new RSA_PSS({ name: "RSA-PSS", hash: { name: 'SHA-384' }, saltLength:128 })
      rsa512 = new RSA_PSS({ name: "RSA-PSS", hash: { name: 'SHA-512' }, saltLength:128 })

      data = new TextEncoder().encode('signed with Chrome webcrypto')

      signatureSHA1 = new Uint8Array([
        106,72,85,203,236,250,251,24,235,182,101,41,84,69,124,31,49,152,145,7,136,
        189,121,111,124,89,102,33,83,247,172,99,104,241,202,99,139,60,16,215,205,
        211,158,56,183,2,36,126,25,230,117,110,176,14,13,215,204,218,140,160,166,
        148,149,191,60,244,179,23,124,34,194,4,32,62,118,27,241,42,19,9,226,176,
        230,104,15,144,17,229,182,43,10,89,154,221,181,222,120,114,168,23,86,4,
        114,45,73,72,96,160,237,51,136,131,4,145,54,144,192,191,123,225,23,213,235,
        121,198,61,54,162,28,126,104,20,123,70,39,173,201,41,232,231,211,113,74,
        116,179,108,241,168,131,89,99,187,201,6,80,18,204,230,150,102,55,126,29,
        224,252,26,66,49,244,164,163,187,182,118,251,228,107,81,199,151,206,223,
        236,82,146,41,145,175,160,64,21,158,119,205,228,169,2,201,14,46,75,237,157,
        22,83,128,43,83,140,14,133,125,234,253,243,83,232,145,192,22,121,173,194,
        179,64,134,217,52,79,164,29,117,229,231,201,1,161,233,148,143,45,170,115,
        151,188,110,40,201,7,19,167,206,66,179,157,166
      ]) 

      signatureSHA256 = new Uint8Array([
        125,62,110,162,81,189,84,124,6,128,24,121,105,62,151,102,224,113,59,
        113,147,64,65,194,190,53,225,5,97,158,120,193,192,12,216,137,232,192,
        22,184,142,237,44,1,111,108,183,0,1,216,215,114,11,145,224,178,122,
        227,99,151,107,40,17,22,207,108,234,141,44,155,82,214,129,234,248,
        75,77,242,201,11,240,157,167,151,61,213,120,255,15,28,232,161,209,
        229,81,79,83,108,48,141,157,12,55,53,43,223,119,196,127,227,230,255,
        240,51,207,55,197,73,195,86,249,130,179,173,102,187,210,70,199,202,
        20,53,83,200,175,197,137,224,70,18,35,231,59,219,119,185,180,64,186,
        140,54,188,200,105,15,142,181,148,187,30,115,90,17,169,58,128,180,77,
        93,37,215,216,135,139,134,190,176,185,233,112,35,82,64,158,250,165,11,
        40,140,26,21,148,57,129,207,169,52,70,158,87,55,38,47,189,17,81,187,
        195,127,142,161,205,127,44,168,53,75,85,14,49,160,227,156,130,210,159,
        8,159,238,192,105,165,195,150,217,118,64,167,113,215,136,7,110,231,224,
        111,127,34,48,243,216,233,37,95,240,20
      ])

      signatureSHA384 = new Uint8Array([
        7,209,224,125,70,61,157,196,171,235,111,163,88,171,190,70,134,216,253,62,
        163,124,28,174,136,175,191,198,238,213,65,4,172,152,202,42,101,190,87,159,
        165,5,107,252,28,45,147,190,98,91,128,115,232,206,33,238,23,245,122,86,167,
        16,239,21,188,28,58,208,248,92,147,164,245,254,76,83,8,41,72,96,222,230,
        140,28,248,120,111,228,69,229,5,21,210,35,108,40,145,159,142,133,75,226,
        134,54,182,156,35,112,108,44,20,14,8,94,160,250,79,116,57,226,32,109,211,
        80,68,160,55,39,152,189,118,195,212,241,183,199,195,190,71,78,178,70,22,
        76,128,224,104,234,128,40,104,37,148,166,34,158,154,225,179,38,197,123,
        246,167,137,226,44,242,90,179,53,164,242,76,235,247,235,215,78,198,9,191,
        253,137,46,213,121,83,38,160,168,229,129,21,140,204,205,37,61,144,27,254,
        175,189,44,230,26,69,228,182,57,51,32,63,108,123,227,139,113,38,229,173,
        121,98,193,76,220,95,235,89,122,120,182,112,20,121,167,249,48,132,80,52,
        40,153,60,133,175,132,118,184,0,233,49,155,39,121
      ])

      signatureSHA512 = new Uint8Array([
        75,151,232,209,207,40,6,156,129,0,77,63,171,160,14,6,186,187,192,149,244,120,
        136,30,25,69,16,155,35,174,28,43,216,85,71,145,36,242,35,248,239,44,223,71,
        252,129,22,202,184,156,114,88,56,57,7,171,37,64,170,30,98,53,96,164,149,124,
        212,224,87,184,182,147,241,203,219,138,15,229,9,45,42,86,224,72,52,23,126,
        148,53,40,137,61,40,162,97,203,138,146,49,60,65,99,68,240,107,253,4,127,16,
        30,241,248,22,87,77,117,167,150,159,67,250,194,151,80,106,172,110,125,148,
        198,30,179,15,69,187,14,127,195,139,165,140,216,138,178,75,27,246,164,115,
        88,15,105,66,59,7,185,56,92,176,21,39,10,178,133,40,114,138,37,227,180,241,
        160,90,156,173,155,156,73,77,39,200,147,175,151,165,70,62,103,151,70,27,87,
        146,203,162,242,15,102,117,72,178,145,49,211,77,171,130,19,110,182,154,212,
        115,211,64,198,111,254,9,23,61,128,119,9,24,80,129,26,251,0,37,142,205,134,
        143,144,97,175,37,200,93,64,58,106,230,4,77,233,131,80,168,107,173,11,177,128
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
      alg = { name: 'RSA-PSS', modulusLength: 2048, hash: { name: 'SHA-256' } }
      rsa = new RSA_PSS(alg)
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
        .should.be.instanceof(RSA_PSS)
    })

    it('should set private key algorithm', () => {
      cryptoKeyPair.privateKey.algorithm
        .should.be.instanceof(RSA_PSS)
    })

    it('should set public key algorithm name', () => {
      cryptoKeyPair.publicKey.algorithm.name
        .should.equal('RSA-PSS')
    })

    it('should set private key algorithm name', () => {
      cryptoKeyPair.privateKey.algorithm.name
        .should.equal('RSA-PSS')
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
            alg: "PS256",
            ext: true
          }

          alg = new RSA_PSS({
            name: 'RSA-PSS',
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
            alg: "PS256",
            ext: true
          }

          alg = new RSA_PSS({
            name: 'RSA-PSS',
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
            alg: "PS256",
            ext: true
          }

          alg = new RSA_PSS({
            name: 'RSA-PSS',
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
            alg: "PS256",
            use: "WRONG",
            ext: true
          }

          alg = new RSA_PSS({
            name: 'RSA-PSS',
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

      describe('PS1 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "PS1",
            ext: true
          }

          alg = new RSA_PSS({ name: 'RSA-PSS' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-1 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-1')
        })
      })

      describe('PS256 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "PS256",
            ext: true
          }

          alg = new RSA_PSS({ name: 'RSA-PSS' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-256 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-256')
        })
      })

      describe('PS384 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "PS384",
            ext: true
          }

          alg = new RSA_PSS({ name: 'RSA-PSS' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-384 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-384')
        })
      })

      describe('PS512 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "PS512",
            ext: true
          }

          alg = new RSA_PSS({ name: 'RSA-PSS' })
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

          alg = new RSA_PSS({ name: 'RSA-PSS' })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', jwk, alg, false, ['verify'])
          }).to.throw('Key alg must be "PS1", "PS256", "PS384", or "PS512"')
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

          alg = new RSA_PSS({ name: 'RSA-PSS' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should not define hash', () => {
          expect(key.algorithm.hash).to.be.undefined
        })
      })

      describe('private RSA key', () => {
        let key, alg

        before(() => {
          alg = new RSA_PSS({ name: 'RSA-PSS' })
          key = alg.importKey('jwk', RsaPrivateJwk, alg, false, ['sign'])
        })

        it('should define type', () => {
          key.type.should.equal('private')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(RSA_PSS)
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
          alg = new RSA_PSS({ name: 'RSA-PSS' })
          key = alg.importKey('jwk', RsaPublicJwk, alg, false, ['verify'])
        })

        it('should define type', () => {
          key.type.should.equal('public')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(RSA_PSS)
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
        let alg = new RSA_PSS({ name: 'RSA-PSS' })

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
          let alg = new RSA_PSS({ name: 'RSA-PSS' })
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

          let alg = new RSA_PSS({ name: 'RSA-PSS' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "PS1"', () => {
          jwk.alg.should.equal('PS1')
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

          let alg = new RSA_PSS({ name: 'RSA-PSS' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "PS256"', () => {
          jwk.alg.should.equal('PS256')
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

          let alg = new RSA_PSS({ name: 'RSA-PSS' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "PS384"', () => {
          jwk.alg.should.equal('PS384')
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

          let alg = new RSA_PSS({ name: 'RSA-PSS' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "PS512"', () => {
          jwk.alg.should.equal('PS512')
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

        let alg = new RSA_PSS({ name: 'RSA-PSS' })

        let caller = () => {
          alg.exportKey('WRONG', key)
        }

        expect(caller).to.throw(NotSupportedError)
        expect(caller).to.throw('is not a supported key format')
      })
    })
  })