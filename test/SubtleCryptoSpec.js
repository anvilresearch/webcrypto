/**
 * Test dependencies
 */
const chai = require('chai')
const expect = chai.expect

/**
 * Assertions
 */
chai.should()

/**
 * Code under test
 */
const crypto = require('../src')
const CryptoKey = require('../src/keys/CryptoKey')
const CryptoKeyPair = require('../src/keys/CryptoKeyPair')
const JsonWebKey = require('../src/keys/JsonWebKey')
const RSASSA_PKCS1_v1_5 = require('../src/algorithms/RSASSA-PKCS1-v1_5')
const AES_CBC = require('../src/algorithms/AES-CBC')
const AES_GCM = require('../src/algorithms/AES-GCM')
const {TextEncoder,TextDecoder} = require('text-encoding')

/**
 * RSA Key Pair for testing
 */
const {
  RsaPrivateKey,
  RsaPrivateJwk,
  RsaPrivateCryptoKeySHA256,
  RsaPublicKey,
  RsaPublicJwk,
  RsaPublicCryptoKeySHA256
} = require('./RsaKeyPairForTesting')


/**
 * Test code for AES-GCM
 */
const good_iv =  Buffer.from([ 220, 29, 37, 164, 41, 84, 153, 197, 157, 122, 156, 254, 196, 161, 114, 74 ])

/**
 * Tests
 */
describe('SubtleCrypto', () => {

  /**
   * encrypt
   */
  describe('encrypt', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        let key = new CryptoKey({})
        let data = new ArrayBuffer()

        promise = crypto.subtle.encrypt(algorithm, key, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

  describe('with mismatched algorithm name', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'AES-CBC' }
        let key = new CryptoKey({ algorithm: { name: 'AES-CCC' } })
        let data = new ArrayBuffer()

        promise = crypto.subtle.encrypt(algorithm, key, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Algorithm does not match key')
      })
    })

  describe('with invalid usages', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'AES-CBC' }

        let key = new CryptoKey({
          algorithm: { name: 'AES-CBC', length: 128 },
          usages: ['decrypt']
        })

        let data = new ArrayBuffer()

        promise = crypto.subtle.encrypt(algorithm, key, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Key usages must include "encrypt"')
      })
    })

    describe('with valid arguments', () => {
      let algorithm,aes, key, iv, promise, result, signature, error

      beforeEach((done) => {

        aes = new AES_CBC({ name: 'AES-CBC', length: 256}) 
        i =  Buffer.from([ 220, 29, 37, 164, 41, 84, 153, 197, 157, 122, 156, 254, 196, 161, 114, 74 ])
        algorithm = { name: 'AES-CBC', iv:i }
        key = aes.importKey(
            "jwk", 
            {   
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true,
            },
            {   
                name: "AES-CBC",
            },
            true, 
            ["encrypt","decrypt"] 
        )
        let data = new TextEncoder().encode('signed with Chrome Webcrypto')

        signature = new Uint8Array([
            76, 82, 211, 155, 13, 154, 24, 6, 156, 203, 50, 
            171, 210, 17, 88, 145, 32, 225, 125, 119, 179, 
            197, 224, 210, 122, 43, 255, 159, 59, 195, 206, 210])

        promise = crypto.subtle
          .encrypt(algorithm, key, data)
          .then(res => {
            result = res 
            done()
          })
          .catch(err => {
            error = err 
            done()  
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve an ArrayBuffer', () => {
        result.should.be.instanceof(ArrayBuffer)
      })

      it('should resolve a correct encryption for the data and key', () => {
        Buffer.from(result).should.eql(Buffer.from(signature.buffer))
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * decrypt
   */
  describe('decrypt', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        let key = new CryptoKey({algorithm})
        let data = new ArrayBuffer()

        promise = crypto.subtle.decrypt(algorithm, key, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with mismatched algorithm name', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'AES-CBC' }
        let key = new CryptoKey({ algorithm: { name: 'AES-CCC' } })
        let data = new ArrayBuffer()

        promise = crypto.subtle.decrypt(algorithm, key, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Algorithm does not match key')
      })
    })

    describe('with invalid usages', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'AES-CBC' }
        let key = new CryptoKey({
          algorithm: { name: 'AES-CBC', length: 128 },
          usages: ['encrypt']
        })
        let data = new ArrayBuffer()

        promise = crypto.subtle.decrypt(algorithm, key, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Key usages must include "decrypt"')
      })
    })

    describe('with valid arguments', () => {
      let algorithm,aes, key, iv, promise, result, signature, error

      beforeEach((done) => {

        aes = new AES_CBC({ name: 'AES-CBC', length: 256}) 
        i =  Buffer.from([ 220, 29, 37, 164, 41, 84, 153, 197, 157, 122, 156, 254, 196, 161, 114, 74 ])
        algorithm = { name: 'AES-CBC', iv:i }
        key = aes.importKey(
            "jwk", 
            {   
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true,
            },
            {   
                name: "AES-CBC",
            },
            true, 
            ["encrypt","decrypt"] 
        )
        let data = new Uint8Array([
            76, 82, 211, 155, 13, 154, 24, 6, 156, 203, 50, 
            171, 210, 17, 88, 145, 32, 225, 125, 119, 179, 
            197, 224, 210, 122, 43, 255, 159, 59, 195, 206, 210])

        signature = new TextEncoder().encode('signed with Chrome Webcrypto')


        promise = crypto.subtle
          .decrypt(algorithm, key,  data)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve a correct decryption for the data and key', () => {
        Buffer.from(result).should.eql(Buffer.from(signature.buffer)) 
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * sign
   */
  describe('sign', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        let privateKey = new CryptoKey({})
        let data = new ArrayBuffer()

        promise = crypto.subtle.sign(algorithm, privateKey, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with mismatched algorithm name', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }
        let privateKey = new CryptoKey({ algorithm: { name: 'RSA-PSS' } })
        let data = new ArrayBuffer()

        promise = crypto.subtle.sign(algorithm, privateKey, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Algorithm does not match key')
      })
    })

    describe('with invalid usages', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }

        let privateKey = new CryptoKey({
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
          usages: ['verify']
        })

        let data = new ArrayBuffer()

        promise = crypto.subtle.sign(algorithm, privateKey, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Key usages must include "sign"')
      })
    })

    describe('with valid arguments', () => {
      let promise, result, signature, error

      beforeEach((done) => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' }}

        let data = new TextEncoder().encode('signed with Chrome webcrypto')

        signature = new Uint8Array([
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

        promise = crypto.subtle
          .sign(algorithm, RsaPrivateCryptoKeySHA256, data)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve an ArrayBuffer', () => {
        result.should.be.instanceof(ArrayBuffer)
      })

      it('should resolve a correct signature for the data and key', () => {
        Buffer.from(result).should.eql(Buffer.from(signature.buffer))
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        let publicKey = new CryptoKey({algorithm})
        let signature = new ArrayBuffer()
        let data = new ArrayBuffer()

        promise = crypto.subtle.verify(algorithm, publicKey, signature, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with mismatched algorithm name', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }
        let publicKey = new CryptoKey({ algorithm: { name: 'RSA-PSS' } })
        let signature = new ArrayBuffer()
        let data = new ArrayBuffer()

        promise = crypto.subtle.verify(algorithm, publicKey, signature, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Algorithm does not match key')
      })
    })

    describe('with invalid usages', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }
        let publicKey = new CryptoKey({
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
          usages: ['sign']
        })
        let signature = new ArrayBuffer()
        let data = new ArrayBuffer()

        promise = crypto.subtle.verify(algorithm, publicKey, signature, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Key usages must include "verify"')
      })
    })

    describe('with valid arguments', () => {
      let promise, result, signature, error

      beforeEach((done) => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' }}

        let data = new TextEncoder().encode('signed with Chrome webcrypto')

        signature = new Uint8Array([
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

        promise = crypto.subtle
          .verify(algorithm, RsaPublicCryptoKeySHA256, signature, data)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.equal(true)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * digest
   */
  describe('digest', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        promise = crypto.subtle.digest(algorithm, new Uint8Array('whatever'))
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with valid arguments', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'SHA-256' }
        promise = crypto.subtle.digest(algorithm, new Buffer('whatever'))
        promise.then(digest => result = digest)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve an ArrayBuffer', () => {
        result.should.be.instanceof(ArrayBuffer)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        promise = crypto.subtle.generateKey(algorithm, false, ['sign', 'verify'])
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    // IS THERE ANY WAY TO TEST THIS WITHOUT SPIES/STUBS?
    // IF THE UNDERLYING ALGORITHMS ARE DOING THE RIGHT THING
    // IT WILL ERROR BEFORE EVER GETTING HERE
    describe('with invalid CryptoKey usages', () => {
      it('should return a promise')
      it('should reject the promise')
    })

    describe('with invalid CryptoKeyPair usages', () => {
      it('should return a promise')
      it('should reject the promise')
    })

    describe('with valid arguments', () => {
      let promise, result, error

      beforeEach((done) => {
        let algorithm = {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 1024,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: 'SHA-256' }
        }

        let extractable = false
        let usages = ['sign', 'verify']

        promise = crypto.subtle
          .generateKey(algorithm, extractable, usages)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.be.instanceof(CryptoKeyPair)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * deriveKey
   */
  describe('deriveKey', () => {
    it('should return a Promise')
  })

  /**
   * deriveBits
   */
  describe('deriveBits', () => {
    it('should return a Promise')
  })

  /**
   * importKey
   */
  describe('importKey', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let format = 'jwk'
        let key = {}
        let algorithm = { name: 'BAD-ALGORITHM' }
        let extractable = false
        let usages = ['verify']

        promise = crypto.subtle.importKey('jwk', key, algorithm, extractable, usages)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with raw format', () => {})
    describe('with pkcs8 format', () => {})
    describe('with spki format', () => {})
    describe('with jwk format', () => {})
    describe('with invalid resulting usages', () => {})

    describe('with valid arguments', () => {
      let promise, result, error

      beforeEach((done) => {
        let key = {
          kty: "RSA",
          e: "AQAB",
          n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
          alg: "RS256",
          ext: true
        }

        let algorithm = {
          name: 'RSASSA-PKCS1-v1_5',
          hash: { name: 'SHA-256' }
        }

        let extractable = true
        let usages = ['sign', 'verify', 'nope']

        promise = crypto.subtle
          .importKey('jwk', key, algorithm, extractable, usages)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.be.instanceof(CryptoKey)
      })

      it('should set extractable', () => {
        result.extractable.should.equal(true)
      })

      it('should normalize key usages', () => {
        result.usages.should.eql(['sign', 'verify'])
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * exportKey
   */
  describe('exportKey', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let format = 'jwk'
        let key = new CryptoKey({
          algorithm: {
            name: 'BAD-ALGORITHM'
          }
        })

        promise = crypto.subtle.exportKey('jwk', key)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with unextractable key', () => {
      let promise, error

      beforeEach(() => {
        let format = 'jwk'
        let key = new CryptoKey({
          type: 'public',
          algorithm: new RSASSA_PKCS1_v1_5({
            name: 'RSASSA-PKCS1-v1_5',
          }),
          extractable: false,
          handle: RsaPrivateKey
        })

        promise = crypto.subtle.exportKey('jwk', key)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Key is not extractable')
      })
    })

    describe('with valid arguments', () => {
      let promise, result, error

      beforeEach((done) => {
        let format = 'jwk'
        let key = new CryptoKey({
          type: 'public',
          algorithm: new RSASSA_PKCS1_v1_5({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          }),
          extractable: true,
          handle: RsaPrivateKey
        })

        promise = crypto.subtle
          .exportKey('jwk', key)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.be.instanceof(JsonWebKey)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * wrapKey
   */
  describe('wrapKey', () => {
      describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM",
            },
            true,
            ["encrypt", "decrypt","wrapKey","unwrapKey"]
        )
        promise = crypto.subtle.wrapKey('jwk',key,key,{name: "AES-NONESENSE"})
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with invalid name property', () => {
      let promise, error

      beforeEach( done => {
        let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM",
            },
            true,
            ["encrypt", "decrypt","wrapKey","unwrapKey"]
        )
        let alg = {name: "AES-CBC",iv:good_iv} // Not GCM
        promise = crypto.subtle.wrapKey('jwk',key,key,alg)
        promise.catch(err => {
          error = err
          done()
        })
      })

      it('should reject the promise', () => {
        promise.should.be.rejected
        error.should.be.instanceof(Error)
        error.message.should.include('NormalizedAlgorthm name must be same as wrappingKey algorithm name')
      })
    })

    describe('with invalid key ops', () => {
      let promise, error

      beforeEach(done => {
        let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM",
            },
            true,
            ["encrypt", "decrypt"]
        )
        let alg = {name: "AES-GCM",iv:good_iv}
        promise = crypto.subtle.wrapKey('jwk',key,key,alg)
                promise.catch(err => {
          error = err
          done()
        })
      })

      it('should reject the promise', () => {
        promise.should.be.rejected
        error.should.be.instanceof(Error)
        error.message.should.include('Wrapping key usages must include "wrapKey"')
      })
    })

  describe('with invalid extractable property', () => {
      let promise, error

      beforeEach(done => {
        let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM",
            },
            false, // Incorrect
            ["encrypt", "decrypt","wrapKey"]
        )
        let alg = {name: "AES-GCM",iv:good_iv}
        promise = crypto.subtle.wrapKey('jwk',key,key,alg)
        promise.catch(err => {
          error = err
          done()
        })
      })

      it('should reject the promise', () => {
        promise.should.be.rejected
        error.should.be.instanceof(Error)
        error.message.should.include('Key is not extractable')
      })
    })


  describe('with valid arguments', () => {
      let promise, result, error

      beforeEach(done => {
        let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM",
            },
            true,
            ["encrypt", "decrypt","wrapKey"]
        )
        let alg = {name: "AES-GCM",iv:good_iv}
        promise = crypto.subtle.wrapKey('jwk',key,key,alg)
        promise.then(res => {
            result = res
            done()
          })  
        .catch(err => {
          error = err
          done()
        })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.be.instanceof(ArrayBuffer)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })      
    })
  })

  /**
   * unwrapKey
   */
  describe('unwrapKey', () => {
    let wrappedKey
    before (() => {
      wrappedKey = new Uint8Array([
        34,105,32,16,166,133,127,43,31,27,51,61,224,43,87,63,222,
        207,113,84,80,101,73,170,5,67,147,1,16,76,204,98,165,66,
        25,48,219,41,143,247,79,136,187,202,198,2,176,61,50,127,
        32,227,5,15,115,49,174,204,21,201,34,37,45,36,68,51,55,
        138,56,65,242,121,247,165,89,74,183,157,112,42,245,233,
        236,138,177,94,14,151,55,134,166,103,181,77,59,234,225,
        115,127,249,108,64,97,144,99,41,205,18,8,123,16,203,141,
        104,145,133,96,15,25,97,109,66,16,32,120,207,212,230,175,
        31,202,237,230,158,207,35,145,82,87,110,67,159,36,146,148,
        147,222,172,81,162,70,16,152,136,228,100,27,111,138,171])
    })

    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM",
            },
            true,
            ["encrypt", "decrypt","wrapKey","unwrapKey"]
        )
        promise = crypto.subtle.unwrapKey(
            'jwk',
            wrappedKey,
            key,
            {
              name:"AES-NONSENSE",
              iv: good_iv,
              tagLength: 128
            },
            {   
                name: "AES-NONSENSE",
                length: 256
            },
            true,
            ["encrypt","decrypt","wrapKey","unwrapKey"]
          )
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with invalid name property', () => {
      let promise, result, error

      before( done => {
        let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM", 
            },
            true,
            ["encrypt", "decrypt","wrapKey","unwrapKey"]
        )
        promise = crypto.subtle.unwrapKey(
            'jwk',
            wrappedKey,
            key,
            {
              name:"AES-CBC", // Incorrect
              iv: good_iv,
              tagLength: 128
            },
            {   
                name: "AES-CBC", // Incorrect 
                length: 256
            },
            true,
            ["encrypt","decrypt","wrapKey","unwrapKey"]
          )
        promise
        .then ( res  => {
          result = res
          done()
        })
        .catch(err => {
          error = err
          done()
        })
      })

      it('should reject the promise', () => {
        promise.should.be.rejected
        error.should.be.instanceof(Error)
        error.message.should.include('NormalizedAlgorthm name must be same as unwrappingKey algorithm name')
      })
    })

    describe('with invalid key ops', () => {
      let promise, error

      before(done => {
       let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM",
            },
            true,
            ["encrypt", "decrypt"]
        )
        promise = crypto.subtle.unwrapKey(
            'jwk',
            wrappedKey,
            key,
            {
              name:"AES-GCM",
              iv: good_iv,
              tagLength: 128
            },
            {   
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt","decrypt"]
          )
        promise.catch(err => {
          error = err
          done()
        })
      })

      it('should reject the promise', () => {
        promise.should.be.rejected
        error.should.be.instanceof(Error)
        error.message.should.include('Unwrapping key usages must include "unwrapKey"')
      })
    })

    describe('with different key arguments', async () => {
      let unwrappedSymmetric;
      before(async () => {
      
        let cryptoAlgorithm = {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: "SHA-1" }
        };

        let cryptoSymmetricAlgorithm = {
          name: "AES-GCM",
          length: 256, //can be  128, 192, or 256
        };
        
        let wrappingAlgorithm = {
          name: "RSA-OAEP",
          hash: {name: "SHA-1"},
        };

        let asymmetricKey = await crypto.subtle.generateKey(
          cryptoAlgorithm,
          true,
          ["encrypt", "decrypt", "wrapKey"]
        );

        let symmetric = await crypto.subtle.generateKey(
          cryptoSymmetricAlgorithm,
          true,
          ["encrypt", "decrypt"]
        );

        let wrappedSymmetric = await crypto.subtle.wrapKey(
          "raw",
          symmetric,
          asymmetricKey.publicKey,
          wrappingAlgorithm
        );

        unwrappedSymmetric = await crypto.subtle.unwrapKey(
            "raw",
            wrappedSymmetric,
            asymmetricKey.privateKey,
            wrappingAlgorithm,
            cryptoSymmetricAlgorithm,
            false,
            ["encrypt", "decrypt"]
        );
      });
      it('should resolve the promise', () => {
        unwrappedSymmetric.should.be.instanceof(CryptoKey)
      })
    })

    describe('with valid arguments', () => {
      let promise, result, error

      before(done => {
        let aes = new AES_GCM({ name: "AES-GCM", length: 256 })
        let key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256GCM",
                ext: true,
            }, 
            {
                name: "AES-GCM",
            },
            true,
            ["encrypt", "decrypt","wrapKey","unwrapKey"]
        )
        promise = crypto.subtle.unwrapKey(
            'jwk',
            wrappedKey,
            key,
            {
              name:"AES-GCM",
              iv: good_iv,
              tagLength: 128
            },
            {   
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt","decrypt","wrapKey","unwrapKey"]
          )
        promise
        .then ( res  => {
          result = res
          done()
        })
        .catch(err => {
          error = err
          done()
        })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.be.instanceof(CryptoKey)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })   
    })
  })
})
