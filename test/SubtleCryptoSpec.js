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
const CryptoKey = require('../src/CryptoKey')
const CryptoKeyPair = require('../src/CryptoKeyPair')
const {str2ab,ab2buf,buf2ab} = require('../src/encodings')

/**
 * RSA Key Pair
 */
const RsaPrivateKey =
`-----BEGIN RSA PRIVATE KEY-----
MIIEoAIBAAKCAQEAjShpceWt4yI7PKZsUJoWdCCVo1y8DDrnoD1i7N7kekxh9Be9
FmwopiQ0k61Xpi2rKi+Y5yFsVHhOKfVM1l86MD/ai6ViJduJB8Fps95vp3N78QZm
VS+bNWgl5+j1R1GOkWK4iCCkNrE1Di9h+Uy1soUwZpo5KwdcCR2r8FeiUYxAyFIh
vabDgxGIjMpfRThiy1t+gLbE02b8mFt6Hg38x4Pu4eIr2pv0jx+FzKnMZNyATbyi
OV1xZzVfRkTcazF6L3zDNhS1waCOg0aKeX8psD+41rWEa1dOXYSd7N0DyGVYKmL3
gxFyLhcq95JXzdYlt225PhCTeBG6USkYYIOiDwIBAQKCAQBrp0lxwhcK21oAbvvx
xDT77QWLh3iA3D0ZlWpTB59OVCbYCiKiiEbYW1zkLIqQqky/jOQsyM4iiZJF2fTf
QabmCth6cC72Bg7bFP/tyIT3PS220hRE839Vji7Wt6Qmc/0qJW/YYJ0cwum1Jx/i
+79dUKhmJ+vZGIntDan6CQ83Nv69u8bBId1flqzCSMEAS4v5pXIOcVOyvBSrFsiZ
gRIOCbc6m3o7GhJrYTyk52k0+JZ8hnh0n23jHdG41PGRlSP6xsqwZj8HagfAPQNs
8F65ailybSCv+mxhQFGFFXDy2oLxJuhvHima5xoqiJ4F+saYhxSXYOUWxVuFQ0Lb
DorBAoGBAPLdvdcex/6rcftJKlHjBXTfxQLiDOmWrVnTOBZ1sgXpimJ3ULgq/Y7/
VOYmhX8ngwvlO2GVSKinQ+v9o0b2E8FxhjoMwOdSYkMxz9kCiQvpY9/57lYA0YE+
nlQ48mYAWoMrjQ36AHrljrHW9jA0HpLWbbdNDCdGDGTYNyTsHDW3AoGBAJTKnMSz
6ocku/FE4ACkbJrz60LNCDK2722L/F89HyHOLh13198rRAwagKzdltRE9Cc///Ot
HypLsYjH6GhhU6Jhi/9j/MJR7gpMQNA9BBSCwkcWabkbSTHy+SK69v3s30DPsUM2
D0stv1LmOf+UfR4mEDFj/tdRjQC71yTvSzZpAoGARe4qtXlsYzpUngUhGpEOhUNr
h04JsdO6YZV4vcBFMIT9A3MKSvF7z4ZIQkTduQhjffJQ2VvLNYrO02PtRT3j0hi4
FLL8xhe4rr2obE5tMEE1qRUpuyEbc+gxksWwYRr/Kr/W7xso+ovPb/gq/vAgtbw/
d4TAwpen7TlGqgI96Z0CgYBjAFZhAyp9x8HIYKD/bmYlW5KTC+iRTuMLIWAzamli
MoZHZ6WMhWETArFCNc3x2DbfWGeQNG9h3rDleBAti3dmERdsK543lSTcBOpguAmw
A1RxCu2w9EWevo3cVoxvLgsVNYXiAxkeGXVXCL/9unUeBWdplDcC0KiG9oIzeF7e
eQKBgCAYYNpOkwMhRivSu/JvS32/FlMICi81EUoqhpny0z2sR/OWloZKfyn41Vbz
w2wjbs9nf3a4zUG6wTud+VRyd+KmPso2tB1MCcDGAC2Ozt3rqEZo1M7jAEpb4VWI
eHSm+1brST/kTLCZsN14g/ms2T0mmnQ3p6TvoWMInEDtKLte
-----END RSA PRIVATE KEY-----`

const RsaPublicKey =
`-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAjShpceWt4yI7PKZsUJoW
dCCVo1y8DDrnoD1i7N7kekxh9Be9FmwopiQ0k61Xpi2rKi+Y5yFsVHhOKfVM1l86
MD/ai6ViJduJB8Fps95vp3N78QZmVS+bNWgl5+j1R1GOkWK4iCCkNrE1Di9h+Uy1
soUwZpo5KwdcCR2r8FeiUYxAyFIhvabDgxGIjMpfRThiy1t+gLbE02b8mFt6Hg38
x4Pu4eIr2pv0jx+FzKnMZNyATbyiOV1xZzVfRkTcazF6L3zDNhS1waCOg0aKeX8p
sD+41rWEa1dOXYSd7N0DyGVYKmL3gxFyLhcq95JXzdYlt225PhCTeBG6USkYYIOi
DwIBAQ==
-----END PUBLIC KEY-----`

/**
 * Tests
 */
describe('SubtleCrypto', () => {

  /**
   * encrypt
   */
  describe('encrypt', () => {
    it('should return a Promise')
  })

  /**
   * decrypt
   */
  describe('decrypt', () => {
    it('should return a Promise')
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
      let promise, result, error

      beforeEach((done) => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }

        let privateKey = new CryptoKey({
          type: 'private',
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
          extractable: false,
          usages: ['sign'],
          handle: RsaPrivateKey
        })

        let data = new ArrayBuffer()

        promise = crypto.subtle
          .sign(algorithm, privateKey, data)
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
        result.should.be.instanceof(ArrayBuffer)
        //console.log(ab2buf(result).toString('base64'))
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
      let signature = buf2ab(new Buffer('K6vDm+8AoOCtUiai3ssiS3nJ2HMy/8BlZywP2NFcl2fSdOniJL1MZkN7JDY0FPj0OuUgotB8C+A0WcPnaerXYUZcXvDHhpkhWjKqhJgWf2vp2Hj8wkujxo50sxXvBChwgsNLEMCshziFg31LnoWkjTCc3bXN9vg6sHAh9S2f51Xd/iRktV0uPwoNEhHxzK8Vc+5hB5wJRv4KuPTGg2E+/iirYsE35AE1QLkFMyF5klyp9ZCGPI/XfAoWPBE0vuSzsLH1tJq2/e5k83hL/6ikGhpt66SsnpcmnRZVksKLfOGUr90dywkaRPq3jQV/klAeUamce1N4lBJW9bYdaVkFvQ==', 'base64'))


      it('should return a promise')
      it('should resolve the promise')
    })
  })

  /**
   * digest
   */
  describe('digest', () => {
    it('should return a Promise')
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

        promise = crypto.subtle
          .generateKey(algorithm, false, ['sign', 'verify'])
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
    it('should return a Promise')
  })

  /**
   * exportKey
   */
  describe('exportKey', () => {
    it('should return a Promise')
  })

  /**
   * wrapKey
   */
  describe('wrapKey', () => {
    it('should return a Promise')
  })

  /**
   * unwrapKey
   */
  describe('unwrapKey', () => {
    it('should return a Promise')
  })
})
