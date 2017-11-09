/**
 * Dependencies
 */
const CryptoKey = require('../src/keys/CryptoKey')
const keyto = require('@trust/keyto')

/**
 * RsaPrivateKey
 */
const RsaPrivateKey =
`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAiEJoO1tBT1Yc9jdYWI5JUkMnOlFD+weoi1rkxsWvZoBRJJGi
fjrdmIn/5xOaaW38Cg535lo6NEorsVsq7V6zGan2QCT1TRCb7vJq4UIEq6tL5uB0
BZMyByKBYDKVGAinXYd502nJ1T7sbZQnSjZFC3HgDvrqb/4bDIbO0+sAiaTumt+2
uyIYcGYBuIfTi8vmElz2ngUFh+8K/uQyH7YjrOrg6ThOldh8IVzaOSA7LAb/DjyC
+H44F/J24qMRLGuWK53gz+2RazSBotiNUsGoxdZv30Sud3Yfbz9ZjSXxPWpRnG6m
ZAZW76oSbn8FvTSTWrf0iU6MyNkv/QuAjF+1BQIDAQABAoIBAHb3G8/vDad59NFX
Yu/2Urfa363/882BUztQQXv2bvycPbwi1u9E7+JVYjLbH667ExmopjBdSIIM2/b+
NQ2H5/EZPmGkovME9E/8ISrInBFR/nP2NfYEHOKz0qctopSYQZ/cP5ZAv7JKPNwz
RNZ7aW7jno8VrYfYIL+gF4ZYoGCLdIdw2rFaobZFGtUQ1ASpuBIS3NAQjxQLTdlz
jUXCqqE02VKVW6Chr/ZPDnsjDmVxZjY5+vLoZRyS4jWBR64fgVrA+FoCFqtbKh5X
ZCGUSRhGYs06XLlnjLn91ftgO6Di3FbQ2d4nrMRkD8ciOPv1iao429wKThiChTge
0DRF5SECgYEAvblqHOYDjdRTPV2rumoWKPzREhebi0ljKeMBFPvqVBM/IvOhqpVa
cBsDCNGHwkOo3lX+M+c8y381ZR66pJb5QpF7qfIjlOQEYQfLc31HErYcHiPtKSNj
L4HP5kAoZT4ILFZlfnVJP8oZ/S+BKO27juMwDVUk/wlI2CiN0a1oPWkCgYEAt9vB
+yjoWydrBXy5q4m0pMcTm9FZum9kahCXx/0QjYPLjxwX6+d8Tc1Y1/VROtQDAIxu
yMZxkboQ0L8uXtVQCjVz8hG1UDeqzISxLyTVP+JtD6yijhyrtQdgtokgAFzBHpYa
MKgr8tARtojF5EyWPTQJpBSI2+tl0GgwEOa3Gz0CgYB65SQLXCNpN+RDl+2pbxaz
rjBvm8Mx0nPdqiIFSblchKsdJNvP97cBbz3j9HYQLGuyudlUHbGPz/LycZlNDE6i
BEMqrqLFy33arIXpZXkocbZ8/6CcSUPyfhABggWoryn0LnLIG4k7PNrg2mi77mLU
B+4UdNbmLUl2W66h58XiIQKBgDG6kMccE2zERqAfUiDhiCihZ95XS4uvoVtGzabb
/eQo55/3m0jFPcvVZNhUk/nzajR1x2kqs4EU8INlkmc4DwQT3R52R7JAvEPBCCOW
NM+osJLywKzreE3ohvIYOL2gWOOq+b57Xhe4y3GxoMTVKjW3o3vryfChxNIPvCB2
JsSJAoGBAJV3gcwgFgAA6t8m7g4YStDKANJngttdfHZC1IhGFOtKPc/rneobgDCt
48gw9bQD8gy87laRb/hjm/0Az4bjtDDOkKY5yhCUtipnpx4FR12nGRmMfRGedLJh
rrdlkni8537vUl2rwiG3U3LTi9vHMIbBQek5rxlbc8jS8ejGUFdc
-----END RSA PRIVATE KEY-----`

/**
 * RsaPrivateJwk
 */
const RsaPrivateJwk = keyto.from(RsaPrivateKey,'pem').toJwk('private')

/**
 * RsaPrivateCryptoKey
 */
const RsaPrivateCryptoKeySHA1 = new CryptoKey({
  type: 'private',
  algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-1'} },
  extractable: false,
  usages: ['sign'],
  handle: RsaPrivateKey
})

const RsaPrivateCryptoKeySHA256 = new CryptoKey({
  type: 'private',
  algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'} },
  extractable: false,
  usages: ['sign'],
  handle: RsaPrivateKey
})

const RsaPrivateCryptoKeySHA384 = new CryptoKey({
  type: 'private',
  algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-384'} },
  extractable: false,
  usages: ['sign'],
  handle: RsaPrivateKey
})

const RsaPrivateCryptoKeySHA512 = new CryptoKey({
  type: 'private',
  algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-512'} },
  extractable: false,
  usages: ['sign'],
  handle: RsaPrivateKey
})

/**
 * RsaPublicKey
 */
const RsaPublicKey =
`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiEJoO1tBT1Yc9jdYWI5J
UkMnOlFD+weoi1rkxsWvZoBRJJGifjrdmIn/5xOaaW38Cg535lo6NEorsVsq7V6z
Gan2QCT1TRCb7vJq4UIEq6tL5uB0BZMyByKBYDKVGAinXYd502nJ1T7sbZQnSjZF
C3HgDvrqb/4bDIbO0+sAiaTumt+2uyIYcGYBuIfTi8vmElz2ngUFh+8K/uQyH7Yj
rOrg6ThOldh8IVzaOSA7LAb/DjyC+H44F/J24qMRLGuWK53gz+2RazSBotiNUsGo
xdZv30Sud3Yfbz9ZjSXxPWpRnG6mZAZW76oSbn8FvTSTWrf0iU6MyNkv/QuAjF+1
BQIDAQAB
-----END PUBLIC KEY-----`

/**
 * RsaPublicJwk
 */
const RsaPublicJwk = keyto.from(RsaPublicKey,'pem').toJwk('public')

/**
 * RsaPrivateCryptoKey
 */
const RsaPublicCryptoKeySHA1 = new CryptoKey({
  type: 'public',
  algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-1'} },
  extractable: true,
  usages: ['verify'],
  handle: RsaPublicKey
})

const RsaPublicCryptoKeySHA256 = new CryptoKey({
  type: 'public',
  algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'} },
  extractable: true,
  usages: ['verify'],
  handle: RsaPublicKey
})

const RsaPublicCryptoKeySHA384 = new CryptoKey({
  type: 'public',
  algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-384'} },
  extractable: true,
  usages: ['verify'],
  handle: RsaPublicKey
})

const RsaPublicCryptoKeySHA512 = new CryptoKey({
  type: 'public',
  algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-512'} },
  extractable: true,
  usages: ['verify'],
  handle: RsaPublicKey
})

/**
 * Export
 */
module.exports = {
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
}
