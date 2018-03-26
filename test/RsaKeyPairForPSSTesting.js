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
MIIEogIBAAKCAQEAtK1GWlnRWt35Nb1J3NUz7SBKP5Ui/r5g8xcqPIdUklKreZdn
xzMLBGf8RV1woo+EudIrLanN5kiReX5e29bm/LKagasBnYn1sb+uLVeFJVahsslS
IY9vKUtIfJlI2svGzrygD2LHLNzrMgQs+Nk7kil+KliFepeaCyEiSuGE+/zb9MUD
K47Jj2YBlhugrqSvCTkfCmIFD98asQsJQpU8oMOKtyDZMHpSaVgNO0MH1/hiH2W4
tC7R0e3/5qpCoD73LOgh0c0EIM03tle7il60cI+9vRleuie7BSqoPiokiQvQLwWi
PLZq3u9hUfLLexHmlPe+JWn9GGi9UNh1eV7OJQIDAQABAoIBAGX9hkBMgWy87wfR
8ZcSVzydRKx9wIJy74Fp6zK95hSvTBLYUAHXo3l6RaLWa1WolHDc3fjp6Mv83Pnr
RxrsRfoRzDw0TzYiAaq0HFuGEygPrjmhgZZmRIbX83Q6hzDTZUegnO3ygaKmlrHm
P4i9/+2zNIAs9jRMze1IZ/ZDNfGUSZsRyJG69k9hnRpFVoJ/WkPn0zJrkDXmiWyw
vVpK06NBMF0fnnXRPs+XN/NDhhB6arg7PQZlU2hk4xubtPDQiwaBkeSzj1PFP5y5
GkocW/bBha6wHpUxzy2Sx7Yte9jmEY3QoZy6KCGvWdkQQYRQ17JN0RyhDc828cL5
rfonpoECgYEA3g9/IyYuQUf+sCnbsEBsd1ni87CvXAxG3NDQXrioZjNIuu32T5r/
I2481gtwfUieyYfg4ZFwXA9m2wWC1qWLz82oZBhedGMO5Uw4IY6glzGHmFZDeFt+
Jrfi0xcmPuBulJTHMkcNHgE/OLMXCpUsr4C96IL7ktGB3OmQagDqE+ECgYEA0EqR
63vQSabgmVd5KvsGlwgjcjN5ajFA7oDrvrP4DFp/8SFjMzia3XylUXqaHU8tyPwe
uq8OMSF1l4KoYiD00waPXXeguvCGNo4vTXSJvMMLoXPVGGXs8QZ4UzKlacplwpiI
jY2oU1ZOBIKHHqMoZmHSVNUI+VYO3BJ5vlfNwsUCgYAUkgzt/aB1Ta0LNqVyO1WQ
7NO4TVrBRSXfWLykuahn50JKhra1gx81cgXSsjaWdH65How3eRiWfprBmU4Ygjdk
ZaG+u/8r+u0rUpc0jJjVyLHN69fOM3OJNKmfclqJopK70thtEOXnLKhloTl2MoF0
NJHjExco751/EGffWfxVIQKBgCqpS0/O8S9UpaXim6eo+IWQninyzwhoBCOVdjN+
Cu0E0DWkH/xKuLVqpTWWBeDA6eDDesvDtQVtE/evRCutElfyfQSoztvbDbI41wln
OBrYXBZ6cgfoQGpxZ82qjuSnFsaPlVBg1jwTbjFQRrqIsmqd2IWViJwA+1Qp2JOa
ykL9AoGAXMgvAWE9jJcoluljAcUhVMp837FTdhY1m1rv6BNzjaG0iQ8qV7OI/MnJ
SHpGrbNh4k/6bUyuozHV9nkWD6vYJL5stEsP3SIv2FqoytyoeGoLpPg4BPD5ye57
QQ6nQ+YQJWuvl63/GPKN3AzB9uMNkcnp4A/ezighFir0KZpwrlw=
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
  algorithm: { name: 'RSA-PSS', saltLength: 128, hash: {name: 'SHA-1'} },
  extractable: false,
  usages: ['sign'],
  handle: RsaPrivateKey
})

const RsaPrivateCryptoKeySHA256 = new CryptoKey({
  type: 'private',
  algorithm: { name: 'RSA-PSS', saltLength: 128, hash: {name: 'SHA-256'} },
  extractable: false,
  usages: ['sign'],
  handle: RsaPrivateKey
})

const RsaPrivateCryptoKeySHA384 = new CryptoKey({
  type: 'private',
  algorithm: { name: 'RSA-PSS', saltLength: 128, hash: {name: 'SHA-384'} },
  extractable: false,
  usages: ['sign'],
  handle: RsaPrivateKey
})

const RsaPrivateCryptoKeySHA512 = new CryptoKey({
  type: 'private',
  algorithm: { name: 'RSA-PSS', saltLength: 128, hash: {name: 'SHA-512'} },
  extractable: false,
  usages: ['sign'],
  handle: RsaPrivateKey
})

/**
 * RsaPublicKey
 */
const RsaPublicKey =
`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtK1GWlnRWt35Nb1J3NUz
7SBKP5Ui/r5g8xcqPIdUklKreZdnxzMLBGf8RV1woo+EudIrLanN5kiReX5e29bm
/LKagasBnYn1sb+uLVeFJVahsslSIY9vKUtIfJlI2svGzrygD2LHLNzrMgQs+Nk7
kil+KliFepeaCyEiSuGE+/zb9MUDK47Jj2YBlhugrqSvCTkfCmIFD98asQsJQpU8
oMOKtyDZMHpSaVgNO0MH1/hiH2W4tC7R0e3/5qpCoD73LOgh0c0EIM03tle7il60
cI+9vRleuie7BSqoPiokiQvQLwWiPLZq3u9hUfLLexHmlPe+JWn9GGi9UNh1eV7O
JQIDAQAB
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
  algorithm: { name: 'RSA-PSS', saltLength: 128, hash: {name: 'SHA-1'} },
  extractable: true,
  usages: ['verify'],
  handle: RsaPublicKey
})

const RsaPublicCryptoKeySHA256 = new CryptoKey({
  type: 'public',
  algorithm: { name: 'RSA-PSS', saltLength: 128, hash: {name: 'SHA-256'} },
  extractable: true,
  usages: ['verify'],
  handle: RsaPublicKey
})

const RsaPublicCryptoKeySHA384 = new CryptoKey({
  type: 'public',
  algorithm: { name: 'RSA-PSS', saltLength: 128, hash: {name: 'SHA-384'} },
  extractable: true,
  usages: ['verify'],
  handle: RsaPublicKey
})

const RsaPublicCryptoKeySHA512 = new CryptoKey({
  type: 'public',
  algorithm: { name: 'RSA-PSS', saltLength: 128, hash: {name: 'SHA-512'} },
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
