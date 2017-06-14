/**
 * Dependencies
 */
const ECDSA = require('../src/algorithms/ECDSA')

/**
 * ECDSAObjects 
 */
const ECDSA_K256 = new ECDSA({ name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } })

/**
 * ECDSA_K256_PublicKey
 */
const ECDSA_K256_PublicKey = ECDSA_K256.importKey(
      'jwk',
      { 
          kty: 'EC',
          crv: 'K-256',
          x: 'v-7l4HaEJwSkQwx0uzm0qZmHavW2Gpjm5D2tKifeIeo',
          y: 'JGGVfZjuI_25bBbEuwI5PA4M2DMyoS5d07BlA5dWr0E' 
      },
      {
          name: 'K-256'
      },
      true,
      ['verify'])

/**
 * ECDSA_K256_PublicPem
 */
ECDSA_K256_PublicPem = 
    `-----BEGIN PUBLIC KEY-----
    MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEL/yAQbK4Kg95AknFkfVO8V5rWkN1shsz
    7jrEyDZ3McDY1rv9hRIcMyfrxeycgY5+jdPCIip9tpNe9q9QrNPqqg==
    -----END PUBLIC KEY-----`

/**
 * ECDSA_K256_PrivateKey
 */
const ECDSA_K256_PrivateKey = ECDSA_K256.importKey(
      'jwk',
      { 
          kty: 'EC',
          crv: 'K-256',
          d: '-2luTboUHmtHxZUDNOyq1MY2JzHnVDd8xyhfaol8Mec',
          x: 'v-7l4HaEJwSkQwx0uzm0qZmHavW2Gpjm5D2tKifeIeo',
          y: 'JGGVfZjuI_25bBbEuwI5PA4M2DMyoS5d07BlA5dWr0E' 
      },
      {
          name: 'K-256'
      },
      true,
      ['sign'])

/**
 * ECDSA_K256_PrivatePem
 */
ECDSA_K256_PrivatePem = 
    `-----BEGIN EC PRIVATE KEY-----
    MHQCAQEEID0efOySYrkhN2hbYWqJ2H91SbQfVl2mXDe1YtDpgVLcoAcGBSuBBAAK
    oUQDQgAEL/yAQbK4Kg95AknFkfVO8V5rWkN1shsz7jrEyDZ3McDY1rv9hRIcMyfr
    xeycgY5+jdPCIip9tpNe9q9QrNPqqg==
    -----END EC PRIVATE KEY-----`


/**
 * Export
 */
module.exports = {
  ECDSA_K256_PrivateKey,
  ECDSA_K256_PublicKey,
  ECDSA_K256_PrivatePem,
  ECDSA_K256_PublicPem,
}
