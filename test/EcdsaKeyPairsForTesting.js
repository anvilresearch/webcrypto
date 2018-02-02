/**
 * Dependencies
 */
const ECDSA = require('../src/algorithms/ECDSA')

/**
 * ECDSAObjects
 */
const ECDSA_K256 = new ECDSA({ name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } })
const ECDSA_P256 = new ECDSA({ name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } })
const ECDSA_P384 = new ECDSA({ name: 'ECDSA', namedCurve: 'P-384', hash: { name: 'SHA-256' } })
const ECDSA_P521 = new ECDSA({ name: 'ECDSA', namedCurve: 'P-521', hash: { name: 'SHA-256' } })

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
          name: 'ECDSA',
          namedCurve: 'K-256',
          hash: {
            name: 'SHA-256'
          }
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
          name: 'ECDSA',
          namedCurve: 'K-256',
          hash: {
            name: 'SHA-256'
          }
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
 * ECDSA_P256_PublicKey
 */
const ECDSA_P256_PublicKey = ECDSA_P256.importKey(
      'jwk',
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "bag3R0FTUvlLJGEM7zEhY2IGJgoEN4Q4UA7eR5Uh7BE",
        "y": "CM1wRrk_90vXDVymupli0yyHAcRBVS3MdQFUCSq5BV0"
      },
      {
          name: 'ECDSA',
          namedCurve: 'P-256',
          hash: {
            name: 'SHA-256'
          }
      },
      true,
      ['verify'])

/**
 * ECDSA_P256_PublicPem
 */
ECDSA_P256_PublicPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbag3R0FTUvlLJGEM7zEhY2IGJgoE
N4Q4UA7eR5Uh7BEIzXBGuT/3S9cNXKa6mWLTLIcBxEFVLcx1AVQJKrkFXQ==
-----END PUBLIC KEY-----`

/**
 * ECDSA_P256_PrivateKey
 */
const ECDSA_P256_PrivateKey = ECDSA_P256.importKey(
      'jwk',
      {
        "kty": "EC",
        "crv": "P-256",
        "d": "3t2jGdosjga1Un35fmweoWMkgDmNYsHeYpkTY707WYE",
        "x": "bag3R0FTUvlLJGEM7zEhY2IGJgoEN4Q4UA7eR5Uh7BE",
        "y": "CM1wRrk_90vXDVymupli0yyHAcRBVS3MdQFUCSq5BV0"
      },
      {
          name: 'ECDSA',
          namedCurve: 'P-256',
          hash: {
            name: 'SHA-256'
          }
      },
      true,
      ['sign'])

/**
 * ECDSA_P256_PrivatePem
 */
ECDSA_P256_PrivatePem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIN7doxnaLI4GtVJ9+X5sHqFjJIA5jWLB3mKZE2O9O1mBoAoGCCqGSM49
AwEHoUQDQgAEbag3R0FTUvlLJGEM7zEhY2IGJgoEN4Q4UA7eR5Uh7BEIzXBGuT/3
S9cNXKa6mWLTLIcBxEFVLcx1AVQJKrkFXQ==
-----END EC PRIVATE KEY-----`

/**
 * ECDSA_P384_PublicKey
 */
const ECDSA_P384_PublicKey = ECDSA_P384.importKey(
      'jwk',
      {
        "kty": "EC",
        "crv": "P-384",
        "x": "XN3ga623z2mu5BdxWXIVeGhznGbDHsqEKaIqTK9RlpCxKwrcdoRqaC3qlIPygcN7",
        "y": "NVey0D8e2Kjx1iqge8-KTCCd7VMs3o6mSPnVjdC6ls6ntN7-0M7yFNUNqh_LPCKz"
      },
      {
          name: 'ECDSA',
          namedCurve: 'P-384',
          hash: {
            name: 'SHA-384'
          }
      },
      true,
      ['verify'])

/**
 * ECDSA_P384_PublicPem
 */
ECDSA_P384_PublicPem = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXN3ga623z2mu5BdxWXIVeGhznGbDHsqE
KaIqTK9RlpCxKwrcdoRqaC3qlIPygcN7NVey0D8e2Kjx1iqge8+KTCCd7VMs3o6m
SPnVjdC6ls6ntN7+0M7yFNUNqh/LPCKz
-----END PUBLIC KEY-----`

/**
 * ECDSA_P384_PrivateKey
 */
const ECDSA_P384_PrivateKey = ECDSA_P384.importKey(
      'jwk',
      {
        "kty": "EC",
        "crv": "P-384",
        "d": "WH7_8esDPbqChcrIj5M0espufGuwWMM1lv_EVI9iJw3dh3QLrLl0MiA8JoyPdp51",
        "x": "XN3ga623z2mu5BdxWXIVeGhznGbDHsqEKaIqTK9RlpCxKwrcdoRqaC3qlIPygcN7",
        "y": "NVey0D8e2Kjx1iqge8-KTCCd7VMs3o6mSPnVjdC6ls6ntN7-0M7yFNUNqh_LPCKz"
      },
      {
          name: 'ECDSA',
          namedCurve: 'P-384',
          hash: {
            name: 'SHA-384'
          }
      },
      true,
      ['sign'])

/**
 * ECDSA_P384_PrivatePem
 */
ECDSA_P384_PrivatePem = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBYfv/x6wM9uoKFysiPkzR6ym58a7BYwzWW/8RUj2InDd2HdAusuXQy
IDwmjI92nnWgBwYFK4EEACKhZANiAARc3eBrrbfPaa7kF3FZchV4aHOcZsMeyoQp
oipMr1GWkLErCtx2hGpoLeqUg/KBw3s1V7LQPx7YqPHWKqB7z4pMIJ3tUyzejqZI
+dWN0LqWzqe03v7QzvIU1Q2qH8s8IrM=
-----END EC PRIVATE KEY-----`

/**
 * ECDSA_P521_PublicKey
 */
const ECDSA_P521_PublicKey = ECDSA_P521.importKey(
      'jwk',
      {
        "kty": "EC",
        "crv": "P-521",
        "x": "AUfN5-iTkxajWZGoNe-jzNCpSydvol5MrKf-QPS0k_3ZxgW62YdOrespAXYrK--G_ff2IoGrXWOw2kuM0JWiioOn",
        "y": "AQc6m4W2GVAfWKxf3qhCtKj6nGCQxCNTHF54AX-Yh4g271LYf8VgW8bshT877SJOJjkYabKJc8NOG_lp1cwffOfq"
      },
      {
          name: 'ECDSA',
          namedCurve: 'P-521',
          hash: {
            name: 'SHA-512'
          }
      },
      true,
      ['verify'])

/**
 * ECDSA_P521_PublicPem
 */
ECDSA_P521_PublicPem = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBR83n6JOTFqNZkag176PM0KlLJ2+i
Xkysp/5A9LST/dnGBbrZh06t6ykBdisr74b99/YigatdY7DaS4zQlaKKg6cBBzqb
hbYZUB9YrF/eqEK0qPqcYJDEI1McXngBf5iHiDbvUth/xWBbxuyFPzvtIk4mORhp
solzw04b+WnVzB985+o=
-----END PUBLIC KEY-----`

/**
 * ECDSA_P521_PrivateKey
 */
const ECDSA_P521_PrivateKey = ECDSA_P521.importKey(
      'jwk',
      {
        "kty": "EC",
        "crv": "P-521",
        "d": "Aae3gDHukB0OAL-LRH3lWBUFJ951hxRRAH8qjnI0lB8zxZjUKR9pDMBaWbulz8WrgU1U5xVvEALQ9aL9S-le2h6W",
        "x": "AUfN5-iTkxajWZGoNe-jzNCpSydvol5MrKf-QPS0k_3ZxgW62YdOrespAXYrK--G_ff2IoGrXWOw2kuM0JWiioOn",
        "y": "AQc6m4W2GVAfWKxf3qhCtKj6nGCQxCNTHF54AX-Yh4g271LYf8VgW8bshT877SJOJjkYabKJc8NOG_lp1cwffOfq"
      },
      {
          name: 'ECDSA',
          namedCurve: 'P-521',
          hash: {
            name: 'SHA-512'
          }
      },
      true,
      ['sign'])

/**
 * ECDSA_P521_PrivatePem
 */
ECDSA_P521_PrivatePem = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBp7eAMe6QHQ4Av4tEfeVYFQUn3nWHFFEAfyqOcjSUHzPFmNQpH2kM
wFpZu6XPxauBTVTnFW8QAtD1ov1L6V7aHpagBwYFK4EEACOhgYkDgYYABAFHzefo
k5MWo1mRqDXvo8zQqUsnb6JeTKyn/kD0tJP92cYFutmHTq3rKQF2Kyvvhv339iKB
q11jsNpLjNCVooqDpwEHOpuFthlQH1isX96oQrSo+pxgkMQjUxxeeAF/mIeINu9S
2H/FYFvG7IU/O+0iTiY5GGmyiXPDThv5adXMH3zn6g==
-----END EC PRIVATE KEY-----`

/**
 * Export
 */
module.exports = {
  ECDSA_K256_PrivateKey,
  ECDSA_K256_PublicKey,
  ECDSA_K256_PrivatePem,
  ECDSA_K256_PublicPem,
  ECDSA_P256_PrivateKey,
  ECDSA_P256_PublicKey,
  ECDSA_P256_PrivatePem,
  ECDSA_P256_PublicPem,
  ECDSA_P384_PrivateKey,
  ECDSA_P384_PublicKey,
  ECDSA_P384_PrivatePem,
  ECDSA_P384_PublicPem,
  ECDSA_P521_PrivateKey,
  ECDSA_P521_PublicKey,
  ECDSA_P521_PrivatePem,
  ECDSA_P521_PublicPem,
}
