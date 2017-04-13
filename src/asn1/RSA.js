// https://github.com/dannycoates/pem-jwk/blob/master/index.js
// https://tools.ietf.org/html/rfc3447#page-44

/**
 * Package dependencies
 */
const asn = require('asn1.js')
const fs = require('fs')

const public_test  = fs.readFileSync('./public.pem').toString("ascii")
const private_test = fs.readFileSync('./private.pem').toString("ascii")




function pad(hex) {
  return (hex.length % 2 === 1) ? '0' + hex : hex
}

function urlize(base64) {
  return base64.replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

function hex2b64url(str) {
  return urlize(Buffer(str, 'hex').toString('base64'))
}

function bn2base64url(bn) {
  return hex2b64url(pad(bn.toString(16)))
}

function base64url2bn(str) {
  return new asn.bignum(Buffer(str, 'base64'))
}

function string2bn(str) {
  if (/^[0-9]+$/.test(str)) {
    return new asn.bignum(str, 10)
  }
  return base64url2bn(str)
}

var Version = asn.define('Version', function () {
  this.int({
    0: 'two-prime',
    1: 'multi'
  })
})

var OtherPrimeInfos = asn.define('OtherPrimeInfos', function () {
  this.seq().obj(
    this.key('ri').int(),
    this.key('di').int(),
    this.key('ti').int()
  )
})

let RSAPublicKey = asn.define('RSAPublicKey', function () {
  this.seq().obj(
    this.key('n').int(),
    this.key('e').int()
  )
})

var AlgorithmIdentifier = asn.define('AlgorithmIdentifier', function () {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('parameters').optional().any()
  )
})



var RSAPrivateKey = asn.define('RSAPrivateKey', function () {
  this.seq().obj(
    this.key('version').use(Version),
    this.key('n').int(),
    this.key('e').int(),
    this.key('d').int(),
    this.key('p').int(),
    this.key('q').int(),
    this.key('dp').int(),
    this.key('dq').int(),
    this.key('qi').int(),
    this.key('other').optional().use(OtherPrimeInfos)
  )
})

var PublicKeyInfo = asn.define('PublicKeyInfo', function () {
  this.seq().obj(
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('publicKey').bitstr()
  )
})

var PrivateKeyInfo = asn.define('PrivateKeyInfo', function () {
  this.seq().obj(
    this.key('version').use(Version),
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('privateKey').bitstr()
  )
})

function decodeRsaPublic(buffer,extras)
{
    var key = RSAPublicKey.decode(buffer, 'der')
    var e = pad(key.e.toString(16))
    var jwk = {
        kty: 'RSA',
        n: bn2base64url(key.n),
        e: hex2b64url(e)
    }
  return jwk
}

function decodeRsaPrivate(buffer, extras) {
  console.log("decodeRsaPrivate")
  var key = RSAPrivateKey.decode(buffer, 'der')
  var e = pad(key.e.toString(16))
  var jwk = {
    kty: 'RSA',
    n: bn2base64url(key.n),
    e: hex2b64url(e),
    d: bn2base64url(key.d),
    p: bn2base64url(key.p),
    q: bn2base64url(key.q),
    dp: bn2base64url(key.dp),
    dq: bn2base64url(key.dq),
    qi: bn2base64url(key.qi)
  }
  return jwk
}

function decodePublic(buffer, extras) {
  var info = PublicKeyInfo.decode(buffer, 'der')
  return decodeRsaPublic(info.publicKey.data,extras)
}

function decodePrivate(buffer, extras) {
  var info = PrivateKeyInfo.decode(buffer, 'der')
  return decodeRsaPrivate(info.privateKey.data, extras)
}


var pem = private_test

console.log(pem)

var text = pem.split(/(\r\n|\r|\n)+/g)
text = text.filter(function(line) {
  return line.trim().length !== 0
});
text = text.slice(1, -1).join('')
let bufferInput = text.replace(/[^\w\d\+\/=]+/g, '')

let buf = Buffer.from( bufferInput, 'base64' )

console.log(buf.toString("base64"))

let returnVal = decodeRsaPrivate(buf,'der')
console.log(returnVal)

/*
let output = Test.encode({ a: 'foo' }, 'der')

console.log(output.toString('base64'))

let decoded = Test.decode(output, 'der')

Object.keys(decoded).forEach(key => {
  decoded[key] = decoded[key].toString('utf8')
})
*/
