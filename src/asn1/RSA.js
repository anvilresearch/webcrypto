console.log("Starting...\n")

/**
 * Package dependencies
 */

// https://github.com/dannycoates/pem-jwk/blob/master/index.js
// https://tools.ietf.org/html/rfc3447#page-44

const asn = require('asn1.js')
const fs = require('fs')

const testRSA = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqkGlLoTlAscAgZDK8wffqDpn5OP2gu/EPZ1AYEX5UbJz4DGTJQ3nDV6dVNDs8rAL+u4N9UrE46h90he0f/d99YcqMuZRrFTb1KcK36aErzJv7X2NPBHuuP5USXGe8100kNvAtmNr7aLbx2K92h42h75Nt6sZJ/WHO/hGosTNJQe7K/rWFwAt66mBBJFmqzt242EtMNZVjm8gZSOpSfrgFeF5kEgkaAPOp0SnRp/JymB8AyLn5qPAmwnpKPPUzQtGpIluIvGXDnhHix5KEvJ5vd6B6c+jBIxvV/L/IPRQ3Q06fmWyZSW4aT9BS1GmN1P8B5Rspq3NFRD+VRHjtGpNbQIDAQAB'

const test2 = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx2gB8RVp8io70LDPlqfDsVdcc+qSONU3KTkUhiTbWSUxhGXKGEMFa3TA8FgI/UqOwEwZUZwaj2p0yd/f1tGq2Zqbb0mMHcde2UlV98Uu1gzB5ROzJ2FexvrcGPxRjpcWLWaJrmmDa5irrT3ncHbrFf/ZJjM5NzCfReCEymVIVkTrXEwpEV6Uhm6G+kuTps4vYexTTpfALe8mg42MMWhosz9al7Y2Cvxz9cqb1J/JJPoA65Gy+ce+5cSHZNYGM5F5KdMNnWNeq9yid3HkmaeN1h68R5tj2JUXd0fVj9U9DUG2/h11UtbBkgdeUKJuvOBFOE24ghukcv4lVPanaiIt7wIDAQAB`

const test3 = fs.readFileSync('./public.pem').toString("ascii")

console.log(test3)

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

var PublicKeyInfo = asn.define('PublicKeyInfo', function () {
  this.seq().obj(
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('publicKey').bitstr()
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

function decodePublic(buffer, extras) {
  var info = PublicKeyInfo.decode(buffer, 'der')
  return decodeRsaPublic(info.publicKey.data, extras)
}

var pem = test3

var text = pem.split(/(\r\n|\r|\n)+/g)
text = text.filter(function(line) {
  return line.trim().length !== 0
});
text = text.slice(1, -1).join('')
let bufferInput = text.replace(/[^\w\d\+\/=]+/g, '')

let buf = Buffer.from( bufferInput, 'base64' )

console.log(buf)

let returnVal = decodePublic(buf,'der')
console.log(returnVal)

/*
let output = Test.encode({ a: 'foo' }, 'der')

console.log(output.toString('base64'))

let decoded = Test.decode(output, 'der')

Object.keys(decoded).forEach(key => {
  decoded[key] = decoded[key].toString('utf8')
})
*/
console.log("\n...ending")
