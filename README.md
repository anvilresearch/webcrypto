# Web Cryptography API

[![Join the chat at https://gitter.im/anvilresearch/webcrypto](https://badges.gitter.im/anvilresearch/webcrypto.svg)](https://gitter.im/anvilresearch/webcrypto?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

This package provides a subset of W3C's [Web Cryptography API][webcrypto] for
Node.js that is necessary to support protocols such as [JOSE][jose] and
[OpenID Connect][oidc]. The purpose of the project is to enable development of
isomorphic libraries that depend on the availability of cryptographic primitives
in order to implement cryptographic protocols. The long term goal of the project
is to encourage or provide a [native, if not core][wtf] Web Cryptography module.

[webcrypto]: https://www.w3.org/TR/WebCryptoAPI/
[jose]: https://datatracker.ietf.org/wg/jose/documents/
[oidc]: http://openid.net/connect/
[wtf]: https://github.com/nodejs/node/issues/2833

## Status

Note: This library is under active development. Expect breaking changes, do
not use in production.

## Running tests

```bash
$ npm test
```

## Supported Algorithms

| Algorithm name | encrypt | decrypt | sign | verify | digest | generateKey | deriveKey | deriveBits | importKey | exportKey | wrapKey | unwrapKey |
|------------------|---|---|---|---|---|---|---|---|---|---|---|---|
|RSASSA-PKCS1-v1_5 |   |   | ✔ | ✔ |   | ✔ |   |   | ✔ | ✔ |   |   |
|RSA-PSS           |   |   | _ | _ |   | _ |   |   | _ | _ |   |   |
|RSA-OAEP          | _ | _ |   |   |   | _ |   |   | _ | _ | _ | _ |
|ECDSA             |   |   | _ | _ |   | _ |   |   | _ | _ |   |   |
|ECDH              |   |   |   |   |   | _ | _ | _ | _ | _ |   |   |
|AES-CTR           | _ | _ |   |   |   | _ |   |   | _ | _ | _ | _ |
|AES-CBC           | _ | _ |   |   |   | _ |   |   | _ | _ | _ | _ |
|AES-GCM           | _ | _ |   |   |   | _ |   |   | _ | _ | _ | _ |
|AES-KW            |   |   |   |   |   | _ |   |   | _ | _ | _ | _ |
|HMAC              |   |   | ✔ | ✔ |   | ✔ |   |   | ✔ | ✔ |   |   |
|SHA-1             |   |   |   |   | ✔ |   |   |   |   |   |   |   |
|SHA-256           |   |   |   |   | ✔ |   |   |   |   |   |   |   |
|SHA-384           |   |   |   |   | ✔ |   |   |   |   |   |   |   |
|SHA-512           |   |   |   |   | ✔ |   |   |   |   |   |   |   |
|HKDF              |   |   |   |   |   |   | _ | _ | _ |   |   |   |
|PBKDF2            |   |   |   |   |   |   | _ | _ | _ |   |   |   |

Key:

` ✔ ` Implemented
` _ ` Need to implement

## MIT License

Copyright (c) 2016 Anvil Research, Inc.
