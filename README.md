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

### Nodejs

```bash
$ npm test
```

### Browser (karma)

```bash
$ npm run karma
```

## MIT License

Copyright (c) 2016 Anvil Research, Inc.
