# W3C Web Cryptography API _(@trust/webcrypto)_

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![Build Status](https://travis-ci.org/anvilresearch/webcrypto.svg?branch=master)](https://travis-ci.org/anvilresearch/webcrypto)

> W3C Web Cryptography API for Node.js

W3C's [Web Cryptography API][webcrypto] defines a standard interface for performing
cryptographic operations in JavaScript, such as key generation, hashing, signing, and
encryption. This package implements the API for Node.js, in order to support universal
crypto-dependent code required by protocols such as [JOSE][jose] and
[OpenID Connect][oidc].

[webcrypto]: https://www.w3.org/TR/WebCryptoAPI/
[jose]: https://datatracker.ietf.org/wg/jose/documents/
[oidc]: http://openid.net/connect/

## Table of Contents

* [Security](#security)
* [Background](#background)
* [Install](#install)
* [Usage](#usage)
* [Develop](#develop)
* [Supported Algorithms](#supported-algorithms)
* [API](#api)
* [Contribute](#contribute)
* [MIT License](#mit-license)

## Security

TBD

## Background

The purpose of this package is to enable development of universal JavaScript
libraries that depend on the availability of cryptographic primitives in order
to implement cryptographic protocols. The long term goal of the project is to
encourage or provide a [native, if not core][wtf] Web Cryptography module.

[wtf]: https://github.com/nodejs/node/issues/2833

## Install

`@trust/webcrypto` requires recent versions of [node][node] and [npm][npm] to run. For key generation operations, it also requires [OpenSSL][openssl] to be installed on the system.

[node]: https://nodejs.org
[npm]: https://www.npmjs.com/
[openssl]: https://www.openssl.org/


```bash
$ npm install @trust/webcrypto --save
```

## Usage

```javascript
const crypto = require('@trust/webcrypto')
```

## Develop

### Install

```bash
$ git clone git@github.com:anvilresearch/webcrypto.git
$ cd webcrypto
$ npm install
```

### Test

```bash
$ npm test
```

## Supported Algorithms

| Algorithm name | encrypt | decrypt | sign | verify | digest | generateKey | deriveKey | deriveBits | importKey | exportKey | wrapKey | unwrapKey |
|------------------|---|---|---|---|---|---|---|---|---|---|---|---|
|RSASSA-PKCS1-v1_5 |   |   | ✔ | ✔ |   | ✔ |   |   | ✔ | ✔ |   |   |
|RSA-PSS           |   |   | ✔ | ✔ |   | ✔ |   |   | ✔ | ✔ |   |   |
|RSA-OAEP          | ✔ | ✔ |   |   |   | ✔ |   |   | ✔ | ✔ | ✔ | ✔ |
|ECDSA             |   |   | ⚐ | ⚐ |   | ⚐ |   |   | ✔ | ✔ |   |   |
|EDDSA             |   |   | ⚐ | ⚐ |   | ⚐ |   |   | ✔ | ✔ |   |   |
|ECDH              |   |   |   |   |   | _ | _ | _ | _ | _ |   |   |
|AES-CTR           | ⚐ | ⚐ |   |   |   | ✔ |   |   | ✔ | ✔ | ✔ | ✔ |
|AES-CBC           | ✔ | ✔ |   |   |   | ✔ |   |   | ✔ | ✔ | ✔ | ✔ |
|AES-GCM           | ✔ | ✔ |   |   |   | ✔ |   |   | ✔ | ✔ | ✔ | ✔ |
|AES-KW            |   |   |   |   |   | ✔ |   |   | ✔ | ✔ | ✔ | ✔ |
|HMAC              |   |   | ✔ | ✔ |   | ✔ |   |   | ✔ | ✔ |   |   |
|SHA-1             |   |   |   |   | ✔ |   |   |   |   |   |   |   |
|SHA-256           |   |   |   |   | ✔ |   |   |   |   |   |   |   |
|SHA-384           |   |   |   |   | ✔ |   |   |   |   |   |   |   |
|SHA-512           |   |   |   |   | ✔ |   |   |   |   |   |   |   |
|HKDF              |   |   |   |   |   |   | _ | _ | _ |   |   |   |
|PBKDF2            |   |   |   |   |   |   | _ | _ | _ |   |   |   |

Key:

` ✔ ` Implemented
` _ ` Currently not implemented
` ⚐ ` Partially implemented, only certain paramaters supported.

## Partial Support
Only the following paramaters are supported for the corresponding algorithm.

| Algorithm name | Supported paramater |
| -------------- | ------------------- |
| ECDSA          | `K-256 (secp256k1)`, `P-256`, `P-384`, `P-512` |
| EDDSA          | `ed25519`           | 
| AES-CTR        | `sha-1`             |


## API

See [W3C Web Cryptography API][webcrypto] specification and diafygi's [webcrypto-examples][examples].

[examples]: https://github.com/diafygi/webcrypto-examples

## Contribute

### Issues

* Please file [issues](https://github.com/anvilresearch/webcrypto/issues) :)
* When writing a bug report, include relevant details such as platform, version, relevant data, and stack traces
* Ensure to check for existing issues before opening new ones
* Read the documentation before asking questions
* It is strongly recommended to open an issue before hacking and submitting a PR
* We reserve the right to close an issue for excessive bikeshedding

### Pull requests

#### Policy

* We're not presently accepting *unsolicited* pull requests
* Create an issue to discuss proposed features before submitting a pull request
* Create an issue to propose changes of code style or introduce new tooling
* Ensure your work is harmonious with the overall direction of the project
* Ensure your work does not duplicate existing effort
* Keep the scope compact; avoid PRs with more than one feature or fix
* Code review with maintainers is required before any merging of pull requests
* New code must respect the style guide and overall architecture of the project
* Be prepared to defend your work

#### Style guide

* ES6
* Standard JavaScript
* jsdocs

#### Code reviews

* required before merging PRs
* reviewers MUST run and test the code under review

### Collaborating

#### Weekly project meeting

* Thursdays from 1:00 PM to 2:00 Eastern US time at [TBD]
* Join remotely with Google Hangouts

#### Pair programming

* Required for new contributors
* Work directly with one or more members of the core development team

### Code of conduct

* @trust/webcrypto follows the [Contributor Covenant](http://contributor-covenant.org/version/1/3/0/) Code of Conduct.

### Contributors

* Christian Smith [@christiansmith](https://github.com/christiansmith)
* Dmitri Zagidulin [@dmitrizagidulin](https://github.com/dmitrizagidulin)
* Greg Linklater [@EternalDeiwos](https://github.com/EternalDeiwos)
* JC Bailey [@thelunararmy](https://github.com/thelunararmy)
* Ioan Budea [@johnny90](https://github.com/johnny90)
* Abdulrahman Alotaibi [@adminq80](https://github.com/adminq80)
* Linus Unnebäck [@LinusU](https://github.com/LinusU)
* Len Boyette [@kevlened](https://github.com/kevlened)
* Tom Bonner [@Glitch0011](https://github.com/Glitch0011)
## MIT License

Copyright (c) 2016 Anvil Research, Inc.
