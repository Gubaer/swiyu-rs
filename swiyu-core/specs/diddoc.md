This is the specification for the `diddoc` module in this repository.

The `diddoc` module provides the data structures for a DID Doc according to the [DID 1.0][did-1-0] specification. 


# Requirements
* The module must provide a public struct called `DIDDoc`
* The structure must hold the data according to the [DID Doc Data Model][did-1-0-data-model].
* Create an `impl` block for structs
    * There must be suitable constructors
    * Implement required getters
* Implement `TryFrom<&Value> for DIDDoc`. It builds a DIDDoc from the JSON-LD representation according to [this specification](https://www.w3.org/TR/did-1.0/#consumption-0).
* Implement `From<DIDDoc> for Value`. It converts a DIDDoc to a JSON object according to [this specification](https://www.w3.org/TR/did-1.0/#production-0).

# Public Keys
* Add a struct `PublicKeyJWK`. The structure must hold the data elements of a PublicKeyJWK according to RFC 7517
* Create an `impl` block for `PublicKeyJWK`
    * There must be suitable constructors
    * Implement required getters
* Implement `TryFrom<&Value> for PublicKeyJWK`. It builds a PublicKeyJWK from its JSON representation according to RFC 7515.
* Implement `From<PublicKeyJWK> for Value`. It converts a PublicKeyJWK to a JSON object according to RFC 7515.

* Add a struct `PublicKeyMultibase`. The structure must hold the raw value of a PublicKey.
* Create an `impl` block for `PublicKeyMultibase`
    * There must be suitable constructors
    * Implement a getter for the raw key data
* Implement `FromStr for PublicKeyMultibase`. It builds a PublicKeyMultibase from its string representation according to [this specification](https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03). Only support `z` as a prefix. Return an error otherwise.
* Implement `Display for PublicKeyMultibase`. It converts a PublicKeyMultibase to a string using the encoding *base58 bitcoin*.


[did-1-0]: https://www.w3.org/TR/did-1.0/
[did-1-0-data-model]: https://www.w3.org/TR/did-1.0/#data-model