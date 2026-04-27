This is the specification for `did` module in this repository.

The `did` module provides the data structures for a DID according to the [did:tdw v0.3][did-tdw-v0-3] specification. The `did:tdw` DID Method is currently used in the Swiss Trust Infrastructure for the Swiss E-ID.

The `did` module also provides data structures for a DID according to the [did:webvh v1.0][did-webvh-v1-0] specification. It will be used in the future in the Swiss Trust Infrastructure. 

# Requirements

* The module must provide a public struct called `DID`. 
* Create an `impl` block for `DID`
* In `parse` and in `new` make sure
    * that the domain is `.`-seperated sequence of domain-segments
    * the path is a `:`-seperated list of path-segments

[did-tdw-v0-3]: https://identity.foundation/didwebvh/v0.3/
[did-webvh-v1-0]: https://identity.foundation/didwebvh/v1.0/