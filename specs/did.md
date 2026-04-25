This is the specification for `did` module in this repository.

The `did` module provides the data structures for a DID according to the [did:tdw v0.3][did-tdw-v0-3] specification. The `did:tdw` DID Method is currently used in the Swiss Trust Infrastructure for the Swiss E-ID.

# Requirements

* The module must provide a public struct called `DID_TDW`. It is already defined in `did/mod.rs`. 
* Create an `impl` block for `DID_TDW`
* In `parse` and in `new` make sure
    * that the domain is `.`-seperated sequence of domain-segments
    * the path is a `:`-seperated list of path-segments




[did-tdw-v0-3]: https://identity.foundation/didwebvh/v0.3/