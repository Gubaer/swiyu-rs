This is the specification for `did` module in this repository.

The `did` module provides the data structures for a DID Log with its entries according to the [did:tdw v0.3][did-tdw-v0-3] specification. The `did:tdw` DID Method is currently used in the Swiss Trust Infrastructure for the Swiss E-ID.

# Requirements
* The module must provide a public struct called `DIDTDWLog` and `DIDTDWLogEntry`
    * Both the structs must encapulate data according to sec 4.5 of the [did:tdw v0.3][did-tdw-v0-3] spec
    * Both the structs must provide public read access to the encapulated state
* Create an `impl` block for structs 
    * There must be suitable constructors 
    * Implement required getters
    * Implement `try_from_json` method. It builds a DIDTDWLogEntry from a already parsed JSON Object
    * Implement `to_json` method. It converts a DIDTDWLogEntry to a JSON object




