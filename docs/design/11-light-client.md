# Light-client status

A proof-only light client is not implemented. Complete chunk proofs can be verified
from an explicitly trusted incoming consensus context, but they do not prove their
own starting context is canonical or connect arbitrary history back to genesis.

`Checkpoint` and recursive wire/RPC types are deferred scaffolding. No production
checkpoint Guest or recursive prover exists. A future design must authenticate the
chain/spec and all context transitions, support gaps and upgrades, and define
bootstrap/retention policies before claiming succinct historical verification.

Current supported synchronization is full execution with block proofs and complete
chunk boundary proofs. See [networking](06-networking.md).
