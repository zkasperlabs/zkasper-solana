# keys/

`zkasper_verifier-keypair.json` is a **public** development keypair. Treat it as
a local-development keypair and nothing else: anyone can deploy a program at this
address on any cluster where it is still free.

**It no longer matches `declare_id!`.** As of 2026-08-20 the program declares
`DNDHd2Rp2JyDy7ENtuYLnDirUxtLRyWowsJMd4CppWkn`, deployed on devnet, whose keypair
is held outside this repository and is not public. The old address
`Cuarryex9DFpVm6HNdCFvpS3EEeArSuTXDMNTk9hpKja` was deployed to devnet and then
closed to reclaim its rent, so it can never be deployed to again.

`scripts/build.sh` reads `PROGRAM_KEYPAIR` and falls back to this file. Because
`cli/` resolves the program id from `declare_id!` and nothing else, a build whose
keypair does not match that constant produces a deployment no client can talk to.
So for a local demo, either point `PROGRAM_KEYPAIR` at a keypair matching
`declare_id!`, or generate a fresh one and change `declare_id!` to match:

```sh
solana-keygen new --outfile my-program-keypair.json
solana-keygen pubkey my-program-keypair.json     # paste into declare_id!
PROGRAM_KEYPAIR=my-program-keypair.json ./scripts/build.sh
```

A real deployment must generate its own keypair and keep it private.
