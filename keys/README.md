# keys/

`zkasper_verifier-keypair.json` is the program keypair for the address in
`declare_id!`, so `scripts/demo.sh` deploys to a predictable place on a local
validator.

**It is public. Treat it as a local-development keypair and nothing else.**

Anyone can deploy a program at this address on any cluster where it is still
free. A real deployment must generate its own keypair, keep it private, and
update `declare_id!` in `program/src/lib.rs` to match:

```sh
solana-keygen new --outfile my-program-keypair.json
solana-keygen pubkey my-program-keypair.json
```
