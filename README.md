# Nova SNARK Example

[Nova](https://github.com/microsoft/Nova)

## How to test

### Merkle process proof

Proves that the Merkle tree has been correctly updated at every step.
The root at the start of each step is bounded by the root at the end of the previous step.

```sh
cargo run --release --example merkle_process_proof
```

The above command produces the following output.

```txt
Nova-based Merkle process proof
=========================================================
Proving 16 levels of MerkleProcessProof per step
Producing public parameters...
PublicParams::setup, took 2.440531916s 
Number of constraints per step (primary circuit): 19864
Number of constraints per step (secondary circuit): 10347
Number of variables per step (primary circuit): 19889
Number of variables per step (secondary circuit): 10329
Generating a RecursiveSNARK...
RecursiveSNARK::prove_step 0: took 64.083625ms 
RecursiveSNARK::prove_step 1: took 95.79725ms 
RecursiveSNARK::prove_step 2: took 112.986083ms 
RecursiveSNARK::prove_step 3: took 106.729875ms 
RecursiveSNARK::prove_step 4: took 108.210583ms 
RecursiveSNARK::prove_step 5: took 107.373666ms 
RecursiveSNARK::prove_step 6: took 106.450708ms 
RecursiveSNARK::prove_step 7: took 107.952083ms 
RecursiveSNARK::prove_step 8: took 107.60175ms 
RecursiveSNARK::prove_step 9: took 107.896ms 
Verifying a RecursiveSNARK...
RecursiveSNARK::verify: true, took 78.51775ms
Generating a CompressedSNARK using Spartan with IPA-PC...
CompressedSNARK::prove: took 1.883280083s
CompressedSNARK::len 7799 bytes
Verifying a CompressedSNARK...
CompressedSNARK::verify took 72.608166ms
=========================================================
```
