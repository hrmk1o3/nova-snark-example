type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;
use flate2::{write::ZlibEncoder, Compression};
use neptune::poseidon::PoseidonConstants;
use nova_snark::{
    traits::{circuit::TrivialTestCircuit, Group},
    CompressedSNARK, PublicParams, RecursiveSNARK,
};
use nova_snark_example::merkle_tree::{circuits::MerkleProcessCircuit, tree::MerkleTree};
use std::time::Instant;

fn main() {
    println!("Nova-based Merkle process proof");
    println!("=========================================================");

    type F = <G1 as Group>::Scalar;

    let num_steps = 10;
    {
        let num_levels = 16;
        debug_assert!(num_steps < 1 << num_levels, "insufficient height");

        // number of iterations of MinRoot per Nova's recursive step
        let poseidon_constants = PoseidonConstants::new();
        let circuit_primary = MerkleProcessCircuit {
            constants: poseidon_constants.clone(),
            siblings: vec![F::zero(); num_levels],
            index: 0,
            old_value: F::zero(),
            new_value: F::zero(),
        };

        let circuit_secondary = TrivialTestCircuit::default();

        println!("Proving {num_levels} levels of MerkleProcessProof per step");

        // produce public parameters
        let start = Instant::now();
        println!("Producing public parameters...");
        let pp = PublicParams::<
            G1,
            G2,
            MerkleProcessCircuit<<G1 as Group>::Scalar>,
            TrivialTestCircuit<<G2 as Group>::Scalar>,
        >::setup(circuit_primary, circuit_secondary.clone());
        println!("PublicParams::setup, took {:?} ", start.elapsed());

        println!(
            "Number of constraints per step (primary circuit): {}",
            pp.num_constraints().0
        );
        println!(
            "Number of constraints per step (secondary circuit): {}",
            pp.num_constraints().1
        );

        println!(
            "Number of variables per step (primary circuit): {}",
            pp.num_variables().0
        );
        println!(
            "Number of variables per step (secondary circuit): {}",
            pp.num_variables().1
        );

        // produce non-deterministic advice
        let mut tree: MerkleTree<F, F> = MerkleTree::new(num_levels);
        let oldest_root = tree.get_root();

        let old_value = F::zero();
        let new_value = F::one();
        let mut poseidon_circuits = vec![];
        for index in 0..num_steps {
            tree.update(index, new_value);
            let siblings = tree.prove(index);

            poseidon_circuits.push(MerkleProcessCircuit {
                constants: poseidon_constants.clone(),
                siblings: siblings.clone(),
                index,
                old_value,
                new_value,
            });
        }
        let latest_root = tree.get_root();

        let z0_primary = vec![oldest_root];

        let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

        type C1 = MerkleProcessCircuit<<G1 as Group>::Scalar>;
        type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;
        // produce a recursive SNARK
        println!("Generating a RecursiveSNARK...");
        let mut recursive_snark: Option<RecursiveSNARK<G1, G2, C1, C2>> = None;

        for (i, circuit_primary) in poseidon_circuits.iter().take(num_steps).enumerate() {
            let start = Instant::now();
            let res = RecursiveSNARK::prove_step(
                &pp,
                recursive_snark,
                circuit_primary.clone(),
                circuit_secondary.clone(),
                z0_primary.clone(),
                z0_secondary.clone(),
            )
            .unwrap();
            println!(
                "RecursiveSNARK::prove_step {}: took {:?} ",
                i,
                start.elapsed()
            );
            recursive_snark = Some(res);
        }

        assert!(recursive_snark.is_some());
        let recursive_snark = recursive_snark.unwrap();

        // verify the recursive SNARK
        println!("Verifying a RecursiveSNARK...");
        let start = Instant::now();
        let res = recursive_snark.verify(&pp, num_steps, z0_primary.clone(), z0_secondary.clone());

        println!(
            "RecursiveSNARK::verify: {:?}, took {:?}",
            res.is_ok(),
            start.elapsed()
        );
        assert!(res.is_ok());

        // produce a compressed SNARK
        println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
        let start = Instant::now();
        type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<G1>;
        type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<G2>;
        type S1 = nova_snark::spartan::RelaxedR1CSSNARK<G1, EE1>;
        type S2 = nova_snark::spartan::RelaxedR1CSSNARK<G2, EE2>;

        let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &recursive_snark).unwrap();
        println!("CompressedSNARK::prove: took {:?}", start.elapsed());
        let compressed_snark = res;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
        let compressed_snark_encoded = encoder.finish().unwrap();
        println!(
            "CompressedSNARK::len {:?} bytes",
            compressed_snark_encoded.len()
        );

        // verify the compressed SNARK
        println!("Verifying a CompressedSNARK...");
        let start = Instant::now();
        let (zn_primary, _) = compressed_snark
            .verify(&pp, num_steps, z0_primary, z0_secondary)
            .unwrap();
        println!("CompressedSNARK::verify took {:?}", start.elapsed());
        assert_eq!(
            zn_primary[0], latest_root,
            "invalid public inputs of the last proof"
        );
        println!("=========================================================");
    }
}
