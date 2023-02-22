use bellperson::{
    gadgets::{boolean::AllocatedBit, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use ff::PrimeField;
use generic_array::typenum::U2;
use neptune::{circuit::poseidon_hash, poseidon::PoseidonConstants, Poseidon};
use nova_snark::traits::circuit::StepCircuit;

use super::tree::usize_to_vec;

#[derive(Clone, Debug)]
pub struct InternalHashCircuit<F: PrimeField> {
    pub constants: PoseidonConstants<F, U2>,
    pub sibling: F,
    pub lr_bit: bool,
}

impl<F> StepCircuit<F> for InternalHashCircuit<F>
where
    F: PrimeField,
{
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>], // child node
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let sibling =
            AllocatedNum::alloc(cs.namespace(|| "allocate sibling"), || Ok(self.sibling))?;
        let lr_bit = AllocatedBit::alloc(cs.namespace(|| "allocate lr_bit"), Some(self.lr_bit))?;
        let (l, r) = AllocatedNum::conditionally_reverse(
            cs.namespace(|| "reverse children"),
            &z[0],
            &sibling,
            &lr_bit.into(),
        )?;
        let output = poseidon_hash(
            cs.namespace(|| "calculate poseidon"),
            vec![l, r],
            &self.constants,
        )?;

        let result = vec![output];

        Ok(result)
    }

    fn output(&self, z: &[F]) -> Vec<F> {
        debug_assert_eq!(z.len(), self.arity());

        let preimage = if self.lr_bit {
            vec![self.sibling, z[0]]
        } else {
            vec![z[0], self.sibling]
        };
        let mut poseidon = Poseidon::new_with_preimage(&preimage, &self.constants);
        let output = poseidon.hash();

        let result = vec![output];

        result
    }
}

#[derive(Clone, Debug)]
pub struct MerkleInclusionCircuit<F: PrimeField> {
    pub constants: PoseidonConstants<F, U2>,
    pub siblings: Vec<F>,
    pub index: usize,
    pub value: F,
}

impl<F> MerkleInclusionCircuit<F>
where
    F: PrimeField,
{
    pub fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let value = AllocatedNum::alloc(cs.namespace(|| "allocate value"), || Ok(self.value))?;
        let path = usize_to_vec(self.index, self.siblings.len());
        let mut result = vec![value];
        for (i, (&lr_bit, &sibling)) in path.iter().rev().zip(self.siblings.iter()).enumerate() {
            let poseidon_circuit = InternalHashCircuit {
                constants: self.constants.clone(),
                sibling,
                lr_bit,
            };

            result = poseidon_circuit.synthesize(
                &mut cs.namespace(|| format!("calculate parent hash {i}")),
                &result,
            )?;
        }

        Ok(vec![result[0].clone()]) // root hash
    }

    pub fn output(&self) -> Vec<F> {
        let mut result = vec![self.value];
        let path = usize_to_vec(self.index, self.siblings.len());
        for (&lr_bit, &sibling) in path.iter().rev().zip(self.siblings.iter()) {
            let poseidon_circuit = InternalHashCircuit {
                constants: self.constants.clone(),
                sibling,
                lr_bit,
            };

            result = poseidon_circuit.output(&result);
        }

        // assert_eq!(result[0], self.root);

        vec![result[0]]
    }
}

#[derive(Clone, Debug)]
pub struct MerkleProcessCircuit<F: PrimeField> {
    pub constants: PoseidonConstants<F, U2>,
    pub siblings: Vec<F>,
    pub index: usize,
    pub old_value: F,
    pub new_value: F,
}

impl<F> StepCircuit<F> for MerkleProcessCircuit<F>
where
    F: PrimeField,
{
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>], // old root
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let old_poseidon_circuit = MerkleInclusionCircuit {
            constants: self.constants.clone(),
            siblings: self.siblings.clone(),
            index: self.index,
            value: self.old_value,
        };

        let old_result =
            old_poseidon_circuit.synthesize(&mut cs.namespace(|| "calculate old root"))?;

        // Ensure `old_result[0] == old_root`
        cs.enforce(
            || "verify old root",
            |lc| lc,
            |lc| lc,
            |lc| lc + old_result[0].get_variable() - z[0].get_variable(),
        );

        let new_poseidon_circuit = MerkleInclusionCircuit {
            constants: self.constants.clone(),
            siblings: self.siblings.clone(),
            index: self.index,
            value: self.new_value,
        };

        let new_result =
            new_poseidon_circuit.synthesize(&mut cs.namespace(|| "calculate new root"))?;

        Ok(vec![new_result[0].clone()]) // new root
    }

    fn output(&self, z: &[F]) -> Vec<F> {
        let old_poseidon_circuit = MerkleInclusionCircuit {
            constants: self.constants.clone(),
            siblings: self.siblings.clone(),
            index: self.index,
            value: self.old_value,
        };

        let old_result = old_poseidon_circuit.output();
        assert_eq!(old_result[0], z[0]);

        let new_poseidon_circuit = MerkleInclusionCircuit {
            constants: self.constants.clone(),
            siblings: self.siblings.clone(),
            index: self.index,
            value: self.new_value,
        };

        let new_result = new_poseidon_circuit.output();

        vec![new_result[0]]
    }
}
