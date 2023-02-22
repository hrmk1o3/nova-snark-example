use std::collections::HashMap;

use ff::PrimeField;
use generic_array::typenum::U2;
use neptune::{poseidon::PoseidonConstants, Poseidon};

/// Can be a leaf of Merkle trees.
pub trait Leafable<F: PrimeField>: Clone {
    /// Default hash which indicates empty value.
    fn empty_leaf() -> Self;

    /// Hash of its value.
    fn hash(&self) -> F;
}

impl<F: PrimeField> Leafable<F> for F {
    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> F {
        *self
    }
}

#[derive(Debug)]
pub struct MerkleTree<F: PrimeField, V: Leafable<F>> {
    pub(crate) poseidon_constants: PoseidonConstants<F, U2>,
    pub(crate) height: usize,
    pub(crate) node_hashes: HashMap<Vec<bool>, F>,
    pub(crate) leaves: HashMap<usize, V>,
    pub(crate) zero_hashes: Vec<F>,
}

impl<F: PrimeField, V: Leafable<F>> MerkleTree<F, V> {
    pub fn new(height: usize) -> Self {
        let poseidon_constants = PoseidonConstants::new();
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let mut h = V::empty_leaf().hash();
        zero_hashes.push(h);
        for _ in 0..height {
            h = Poseidon::new_with_preimage(&[h, h], &poseidon_constants).hash();
            zero_hashes.push(h);
        }
        zero_hashes.reverse();

        let node_hashes: HashMap<Vec<bool>, F> = HashMap::new();
        let leaves: HashMap<usize, V> = HashMap::new();

        Self {
            poseidon_constants,
            height,
            node_hashes,
            leaves,
            zero_hashes,
        }
    }

    fn get_node_hash(&self, path: &Vec<bool>) -> F {
        assert!(path.len() <= self.height);
        match self.node_hashes.get(path) {
            Some(h) => *h,
            None => self.zero_hashes[path.len()],
        }
    }

    fn get_sibling_hash(&self, path: &Vec<bool>) -> F {
        assert!(!path.is_empty());
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];
        self.get_node_hash(&path)
    }

    pub fn get_root(&self) -> F {
        self.get_node_hash(&vec![])
    }

    pub fn get_leaf(&self, index: usize) -> V {
        match self.leaves.get(&index) {
            Some(leaf) => leaf.clone(),
            None => V::empty_leaf(),
        }
    }

    pub fn update(&mut self, index: usize, leaf: V) {
        let mut path = usize_to_vec(index, self.height);

        self.leaves.insert(index, leaf.clone());

        let mut h = leaf.hash();
        self.node_hashes.insert(path.clone(), h);

        while !path.is_empty() {
            let sibling = self.get_sibling_hash(&path);
            let preimage = if path.pop().unwrap() {
                vec![sibling, h]
            } else {
                vec![h, sibling]
            };
            h = Poseidon::new_with_preimage(&preimage, &self.poseidon_constants).hash();
            self.node_hashes.insert(path.clone(), h);
        }
    }

    pub fn remove(&mut self, index: usize) {
        self.update(index, V::empty_leaf())
    }

    pub fn prove(&self, index: usize) -> Vec<F> {
        let mut path = usize_to_vec(index, self.height);
        let mut siblings = vec![];
        while !path.is_empty() {
            siblings.push(self.get_sibling_hash(&path));
            path.pop();
        }

        siblings
    }
}

/// usize to big endian bool vec.
pub fn usize_to_vec(x: usize, length: usize) -> Vec<bool> {
    let mut x = x;
    let mut v = vec![];
    for _ in 0..length {
        v.push((x & 1) == 1);
        x >>= 1;
    }
    v.reverse();
    v
}
