/*

Building a simple Merkle Tree

Exercise 1:
    Given a set of data D, construct a Merkle Tree.

Assume that D is a power of 2 (the binary tree is perfect).

Example input:
    D = [A1, A2, A3, A4]

Example output:

                               Root
                           ┌──────────┐
                           │    H7    │
                           │ H(H5|H6) │
                  ┌────────┴──────────┴──────────┐
                  │                              │
                  │                              │
             ┌────┴─────┐                  ┌─────┴────┐
             │    H5    │                  │    H6    │
             │ H(H1|H2) │                  │ H(H3|H4) │
             └─┬─────┬──┘                  └─┬──────┬─┘
               │     │                       │      │
     ┌─────────┴┐   ┌┴─────────┐    ┌────────┴─┐  ┌─┴────────┐
     │   H1     │   │    H2    │    │    H3    │  │    H4    │
     │  H(A1)   │   │   H(A2)  │    │   H(A3)  │  │   H(A4)  │
     └───┬──────┘   └────┬─────┘    └────┬─────┘  └────┬─────┘
         │               │               │             │
         A1              A2              A3            A4


Exercise 1b:
    Write a function that will verify a given set of data with a given root hash.

Exercise 2:
    Write a function that will use a proof like the one in Exercise 3 to verify that the proof is indeed correct.

Exercise 3 (Hard):
    Write a function that returns a proof that a given data is in the tree.

    Hints:
        -   The proof should be a set of ordered data hashes and their positions (left 0 or right 1).
        -   Let's say we are asked to prove that H3 (A3) is in this tree. We have the entire tree so we can traverse it and find H3.
            Then we only need to return the hashes that can be used to calculate with the hash of the given data to calculate the root hash.
            i.e Given a data H3, a proof [(1, H4), (0, H5)] and a root:
                H3|H4 => H6 => H5|H6 => H7 = root

*/
#![allow(dead_code)]
#![allow(unused_variables)]

use std::fmt::{Display, Formatter};
use std::slice::Chunks;

use sha2::Digest;

fn main() {
    // let data = example_data(4);
    let data = vec![vec![0], vec![1], vec![2], vec![3]];
    let vec0_hashed = hash_data(&data[0]);
    let vec1_hashed = hash_data(&data[1]);
    let vec0_vec1_hashed = hash_concat(&vec0_hashed, &vec1_hashed);
    println!("vec0_vec1_hashed: {:#?}", hex::encode(&vec0_vec1_hashed));
    let vec2_hashed = hash_data(&data[2]);
    let vec3_hashed = hash_data(&data[3]);
    let vec2_vec3_hashed = hash_concat(&vec2_hashed, &vec3_hashed);
    println!("vec2_vec3_hashed: {:#?}", hex::encode(&vec2_vec3_hashed));
    let vec0_vec1_vec2_vec3_hashed = hash_concat(&vec0_vec1_hashed, &vec2_vec3_hashed);
    println!("vec0_hashed: {:#?}", hex::encode(vec0_vec1_vec2_vec3_hashed));
}

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

/// A Merkle Tree.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root: MerkleNode,
}

#[derive(Debug, Clone)]
pub struct MerkleNode {
    /// The hashed data.
    hash: Hash,
    raw_data: Data,
    /// Parent node
    ///
    /// If the parent node is null, it is the root node.
    parent: Option<Box<MerkleNode>>,
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
}

impl Display for MerkleNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MerkleNode: {}", hex::encode(&self.hash))
    }
}

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

impl MerkleTree {
    /// Gets root hash for this tree
    pub fn root(&self) -> Hash {
        self.root.hash.clone()
    }

    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        let chunks = input.chunks(2);
        let mut workspace: Vec<MerkleNode> = Vec::new();
        for chunk in chunks.clone() {
            let node = MerkleTree::construct_core(chunk);
            workspace.push(node);
        }

        let mut workspace_chunks: Chunks<MerkleNode>;
        loop {
            let cloned_workspace = workspace.to_owned();
            workspace_chunks = cloned_workspace.chunks(2);
            workspace.clear();

            for chunk in workspace_chunks.clone() {
                let node = MerkleTree::construct_from_nodes(chunk);
                workspace.push(node);
            }

            // We have done, and we have only one node left now.
            if workspace.len() == 1 {
                break;
            }
        }

        MerkleTree {
            root: workspace[0].to_owned(),
        }
    }

    fn construct_from_nodes(nodes: &[MerkleNode]) -> MerkleNode {
        if nodes.len() > 2 {
            panic!("Input data must be less than or equal to 2");
        }

        let mut node_iter = nodes.iter();
        let left_node = node_iter.next();
        let left_left_node = left_node.unwrap().left.clone().unwrap();
        let left_right_node = left_node.unwrap().right.clone().unwrap();
        let left = MerkleNode {
            hash: hash_concat(&left_left_node.hash, &left_right_node.hash),
            raw_data: left_node.unwrap().raw_data.clone(),
            parent: None,
            left: Some(left_left_node),
            right: Some(left_right_node),
        };
        let right_node = node_iter.next();
        let right = MerkleNode {
            hash: match right_node {
                None => { left.hash.clone() }
                Some(data) => {
                    let right_left_node = data.left.clone().unwrap();
                    let right_right_node = data.right.clone().unwrap();
                    hash_concat(&right_left_node.hash, &right_right_node.hash)
                }
            },
            raw_data: match right_node {
                None => { vec![] }
                Some(data) => {
                    data.raw_data.clone()
                }
            },
            parent: None,
            left: right_node.map(|right_node| right_node.left.clone()
                // We can safely unwrap here because we know that as long as this node exists, it must have a left node.
                .unwrap()),
            right: right_node.map(|right_node| right_node.right.clone()
                // We can safely unwrap here because we know that as long as this node exists, it must have a right node.
                .unwrap()),
        };

        Self::create_parent_node(left, right)
    }

    fn create_parent_node(left: MerkleNode, right: MerkleNode) -> MerkleNode {
        let mut parent = MerkleNode {
            hash: hash_concat(&left.hash, &right.hash),
            raw_data: left.raw_data.iter().copied().chain(right.raw_data.iter().copied()).collect(),
            parent: None,
            left: Some(Box::new(left.to_owned())),
            right: Some(Box::new(right.to_owned())),
        };

        parent.left.as_mut().unwrap().parent = Some(Box::new(parent.to_owned()));
        parent.right.as_mut().unwrap().parent = Some(Box::new(parent.to_owned()));
        parent
    }

    /// Constructs a pair of Merkle nodes from given input data.
    ///
    /// - [input] - A group of data. Must be less than or equal to 2.
    /// - Returns a parent node that contains the two input nodes.
    fn construct_core(input: &[Data]) -> MerkleNode {
        if input.len() > 2 {
            panic!("Input data must be less than or equal to 2");
        }

        let mut input_iter = input.iter();
        let left_data = input_iter.next().unwrap();
        let left = MerkleNode {
            hash: hash_data(left_data),
            raw_data: left_data.clone(),
            parent: None,
            left: None,
            right: None,
        };
        let right_data = input_iter.next();
        let right = MerkleNode {
            hash: match right_data {
                // In the event of unbalanced tree, reuse the left hash. Check https://medium.com/techskill-brew/merkle-tree-in-blockchain-part-5-blockchain-basics-4e25b61179a2 for more info.
                None => { left.hash.clone() }
                Some(data) => {
                    hash_data(data)
                }
            },
            raw_data: match right_data {
                None => { vec![] }
                Some(data) => {
                    data.clone()
                }
            },
            parent: None,
            left: None,
            right: None,
        };
        Self::create_parent_node(left, right)
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        todo!("Exercise 1b")
    }

    /// Verifies that the given data and proof_path correctly produce the given root_hash
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        todo!("Exercise 2")
    }

    /// Returns a list of hashes that can be used to prove that the given data is in this tree
    pub fn prove(&self, data: &Data) -> Option<Proof> {
        todo!("Exercise 3")
    }
}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_data(n: usize) -> Vec<Data> {
        let mut data = vec![];
        for i in 0..n {
            data.push(vec![i as u8]);
        }
        data
    }

    #[test]
    fn test_constructions() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert_eq!(hex::encode(tree.root()), expected_root);

        // Uncomment if your implementation allows for unbalanced trees
        // let data = example_data(3);
        // let tree = MerkleTree::construct(&data);
        // let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        // assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root()), expected_root);
    }

    #[test]
    fn test_structure_correct() {
        let data = example_data(4);

        let tree = MerkleTree::construct(&data);
        println!("{:#?}", tree);
        let root = tree.root;
        let left = root.left.unwrap();
        left.parent.unwrap();
        let right = root.right.unwrap();
        right.parent.unwrap();
        let left_left = left.left.unwrap();
        let left_right = left.right.unwrap();
        let right_left = right.left.unwrap();
        let right_right = right.right.unwrap();
    }
}
