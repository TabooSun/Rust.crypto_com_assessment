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

use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use std::rc::Rc;

use sha2::Digest;

fn main() {
    // let data = example_data(4);
}

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

/// A Merkle Tree.
#[derive(Debug, Clone)]
pub struct MerkleTree<'a> {
    pub root: MerkleNodeRef<'a>,
}

type MerkleNodeRef<'a> = Rc<RefCell<MerkleNode<'a>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleNode<'a> {
    /// The hashed data.
    hash: &'a Hash,
    raw_data: Data,
    /// Parent node
    ///
    /// If the parent node is null, it is the root node.
    parent: Option<MerkleNodeRef<'a>>,
    left: Option<MerkleNodeRef<'a>>,
    right: Option<MerkleNodeRef<'a>>,
}

impl<'a> MerkleNode<'a> {
    pub fn get_sibling(&self) -> Option<(MerkleNodeRef<'a>, HashDirection)> {
        match &self.parent {
            None => None,
            Some(parent) => {
                let self_hash = Some(self.hash.to_owned());
                let parent_borrowed = parent.borrow();
                if parent_borrowed.left.as_ref().map(|left| left.borrow().hash.clone()) == self_hash {
                    return parent_borrowed.right.clone().map(|right| (right, HashDirection::Right));
                }

                if parent_borrowed.right.to_owned().map(|right| right.borrow().hash.clone()) == self_hash {
                    return parent_borrowed.left.clone().map(|left| (left, HashDirection::Left));
                }

                None
            }
        }
    }
}

impl<'a> Display for MerkleNode<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MerkleNode: {}", hex::encode(&self.hash))
    }
}

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

impl<'a> MerkleTree<'a> {
    /// Gets root hash for this tree
    pub fn root(&self) -> Hash {
        self.root.borrow().hash.clone()
    }

    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        let chunks = input.chunks(2);
        let mut workspace: Vec<MerkleNodeRef> = Vec::new();
        for chunk in chunks.clone() {
            let node = MerkleTree::construct_from_data(chunk);
            println!("{:#?}", hex::encode(&node.borrow().hash));
            workspace.push(node);
        }

        loop {
            let cloned_workspace = workspace.to_owned();

            let workspace_chunks = cloned_workspace.chunks(2);
            workspace.clear();

            for chunk in workspace_chunks.clone() {
                let node = MerkleTree::construct_from_nodes(chunk);
                println!("{:#?}", hex::encode(&node.borrow().hash));
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

    /// Constructs a Merkle node from given input nodes.
    ///
    /// # Arguments
    ///
    /// * `nodes`: A group of Merkle nodes. Must be less than or equal to 2.
    ///
    /// returns: MerkleNode that contains the two input nodes.
    fn construct_from_nodes(nodes: &[MerkleNodeRef<'a>]) -> MerkleNodeRef<'a> {
        if nodes.len() > 2 {
            panic!("Input data must be less than or equal to 2");
        }

        let nodes = nodes.to_owned();
        let mut node_iter = nodes.into_iter();
        let left_node = node_iter.next().unwrap();
        let right_node = node_iter.next();

        let parent_node = Self::create_parent_node(left_node, right_node);
        parent_node
    }

    fn create_parent_node(left: MerkleNodeRef<'a>, right: Option<MerkleNodeRef<'a>>) -> MerkleNodeRef<'a> {
        let parent_hash = match &right {
            None => { left.borrow().hash }
            Some(right) => {
                hash_concat(&left.borrow().hash, &right.borrow().hash).as_slice()
            }
        };
        let mut parent = MerkleNode {
            hash: parent_hash,
            raw_data: match &right {
                None => { left.borrow().raw_data.clone() }
                Some(right) => {
                    left.borrow().raw_data.iter().copied().chain(right.borrow().raw_data.iter().copied()).collect()
                }
            },
            parent: None,
            left: Some(left),
            right,
        };

        let boxed_parent = Rc::new(RefCell::new(parent.to_owned()));
        if let Some(ref mut left_child) = parent.left {
            let mut left_child = left_child.borrow_mut();
            left_child.parent = Some(boxed_parent.clone());
        }

        boxed_parent.clone().borrow().left.clone().unwrap().borrow().parent.clone().unwrap();
        if let Some(ref mut right_child) = parent.right {
            let mut right_child = right_child.borrow_mut();
            right_child.parent = Some(boxed_parent.clone());
        }
        boxed_parent
    }

    /// Constructs a pair of Merkle nodes from given input data.
    ///
    /// # Arguments
    ///
    /// * `input`: A group of data. Must be less than or equal to 2.
    ///
    /// returns: MerkleNode that contains the two input nodes.
    fn construct_from_data(input: &'a [Data]) -> MerkleNodeRef<'a> {
        if input.len() > 2 {
            panic!("Input data must be less than or equal to 2");
        }

        let mut input_iter = input.iter();
        let left_data = input_iter.next().unwrap();
        let left = Rc::new(RefCell::new(MerkleNode {
            hash: &hash_data(left_data),
            raw_data: left_data.clone(),
            parent: None,
            left: None,
            right: None,
        }));
        let right_data = input_iter.next();
        let right = right_data.map(|right_data| Rc::new(RefCell::new(MerkleNode {
            hash: &hash_data(right_data),
            raw_data: right_data.clone(),
            parent: None,
            left: None,
            right: None,
        })));
        let parent_node = Self::create_parent_node(left, right);
        parent_node
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        let tree = MerkleTree::construct(input);
        let tree_root = tree.root();
        tree_root == *root_hash
    }

    /// Verifies that the given data and proof_path correctly produce the given root_hash
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let mut workspace: Hash = hash_data(data);
        for (direction, hash) in &proof.hashes {
            workspace = match direction {
                HashDirection::Left => {
                    hash_concat(hash, &workspace)
                }
                HashDirection::Right => {
                    hash_concat(&workspace, hash)
                }
            };
            println!("{:#?}", hex::encode(&workspace));
        }

        workspace == *root_hash
    }

    /// Returns a list of hashes that can be used to prove that the given data is in this tree
    pub fn prove(&'a self, data: &Data) -> Option<Proof<'a>> {
        let hashed_data = hash_data(data);

        let mut proof_hashes: Vec<(HashDirection, &Hash)> = vec![];
        proof_hashes.push((HashDirection::Left, &self.root.borrow().left.as_ref().unwrap().borrow().hash));
        self.prove_core(&hashed_data, &mut proof_hashes);

        Some(Proof {
            hashes: proof_hashes,
        })
    }

    fn prove_core(&self, hashed_data: &Hash, proof_hashes: &mut Vec<(HashDirection, &'a Hash)>) {
        let hashed_data_node = Self::find_node(hashed_data, Some(&self.root));
        hashed_data_node.clone().unwrap().borrow().parent.clone().unwrap().borrow().parent.clone().unwrap();
        Self::drive_path(&hashed_data_node.unwrap(), proof_hashes);
    }

    fn drive_path(node: &MerkleNodeRef<'a>, proof_hashes: &mut Vec<(HashDirection, &'a Hash)>) {
        match &node.borrow().parent {
            None => {
                // This is a root node. Nothing to do here. We can close our recursive loop now.
            }
            Some(parent) => {
                let sibling = node.borrow().get_sibling();
                match sibling {
                    None => {}
                    Some((sibling, direction)) => {
                        proof_hashes.push((direction, sibling.borrow().hash));
                    }
                }

                Self::drive_path(parent, proof_hashes);
            }
        }
    }

    fn find_node(hashed_data: &Hash, parent_node: Option<&MerkleNodeRef<'a>>) -> Option<MerkleNodeRef<'a>> {
        match parent_node {
            None => None,
            Some(parent_node) => {
                let left = Self::find_node(hashed_data, parent_node.borrow().left.as_ref());
                if left.is_some() {
                    return left;
                }

                let right = Self::find_node(hashed_data, parent_node.borrow().right.as_ref());
                if right.is_some() {
                    return right;
                }

                if parent_node.borrow().hash == hashed_data {
                    return Some(parent_node.to_owned());
                }

                None
            }
        }
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
        let data = example_data(3);
        let tree = MerkleTree::construct(&data);
        let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root()), expected_root);
    }

    #[test]
    fn test_verify() {
        // Arrange
        let data = example_data(4);
        let root_hash = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";

        // Act
        let result = MerkleTree::verify(&data, &hex::decode(root_hash).unwrap());

        // Assert
        assert!(result);
    }

    #[test]
    fn test_verify_proof() {
        // Arrange
        let data = example_data(4);
        let data_to_prove = &vec![2u8].clone();
        let h4 = hash_data(&vec![3u8].clone());
        println!("h4: {:#?}", hex::encode(&h4));
        let h1 = hash_data(&vec![0u8].clone());
        println!("h1: {:#?}", hex::encode(&h1));
        let h2 = hash_data(&vec![1u8].clone());
        println!("h2: {:#?}", hex::encode(&h2));
        let h5 = hash_concat(&h1, &h2);
        println!("h5: {:#?}", hex::encode(&h5));
        let prove = Proof {
            hashes: vec![
                (HashDirection::Right, &h4),
                (HashDirection::Left, &h5),
            ],
        };
        let root_hash = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";

        // Act
        let result = MerkleTree::verify_proof(data_to_prove, &prove, &hex::decode(root_hash).unwrap());

        // Assert
        assert!(result);
    }

    #[test]
    fn test_prove() {
        // Arrange
        let data = example_data(4);
        let data_to_prove = &vec![2u8].clone();
        let h4 = hash_data(&vec![3u8].clone());
        println!("h4: {:#?}", hex::encode(&h4));
        let h1 = hash_data(&vec![0u8].clone());
        println!("h1: {:#?}", hex::encode(&h1));
        let h2 = hash_data(&vec![1u8].clone());
        println!("h2: {:#?}", hex::encode(&h2));
        let h5 = hash_concat(&h1, &h2);
        println!("h5: {:#?}", hex::encode(&h5));
        let prove = Proof {
            hashes: vec![
                (HashDirection::Right, &h4),
                (HashDirection::Left, &h5),
            ],
        };
        let tree = MerkleTree::construct(&data);

        // Act
        let result = tree.prove(data_to_prove);

        // Assert
        assert_eq!(result, Some(prove));
    }

    #[test]
    fn test_structure_correct() {
        let data = example_data(4);

        let tree = MerkleTree::construct(&data);
        tree.root.clone().borrow().right.clone().unwrap().borrow().left.clone().unwrap().borrow().parent.clone().unwrap().borrow().parent.clone().unwrap();
        /*println!("{:#?}", tree);
        let root = tree.root;
        let left = root.left.unwrap();
        left.parent.unwrap();
        let right = root.right.unwrap();
        right.parent.unwrap();
        let left_left = left.left.unwrap();
        let left_right = left.right.unwrap();
        let right_left = right.left.unwrap();
        let right_right = right.right.unwrap();*/
    }

    #[test]
    fn test_hash_by_raw_data() {
        let data = vec![vec![0], vec![1], vec![2], vec![3]];
        let vec0_hashed = hash_data(&data[0]);
        let vec1_hashed = hash_data(&data[1]);
        let vec0_vec1_hashed = hash_concat(&vec0_hashed, &vec1_hashed);
        println!("vec0_vec1_hashed/h5: {:#?}", hex::encode(&vec0_vec1_hashed));
        let vec2_hashed = hash_data(&data[2]);
        let vec3_hashed = hash_data(&data[3]);
        let vec2_vec3_hashed = hash_concat(&vec2_hashed, &vec3_hashed);
        println!("vec2_vec3_hashed/h6: {:#?}", hex::encode(&vec2_vec3_hashed));
        let vec0_vec1_vec2_vec3_hashed = hash_concat(&vec0_vec1_hashed, &vec2_vec3_hashed);
        println!("vec0_vec1_vec2_vec3_hashed: {:#?}", hex::encode(vec0_vec1_vec2_vec3_hashed));
    }

    #[test]
    fn test_hash_by_raw_data_unbalanced() {
        let data = vec![vec![0], vec![1], vec![2]];
        let vec0_hashed = hash_data(&data[0]);
        let vec1_hashed = hash_data(&data[1]);
        let vec0_vec1_hashed = hash_concat(&vec0_hashed, &vec1_hashed);
        println!("vec0_vec1_hashed: {:#?}", hex::encode(&vec0_vec1_hashed));
        let vec2_hashed = hash_data(&data[2]);
        println!("vec2_hashed: {:#?}", hex::encode(&vec2_hashed));
        let vec0_vec1_vec2_hashed = hash_concat(&vec0_vec1_hashed, &vec2_hashed);
        println!("vec0_vec1_vec2_hashed: {:#?}", hex::encode(vec0_vec1_vec2_hashed));
    }

    #[test]
    fn test_find_node() {
        // Arrange
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let data_to_find = vec![2u8];

        // Act
        // let result = MerkleTree::find_node(&hash_data(&data_to_find), Some(&tree.root));
    }
}
