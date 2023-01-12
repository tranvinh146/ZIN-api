use ark_bls12_381::Bls12_381;
use ark_ff::Fp256;
use ark_groth16::{Groth16, ProvingKey};
use commitment::Commitment;
use constraints::MerkleTreeVerification;
use rand::Rng;
use std::io;

use ark_crypto_primitives::{crh::TwoToOneCRH, MerkleTree, CRH, SNARK};

pub mod commitment;
pub mod common;
pub mod constraints;
use common::*;

pub fn main() {
    let mut rng = ark_std::test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    let mut tree = ZinMerkleTree::blank(&leaf_crh_params, &two_to_one_crh_params, 4).unwrap();
    let proof = tree.generate_proof(0).unwrap();

    let cs = MerkleTreeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root: tree.root(),
        leaf: Fp256::default(),
        hashed_nullifier: Fp256::default(),

        // witness
        commitment: Commitment {
            nullifier: 0,
            secret: 0,
        },
        path: Some(proof),
    };
    let (pk, _vk) = Groth16::<Bls12_381>::circuit_specific_setup(cs, &mut rng).unwrap();

    let mut index = 0;

    loop {
        let mut option = String::new();

        println!("\nChoose option: ");
        println!("\t1. Generate a commitment.");
        println!("\t2. Create a proof.");
        println!("\t3. Exit");

        io::stdin().read_line(&mut option).expect("Invalid Input");

        let number: u8 = match option.trim().parse() {
            Ok(num) => num,
            Err(_) => continue,
        };

        if number == 1 {
            gen_commitment(&mut tree, index);
            index += 1;
        }

        if number == 2 {
            create_proof(&tree, &pk);
        }

        if number == 3 {
            break;
        }
    }
}

pub fn gen_commitment(tree: &mut MerkleTree<MerkleConfig>, index: usize) {
    let mut rng = ark_std::test_rng();
    let _ = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    let mut nullifier_bytes = [0u8; 16];
    let mut secret_bytes = [0u8; 16];

    for i in 0..16 {
        let nullifier_byte: u8 = rand::thread_rng().gen_range(0..=255);
        let secret_byte: u8 = rand::thread_rng().gen_range(0..=255);

        nullifier_bytes[i] = nullifier_byte;
        secret_bytes[i] = secret_byte;
    }

    let nullifier_hex: String = nullifier_bytes
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("");
    let secret_hex: String = secret_bytes
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("");
    let index_hex: String = format!("{:02x}", index).to_string();

    let mut commitment_hex = String::from("0x");
    commitment_hex.push_str(&nullifier_hex);
    commitment_hex.push_str(&index_hex);
    commitment_hex.push_str(&secret_hex);

    println!("\nStore Secret in local: {:?}", commitment_hex);

    let nullifier = u128::from_str_radix(&nullifier_hex, 16).unwrap();
    let secret = u128::from_str_radix(&secret_hex, 16).unwrap();

    let commitment = <TwoToOneHash as TwoToOneCRH>::evaluate(
        &two_to_one_crh_params,
        &nullifier.to_le_bytes(),
        &secret.to_le_bytes(),
    )
    .unwrap();

    tree.update(index, &commitment).unwrap();

    let mut commitment_str = String::from("0x");
    commitment_str.push_str(&commitment.0.to_string());
    println!(
        "Submit Hashed Commitment to blockchain: {:?}",
        commitment_str
    );
    println!("\n\n=======================================================");
}

pub fn create_proof(tree: &MerkleTree<MerkleConfig>, pk: &ProvingKey<Bls12_381>) {
    let mut rng = ark_std::test_rng();
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    let mut raw_commitment = String::new();
    println!("Input raw commitment: ");
    io::stdin()
        .read_line(&mut raw_commitment)
        .expect("Invalid Input");

    let without_prefix = raw_commitment.trim_start_matches("0x");
    let nullifier = u128::from_str_radix(&without_prefix[0..32], 16).unwrap();
    let index = u8::from_str_radix(&without_prefix[32..34], 16).unwrap();
    let secret = u128::from_str_radix(&without_prefix[34..66], 16).unwrap();

    let root = tree.root();
    let proof = tree.generate_proof(index as usize).unwrap();

    let leaf = <TwoToOneHash as TwoToOneCRH>::evaluate(
        &two_to_one_crh_params.clone(),
        &nullifier.to_le_bytes(),
        &secret.to_le_bytes(),
    )
    .unwrap();

    let commitment = Commitment { nullifier, secret };
    let hashed_nullifier =
        <LeafHash as CRH>::evaluate(&leaf_crh_params, &commitment.nullifier.to_le_bytes()).unwrap();

    let circuit = MerkleTreeVerification {
        leaf_crh_params,
        two_to_one_crh_params,
        root,
        hashed_nullifier,
        leaf,
        commitment,
        path: Some(proof),
    };

    let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();

    let a_x_str = proof.a.x.0.to_string();
    let a_y_str = proof.a.y.0.to_string();
    let a_infi_str = (proof.a.infinity as u8).to_string();
    let mut a_point = String::new();
    a_point.push_str(&a_x_str);
    a_point.push_str(&a_y_str);
    a_point.push('0');
    a_point.push_str(&a_infi_str);

    // Point b
    let b_x_c0_str = proof.b.x.c0.0.to_string();
    let b_x_c1_str = proof.b.x.c1.0.to_string();
    let b_y_c0_str = proof.b.y.c0.0.to_string();
    let b_y_c1_str = proof.b.y.c1.0.to_string();
    let b_infi_str = (proof.b.infinity as u8).to_string();
    let mut b_point = String::new();
    b_point.push_str(&b_x_c0_str);
    b_point.push_str(&b_x_c1_str);
    b_point.push_str(&b_y_c0_str);
    b_point.push_str(&b_y_c1_str);
    b_point.push('0');
    b_point.push_str(&b_infi_str);

    // Point c
    let c_x_str = proof.c.x.0.to_string();
    let c_y_str = proof.c.y.0.to_string();
    let c_infi_str = (proof.c.infinity as u8).to_string();
    let mut c_point = String::new();
    c_point.push_str(&c_x_str);
    c_point.push_str(&c_y_str);
    c_point.push('0');
    c_point.push_str(&c_infi_str);

    // Proof
    let mut proof_str = String::new();
    proof_str.push_str("0x");
    proof_str.push_str(&a_point);
    proof_str.push_str(&b_point);
    proof_str.push_str(&c_point);

    let mut hashed_nullifier_str = String::from("0x");
    hashed_nullifier_str.push_str(&hashed_nullifier.0.to_string());
    println!("\n\n** Nullifier **: {:?}", hashed_nullifier_str);
    println!("\n** Proof **: {:?}", proof_str);
    println!("\n\n=======================================================");
}
