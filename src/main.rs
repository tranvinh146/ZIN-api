use std::sync::Mutex;

use actix_web::{post, web, App, HttpServer, Responder, Result};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::crh::pedersen::Parameters;
use ark_crypto_primitives::{crh::TwoToOneCRH, CRH, SNARK};
use ark_ec::twisted_edwards_extended::GroupProjective;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_381::EdwardsParameters;
use ark_ff::Fp256;
use ark_groth16::{Groth16, ProvingKey};
use commitment::Commitment;
use constraints::MerkleTreeVerification;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub mod commitment;
pub mod common;
pub mod constraints;
use common::*;
// mod __main;

#[derive(Serialize)]
struct CommitmentInfo {
    secret: String,
    commitment: String,
}

#[derive(Serialize)]
struct ProofInfo {
    nullifier: String,
    proof: String,
}

#[derive(Deserialize)]
struct Secret {
    secret: String,
}

struct MerkleTreeState<C: ProjectiveCurve> {
    tree: Mutex<ZinMerkleTree>,
    leaf_crh_params: Parameters<C>,
    two_to_one_crh_params: Parameters<C>,
    pk: ProvingKey<Bls12_381>,
    index: Mutex<u32>,
}

#[post("/commitment")]
async fn generate_commitment(
    data: web::Data<MerkleTreeState<GroupProjective<EdwardsParameters>>>,
) -> Result<impl Responder> {
    let mut tree = data.tree.lock().unwrap();
    let mut index = data.index.lock().unwrap();
    let two_to_one_crh_params = data.two_to_one_crh_params.clone();

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
    let index_hex: String = format!("{:02x}", *index).to_string();

    let mut raw_commitment_hex = String::from("0x");
    raw_commitment_hex.push_str(&nullifier_hex);
    raw_commitment_hex.push_str(&index_hex);
    raw_commitment_hex.push_str(&secret_hex);

    let nullifier = u128::from_str_radix(&nullifier_hex, 16).unwrap();
    let secret = u128::from_str_radix(&secret_hex, 16).unwrap();

    let commitment = <TwoToOneHash as TwoToOneCRH>::evaluate(
        &two_to_one_crh_params,
        &nullifier.to_le_bytes(),
        &secret.to_le_bytes(),
    )
    .unwrap();

    tree.update(*index as usize, &commitment).unwrap();
    *index += 1;

    let mut commitment_str = String::from("0x");
    commitment_str.push_str(&commitment.0.to_string());

    let res = CommitmentInfo {
        secret: raw_commitment_hex,
        commitment: commitment_str,
    };
    Ok(web::Json(res))
}

#[post("/proof")]
async fn generate_proof(
    data: web::Data<MerkleTreeState<GroupProjective<EdwardsParameters>>>,
    body: web::Json<Secret>,
) -> Result<impl Responder> {
    let mut rng = ark_std::test_rng();

    let tree = data.tree.lock().unwrap();
    let leaf_crh_params = data.leaf_crh_params.clone();
    let two_to_one_crh_params = data.two_to_one_crh_params.clone();
    let pk = &data.pk;

    let raw_commitment = body.secret.clone();

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

    let res = ProofInfo {
        nullifier: hashed_nullifier_str,
        proof: proof_str,
    };
    Ok(web::Json(res))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut rng = ark_std::test_rng();
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();
    let tree = ZinMerkleTree::blank(&leaf_crh_params, &two_to_one_crh_params, 4).unwrap();
    let init_proof = tree.generate_proof(0).unwrap();

    let cs = MerkleTreeVerification {
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_crh_params: two_to_one_crh_params.clone(),
        root: tree.root(),
        leaf: Fp256::default(),
        hashed_nullifier: Fp256::default(),
        commitment: Commitment::default(),
        path: Some(init_proof),
    };
    let (pk, _vk) = Groth16::<Bls12_381>::circuit_specific_setup(cs, &mut rng).unwrap();

    let merkle_tree_state = web::Data::new(MerkleTreeState {
        tree: Mutex::new(tree),
        leaf_crh_params,
        two_to_one_crh_params,
        index: Mutex::new(0),
        pk,
    });

    HttpServer::new(move || {
        let merkle_tree_state = merkle_tree_state.clone();

        App::new()
            .app_data(merkle_tree_state)
            .service(generate_commitment)
            .service(generate_proof)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
