use crate::{
    commitment::Commitment, common::*, HashedCommitment, HashedNullifier, Root, SimplePath,
};

use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
    CRHGadget, PathVar, CRH,
};
use ark_r1cs_std::{prelude::*, uint128::UInt128};
use ark_relations::{ns, r1cs::ConstraintSynthesizer};

pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;
pub type HashedCommitmentVar = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::OutputVar;
pub type HashedNullifierVar = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::OutputVar;

pub type SimplePathVar =
    PathVar<crate::MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>;

//////////////////////////////////////////////////////////
#[derive(Clone)]
pub struct MerkleTreeVerification {
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    pub root: Root,
    pub commitment: Commitment,
    pub leaf: HashedCommitment,
    pub hashed_nullifier: HashedNullifier,
    pub path: Option<SimplePath>,
}

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeVerification {
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<ConstraintF>,
    ) -> ark_relations::r1cs::Result<()> {
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;

        let root = RootVar::new_input(ns!(cs, "root_var"), || Ok(&self.root))?;

        let hashed_nullifier =
            HashedNullifierVar::new_input(ns!(cs, "nullifier_var"), || Ok(self.hashed_nullifier))?;

        let nullifier =
            UInt128::new_witness(ns!(cs, "nullifier_var"), || Ok(self.commitment.nullifier))?;
        let secret = UInt128::new_witness(ns!(cs, "secret_var"), || Ok(self.commitment.secret))?;

        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        let path =
            SimplePathVar::new_witness(ns!(cs, "path_var"), || Ok(self.path.as_ref().unwrap()))?;

        let leaf =
            HashedCommitmentVar::new_witness(ns!(cs, "hashed_commitment_var"), || Ok(self.leaf))?;

        let nullifier_hashed = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::evaluate(
            &leaf_crh_params,
            &nullifier.to_bytes().unwrap(),
        )?;

        hashed_nullifier.enforce_equal(&nullifier_hashed)?;

        let hashed_commitment =
            <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::evaluate(
                &two_to_one_crh_params,
                &nullifier.to_bytes()?,
                &secret.to_bytes()?,
            )
            .unwrap();

        leaf.enforce_equal(&hashed_commitment)?;

        let is_member = path.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf.to_bytes().unwrap().as_slice(),
        )?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::FqParameters;
    use ark_ff::{BigInteger256, BigInteger384, Fp256, Fp384};
    use ark_groth16::Proof;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;

    #[test]
    fn merkle_tree_constraints_correctness() {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        let commitment_one = Commitment {
            nullifier: 12,
            secret: 44,
        };

        // Next, let's construct our tree.
        let mut tree =
            crate::ZinMerkleTree::blank(&leaf_crh_params, &two_to_one_crh_params, 4).unwrap();

        let leaf = <TwoToOneHash as TwoToOneCRH>::evaluate(
            &two_to_one_crh_params,
            &commitment_one.nullifier.to_le_bytes(),
            &commitment_one.secret.to_le_bytes(),
        )
        .unwrap();
        // println!("Leaf String {:?}", leaf.0.to_string());
        // println!("Bytes String {:?}", leaf.0 .0);
        // let vec: [u8; 32] = [
        //     68, 83, 11, 19, 152, 27, 5, 103, 110, 215, 168, 185, 255, 122, 189, 5, 225, 146, 48,
        //     35, 251, 165, 55, 80, 151, 41, 8, 196, 98, 61, 62, 10,
        // ];
        // let x = u64::from_be_bytes([68, 83, 11, 19, 152, 27, 5, 103]);
        // let x = u8::from_be_bytes([true as u8]);
        // println!("{:?}", x);
        // let vect = vec.to_vec();
        // let vec_ref: &[u8] = vect.as_ref();
        // let byte: [u8; 32] = vec_ref.try_into().unwrap();
        // println!("{:?}", byte);
        // let part_one = &vec[0..8];

        // part_one.align_to()

        // let hex_bytes: [u8; 8] = [7, 183, 184, 191, 22, 112, 147, 39];
        // let number: u64 = 10892246813327048202;

        // hex_bytes;
        // number

        // let x = leaf.0.to_string();
        // println!("{:?}", u64::from_str_radix(&x[0..16], 16));
        // // let x = leaf.0.to_string().
        // println!("Leaf BigInt {:?}", leaf.0 .0);
        // let k = leaf.0 .0[0].to_le_bytes();
        // println!("Element BigInt {:?}", k);

        tree.update(0, &leaf).unwrap();
        // println!("Leaf {:?}", leaf.0.as_ref());
        // let t = leaf.0;
        // let k: Fp256<FrParameters> = Fp256::new(BigInteger256::new([
        //     8484409096744848449,
        //     17055854317687598833,
        //     4240331956081551118,
        //     3983855268493553701,
        // ]));
        // let x = leaf.eq(&k);
        // println!("{:?}", x);
        // Now, let's try to generate a membership proof for the 1st item.
        let proof = tree.generate_proof(0).unwrap();

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let x = root.0.as_ref();
        let y: Fp256<BigInteger256> = Fp256::new(BigInteger256::new(x.try_into().unwrap()));
        println!("{:?}", root.0.to_string());
        println!("{:?}", y.0.to_string());
        let hashed_nullifier =
            <LeafHash as CRH>::evaluate(&leaf_crh_params, &commitment_one.nullifier.to_le_bytes())
                .unwrap();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            leaf,
            hashed_nullifier,

            // witness
            commitment: commitment_one,
            path: Some(proof),
        };
        // First, some boilerplat that helps with debugging
        let mut layer = ConstraintLayer::default();
        layer.mode = TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Next, let's make the circuit!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            // If it isn't, find out the offending constraint.
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(is_satisfied);
    }

    fn build_two_commitment_circuit() -> MerkleTreeVerification {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        let commitment_one = Commitment {
            nullifier: 12,
            secret: 44,
        };

        // let commitment_two = Commitment {
        //     nullifier: 12,
        //     secret: 24,
        // };

        // Next, let's construct our tree.
        let mut tree =
            crate::ZinMerkleTree::blank(&leaf_crh_params, &two_to_one_crh_params, 4).unwrap();

        let leaf_one = <TwoToOneHash as TwoToOneCRH>::evaluate(
            &two_to_one_crh_params,
            &commitment_one.nullifier.to_le_bytes(),
            &commitment_one.secret.to_le_bytes(),
        )
        .unwrap();

        println!("*** Commitment *** {:?}", leaf_one.0.to_string());

        tree.update(0, &leaf_one).unwrap();

        // let leaf_two = <TwoToOneHash as TwoToOneCRH>::evaluate(
        //     &two_to_one_crh_params,
        //     &commitment_two.nullifier.to_le_bytes(),
        //     &commitment_two.secret.to_le_bytes(),
        // )
        // .unwrap();
        // tree.update(1, &leaf_two).unwrap();

        // Now, let's try to generate a membership proof for the 1st item.
        let proof = tree.generate_proof(0).unwrap();

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let hashed_nullifier =
            <LeafHash as CRH>::evaluate(&leaf_crh_params, &commitment_one.nullifier.to_le_bytes())
                .unwrap();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            leaf: leaf_one,
            hashed_nullifier,

            // witness
            commitment: commitment_one,
            path: Some(proof),
        };
        circuit
    }

    #[test]
    fn proof() {
        use ark_bls12_381::Bls12_381;
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        let mut rng = ark_std::test_rng();
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();
        let tree =
            crate::ZinMerkleTree::blank(&leaf_crh_params, &two_to_one_crh_params, 4).unwrap();
        let proof = tree.generate_proof(0).unwrap();
        let cs = MerkleTreeVerification {
            leaf_crh_params,
            two_to_one_crh_params,
            root: tree.root(),
            leaf: Fp256::default(),
            hashed_nullifier: Fp256::default(),
            commitment: Commitment {
                nullifier: 0,
                secret: 0,
            },
            path: Some(proof),
        };
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(cs, &mut rng).unwrap();

        let circuit_to_verify_against = build_two_commitment_circuit();
        let public_input = [
            circuit_to_verify_against.root,
            circuit_to_verify_against.hashed_nullifier,
        ];

        let proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng).unwrap();

        // Point a
        let a_x_proof = proof.a.x.0 .0;
        let a_y_proof = proof.a.y.0 .0;
        let a_infi_proof = proof.a.infinity;

        // Point b
        let b_x_c0_proof = proof.b.x.c0.0 .0;
        let b_x_c1_proof = proof.b.x.c1.0 .0;
        let b_y_c0_proof = proof.b.y.c0.0 .0;
        let b_y_c1_proof = proof.b.y.c1.0 .0;
        let b_infi_proof = proof.b.infinity;

        // Point c
        let c_x_proof = proof.c.x.0 .0;
        let c_y_proof = proof.c.y.0 .0;
        let c_infi_proof = proof.c.infinity;

        let mut new_proof: Proof<Bls12_381> = Proof::default();

        // Point a of new proof
        new_proof.a.x.clone_from(
            &(Fp384::new(BigInteger384::new(a_x_proof.try_into().unwrap())) as Fp384<FqParameters>),
        );
        new_proof.a.y.clone_from(
            &(Fp384::new(BigInteger384::new(a_y_proof.try_into().unwrap())) as Fp384<FqParameters>),
        );
        new_proof.a.infinity.clone_from(&a_infi_proof);

        // Point b of new proof
        new_proof.b.x.c0.clone_from(
            &(Fp384::new(BigInteger384::new(b_x_c0_proof.try_into().unwrap()))
                as Fp384<FqParameters>),
        );
        new_proof.b.x.c1.clone_from(
            &(Fp384::new(BigInteger384::new(b_x_c1_proof.try_into().unwrap()))
                as Fp384<FqParameters>),
        );
        new_proof.b.y.c0.clone_from(
            &(Fp384::new(BigInteger384::new(b_y_c0_proof.try_into().unwrap()))
                as Fp384<FqParameters>),
        );
        new_proof.b.y.c1.clone_from(
            &(Fp384::new(BigInteger384::new(b_y_c1_proof.try_into().unwrap()))
                as Fp384<FqParameters>),
        );
        new_proof.b.infinity.clone_from(&b_infi_proof);

        // Point c of new proof
        new_proof.c.x.clone_from(
            &(Fp384::new(BigInteger384::new(c_x_proof.try_into().unwrap())) as Fp384<FqParameters>),
        );
        new_proof.c.y.clone_from(
            &(Fp384::new(BigInteger384::new(c_y_proof.try_into().unwrap())) as Fp384<FqParameters>),
        );
        new_proof.c.infinity.clone_from(&c_infi_proof);

        // String proof
        // Point a
        let a_x_str = new_proof.a.x.0.to_string();
        let a_y_str = new_proof.a.y.0.to_string();
        let a_infi_str = (new_proof.a.infinity as u8).to_string();
        let mut a_point = String::new();
        a_point.push_str(&a_x_str);
        a_point.push_str(&a_y_str);
        a_point.push('0');
        a_point.push_str(&a_infi_str);

        // Point b
        let b_x_c0_str = new_proof.b.x.c0.0.to_string();
        let b_x_c1_str = new_proof.b.x.c1.0.to_string();
        let b_y_c0_str = new_proof.b.y.c0.0.to_string();
        let b_y_c1_str = new_proof.b.y.c1.0.to_string();
        let b_infi_str = (new_proof.b.infinity as u8).to_string();
        let mut b_point = String::new();
        b_point.push_str(&b_x_c0_str);
        b_point.push_str(&b_x_c1_str);
        b_point.push_str(&b_y_c0_str);
        b_point.push_str(&b_y_c1_str);
        b_point.push('0');
        b_point.push_str(&b_infi_str);

        // Point c
        let c_x_str = new_proof.c.x.0.to_string();
        let c_y_str = new_proof.c.y.0.to_string();
        let c_infi_str = (new_proof.c.infinity as u8).to_string();
        let mut c_point = String::new();
        c_point.push_str(&c_x_str);
        c_point.push_str(&c_y_str);
        c_point.push('0');
        c_point.push_str(&c_infi_str);

        // Proof
        let mut proof_str = String::new();
        proof_str.push_str(&a_point);
        proof_str.push_str(&b_point);
        proof_str.push_str(&c_point);

        println!("*** Proof *** {:?}", proof_str);

        let valid_proof = Groth16::verify(&vk, &public_input, &new_proof).unwrap();
        assert!(valid_proof);
    }

    #[test]
    fn snark_verification() {
        use ark_bls12_381::Bls12_381;
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();
        // Use a circuit just to generate the circuit

        let tree =
            crate::ZinMerkleTree::blank(&leaf_crh_params, &two_to_one_crh_params, 4).unwrap();
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
        // let cs = build_two_commitment_circuit();
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(cs, &mut rng).unwrap();
        let mut rng = ark_std::test_rng();

        let circuit_to_verify_against = build_two_commitment_circuit();

        let public_input = [
            circuit_to_verify_against.root,
            circuit_to_verify_against.hashed_nullifier,
        ];

        println!(
            "*** Nullifier *** {:?}",
            circuit_to_verify_against.hashed_nullifier.0.to_string()
        );

        let proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng).unwrap();

        // // let circuit_defining_cs = build_two_commitment_circuit();
        // let mut new_vk: VerifyingKey<Bls12_381> = VerifyingKey::default();

        // // Alpha
        // let alpha_g1_x = vk.alpha_g1.x;
        // new_vk.alpha_g1.x.clone_from(&alpha_g1_x);
        // let alpha_g1_y = vk.alpha_g1.y;
        // new_vk.alpha_g1.y.clone_from(&alpha_g1_y);
        // let alpha_g1_infi = vk.alpha_g1.infinity;
        // new_vk.alpha_g1.infinity.clone_from(&alpha_g1_infi);
        // println!("{:?}", alpha_g1_x.0 .0);
        // println!("{:?}", alpha_g1_y.0 .0);
        // println!("{:?}", alpha_g1_infi);

        // // Beta
        // let beta_g2_x_c0 = vk.beta_g2.x.c0;
        // let beta_g2_x_c1 = vk.beta_g2.x.c1;
        // let beta_g2_y_c0 = vk.beta_g2.y.c0;
        // let beta_g2_y_c1 = vk.beta_g2.y.c1;
        // let beta_g2_infi = vk.beta_g2.infinity;

        // new_vk.beta_g2.x.c0.clone_from(&beta_g2_x_c0);
        // new_vk.beta_g2.x.c1.clone_from(&beta_g2_x_c1);
        // new_vk.beta_g2.y.c0.clone_from(&beta_g2_y_c0);
        // new_vk.beta_g2.y.c1.clone_from(&beta_g2_y_c1);
        // new_vk.beta_g2.infinity.clone_from(&beta_g2_infi);

        // println!("{:?}", beta_g2_x_c0);
        // println!("{:?}", beta_g2_x_c1);
        // println!("{:?}", beta_g2_y_c0);
        // println!("{:?}", beta_g2_y_c1);
        // println!("{:?}", beta_g2_infi);

        // // Delta
        // let delta_g2_x_c0 = vk.delta_g2.x.c0;
        // let delta_g2_x_c1 = vk.delta_g2.x.c1;
        // let delta_g2_y_c0 = vk.delta_g2.y.c0;
        // let delta_g2_y_c1 = vk.delta_g2.y.c1;
        // let delta_g2_infi = vk.delta_g2.infinity;
        // new_vk.delta_g2.x.c0.clone_from(&delta_g2_x_c0);
        // new_vk.delta_g2.x.c1.clone_from(&delta_g2_x_c1);
        // new_vk.delta_g2.y.c0.clone_from(&delta_g2_y_c0);
        // new_vk.delta_g2.y.c1.clone_from(&delta_g2_y_c1);
        // new_vk.delta_g2.infinity.clone_from(&delta_g2_infi);
        // println!("{:?}", delta_g2_x_c0);
        // println!("{:?}", delta_g2_x_c1);
        // println!("{:?}", delta_g2_y_c0);
        // println!("{:?}", delta_g2_y_c1);
        // println!("{:?}", delta_g2_infi);

        // // Gamma
        // let gamma_g2_x_c0 = vk.gamma_g2.x.c0;
        // let gamma_g2_x_c1 = vk.gamma_g2.x.c1;
        // let gamma_g2_y_c0 = vk.gamma_g2.y.c0;
        // let gamma_g2_y_c1 = vk.gamma_g2.y.c1;
        // let gamma_g2_infi = vk.gamma_g2.infinity;
        // new_vk.gamma_g2.x.c0.clone_from(&gamma_g2_x_c0);
        // new_vk.gamma_g2.x.c1.clone_from(&gamma_g2_x_c1);
        // new_vk.gamma_g2.y.c0.clone_from(&gamma_g2_y_c0);
        // new_vk.gamma_g2.y.c1.clone_from(&gamma_g2_y_c1);
        // new_vk.gamma_g2.infinity.clone_from(&gamma_g2_infi);
        // println!("{:?}", gamma_g2_x_c0);
        // println!("{:?}", gamma_g2_x_c1);
        // println!("{:?}", gamma_g2_y_c0);
        // println!("{:?}", gamma_g2_y_c1);
        // println!("{:?}", gamma_g2_infi);

        // let gamma_abc_g1_len = vk.gamma_abc_g1.clone().len();
        // for i in 0..gamma_abc_g1_len {
        //     let mut gamma_abc_ith = *vk.gamma_abc_g1.get(i).unwrap();
        //     let x = gamma_abc_ith.x;
        //     let y = gamma_abc_ith.y;
        //     let infi = gamma_abc_ith.infinity;

        //     gamma_abc_ith.x.clone_from(&x);
        //     gamma_abc_ith.y.clone_from(&y);
        //     gamma_abc_ith.infinity.clone_from(&infi);

        //     println!("{:?}", x.0);
        //     println!("{:?}", y.0);
        //     println!("{:?}", infi);

        //     new_vk.gamma_abc_g1.push(gamma_abc_ith)
        // }

        // println!("VK: {:?}", vk);
        // println!("NEW VK: {:?}", new_vk);

        let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();
        // String proof
        let new_proof = proof;
        // Point a
        let a_x_str = new_proof.a.x.0.to_string();
        let a_y_str = new_proof.a.y.0.to_string();
        let a_infi_str = (new_proof.a.infinity as u8).to_string();
        let mut a_point = String::new();
        a_point.push_str(&a_x_str);
        a_point.push_str(&a_y_str);
        a_point.push('0');
        a_point.push_str(&a_infi_str);

        // Point b
        let b_x_c0_str = new_proof.b.x.c0.0.to_string();
        let b_x_c1_str = new_proof.b.x.c1.0.to_string();
        let b_y_c0_str = new_proof.b.y.c0.0.to_string();
        let b_y_c1_str = new_proof.b.y.c1.0.to_string();
        let b_infi_str = (new_proof.b.infinity as u8).to_string();
        let mut b_point = String::new();
        b_point.push_str(&b_x_c0_str);
        b_point.push_str(&b_x_c1_str);
        b_point.push_str(&b_y_c0_str);
        b_point.push_str(&b_y_c1_str);
        b_point.push('0');
        b_point.push_str(&b_infi_str);

        // Point c
        let c_x_str = new_proof.c.x.0.to_string();
        let c_y_str = new_proof.c.y.0.to_string();
        let c_infi_str = (new_proof.c.infinity as u8).to_string();
        let mut c_point = String::new();
        c_point.push_str(&c_x_str);
        c_point.push_str(&c_y_str);
        c_point.push('0');
        c_point.push_str(&c_infi_str);

        // Proof
        let mut proof_str = String::new();
        proof_str.push_str(&a_point);
        proof_str.push_str(&b_point);
        proof_str.push_str(&c_point);

        println!("*** Proof *** {:?}", proof_str);

        assert!(valid_proof);
    }

    #[test]
    fn reuse_snark() {
        // use ark_bls12_381::Bls12_381;
        // use ark_groth16::Groth16;
        // use ark_snark::SNARK;

        // let mut rng = ark_std::test_rng();

        // let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        // let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // let commitment_one = Commitment {
        //     nullifier: 10,
        //     secret: 5,
        // };

        // let commitment_two = Commitment {
        //     nullifier: 15,
        //     secret: 24,
        // };

        // let commitment_three = Commitment {
        //     nullifier: 432,
        //     secret: 128,
        // };

        // let mut tree =
        //     crate::ZinMerkleTree::blank(&leaf_crh_params, &two_to_one_crh_params, 3).unwrap();

        // let leaf_one = <TwoToOneHash as TwoToOneCRH>::evaluate(
        //     &two_to_one_crh_params,
        //     &commitment_one.nullifier.to_le_bytes(),
        //     &commitment_one.secret.to_le_bytes(),
        // )
        // .unwrap();
        // tree.update(0, &leaf_one).unwrap();

        // let leaf_two = <TwoToOneHash as TwoToOneCRH>::evaluate(
        //     &two_to_one_crh_params,
        //     &commitment_two.nullifier.to_le_bytes(),
        //     &commitment_two.secret.to_le_bytes(),
        // )
        // .unwrap();
        // tree.update(1, &leaf_two).unwrap();

        // // let leaf_three = <TwoToOneHash as TwoToOneCRH>::evaluate(
        // //     &two_to_one_crh_params,
        // //     &commitment_three.nullifier.to_le_bytes(),
        // //     &commitment_three.secret.to_le_bytes(),
        // // )
        // // .unwrap();
        // // tree.update(2, &leaf_three).unwrap();

        // let proof = tree.generate_proof(0).unwrap();
        // let root = tree.root();
        // let circuit_one = MerkleTreeVerification {
        //     leaf_crh_params: leaf_crh_params.clone(),
        //     two_to_one_crh_params: two_to_one_crh_params.clone(),
        //     root,
        //     leaf: leaf_one,
        //     commitment: commitment_one.clone(),
        //     path: Some(proof),
        // };

        // let (pk, vk) =
        //     Groth16::<Bls12_381>::circuit_specific_setup(circuit_one.clone(), &mut rng).unwrap();

        // let public_input = [circuit_one.root];

        // let proof = Groth16::prove(&pk, circuit_one, &mut rng).unwrap();
        // let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();

        // assert!(valid_proof);

        // // =======================================================
        // let proof_two = tree.generate_proof(1).unwrap();
        // let circuit_two = MerkleTreeVerification {
        //     leaf_crh_params: leaf_crh_params.clone(),
        //     two_to_one_crh_params: two_to_one_crh_params.clone(),
        //     root,
        //     leaf: leaf_two,
        //     commitment: commitment_two,
        //     path: Some(proof_two),
        // };
        // let public_input = [circuit_two.root];

        // let proof = Groth16::prove(&pk, circuit_two, &mut rng).unwrap();
        // let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();
        // assert!(valid_proof);

        // // ======================================================
        // let leaf_three = <TwoToOneHash as TwoToOneCRH>::evaluate(
        //     &two_to_one_crh_params,
        //     &commitment_three.nullifier.to_le_bytes(),
        //     &commitment_three.secret.to_le_bytes(),
        // )
        // .unwrap();
        // tree.update(2, &leaf_three).unwrap();

        // let proof_three = tree.generate_proof(2).unwrap();
        // let circuit_three = MerkleTreeVerification {
        //     leaf_crh_params: leaf_crh_params.clone(),
        //     two_to_one_crh_params: two_to_one_crh_params.clone(),
        //     root: tree.root(),
        //     leaf: leaf_three,
        //     commitment: commitment_three,
        //     path: Some(proof_three),
        // };
        // let public_input = [circuit_three.root];

        // let proof = Groth16::prove(&pk, circuit_three, &mut rng).unwrap();
        // let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();
        // println!("{:?}", valid_proof);
        // assert!(valid_proof);
    }
}
