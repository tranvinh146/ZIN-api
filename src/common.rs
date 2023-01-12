use ark_crypto_primitives::{
    crh::{
        injective_map::{
            constraints::{PedersenCRHCompressorGadget, TECompressorGadget},
            PedersenCRHCompressor, TECompressor,
        },
        pedersen, TwoToOneCRH, TwoToOneCRHGadget,
    },
    merkle_tree::Config,
    CRHGadget, MerkleTree, Path, CRH,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};

#[derive(Clone)]
pub struct MerkleConfig;

impl Config for MerkleConfig {
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 128;
}

pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;
pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;

impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 144;
}

pub type ZinMerkleTree = MerkleTree<MerkleConfig>;
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
pub type HashedCommitment = <TwoToOneHash as TwoToOneCRH>::Output;
pub type SimplePath = Path<MerkleConfig>;
pub type HashedNullifier = <LeafHash as CRH>::Output;

pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    TwoToOneWindow,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    LeafWindow,
    EdwardsVar,
    TECompressorGadget,
>;

pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::ParametersVar;

pub type LeafHashParamsVar = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::ParametersVar;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;
