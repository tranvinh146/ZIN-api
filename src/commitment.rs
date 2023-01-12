use std::borrow::Borrow;

use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode},
    uint128::UInt128,
    uint8::UInt8,
    ToBytesGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::common::ConstraintF;

#[derive(Hash, Eq, PartialEq, Clone, Default)]
pub struct Commitment {
    pub nullifier: u128,
    pub secret: u128,
}

impl Commitment {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        ark_ff::to_bytes![self.nullifier, self.secret].unwrap()
    }
}

#[derive(Hash, Eq, PartialEq, Copy, Clone, PartialOrd, Ord, Debug)]
pub struct Nullifier(pub u128);

impl Nullifier {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct NullifierVar(pub UInt128<ConstraintF>);

impl NullifierVar {
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn to_bytes_le(&self) -> Vec<UInt8<ConstraintF>> {
        self.0.to_bytes().unwrap()
    }
}

impl AllocVar<Nullifier, ConstraintF> for NullifierVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<Nullifier>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        UInt128::new_variable(cs.into(), || f().map(|u| u.borrow().0), mode).map(Self)
    }
}
