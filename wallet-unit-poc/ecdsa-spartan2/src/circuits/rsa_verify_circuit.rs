use crate::{
    paths::PathConfig,
    utils::{hashmap_to_json_string, parse_inputs, parse_witness, FieldParser},
    Scalar, E,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use tracing::info;

witnesscalc_adapter::witness!(rsa_verify_2048);
witnesscalc_adapter::witness!(rsa_verify_4096);

/// RsaVerifyCircuit wraps the RSA signature verification circuit.
/// Supports both RSA-2048 (k=17) and RSA-4096 (k=34) variants.
#[derive(Debug, Clone)]
pub struct RsaVerifyCircuit {
    /// Circuit name used for path resolution ("rsa_verify_2048" or "rsa_verify_4096")
    circuit_name: &'static str,
    /// Number of RSA limbs (17 for 2048-bit, 34 for 4096-bit)
    k: usize,
    /// Path configuration for resolving file paths
    path_config: PathConfig,
    /// Optional override for input JSON path
    input_path: Option<PathBuf>,
    /// Cached witness for reuse across synthesize and public_values calls
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl RsaVerifyCircuit {
    /// Create a new RSA-2048 verify circuit.
    pub fn new_2048(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            circuit_name: "rsa_verify_2048",
            k: 17,
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new RSA-4096 verify circuit.
    pub fn new_4096(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            circuit_name: "rsa_verify_4096",
            k: 34,
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    /// Resolve the input JSON path using PathConfig.
    fn resolve_input_json(&self) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| self.path_config.resolve(p))
            .unwrap_or_else(|| self.path_config.input_json(self.circuit_name))
    }

    /// Get the R1CS file path.
    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path(self.circuit_name)
    }

    /// Get cached witness or generate and cache it.
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();

        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let path = self.resolve_input_json();
        info!("Loading RSA verify inputs from {}", path.display());

        let file = File::open(&path).map_err(|_| SynthesisError::AssignmentMissing)?;
        let json_value: serde_json::Value =
            serde_json::from_reader(file).map_err(|_| SynthesisError::AssignmentMissing)?;

        let field_defs: &[(&str, FieldParser)] = &[
            ("message", FieldParser::BigIntArray),
            ("messageLength", FieldParser::U64Scalar),
            ("signature", FieldParser::BigIntArray),
            ("modulus", FieldParser::BigIntArray),
        ];

        let inputs = parse_inputs(&json_value, field_defs)?;

        info!("Generating witness using witnesscalc...");
        let t0 = Instant::now();

        let inputs_json = hashmap_to_json_string(&inputs)?;

        let witness_bytes = match self.circuit_name {
            "rsa_verify_2048" => rsa_verify_2048_witness(&inputs_json),
            "rsa_verify_4096" => rsa_verify_4096_witness(&inputs_json),
            _ => unreachable!(),
        }
        .map_err(|_| SynthesisError::Unsatisfiable)?;

        info!("witnesscalc time: {} ms", t0.elapsed().as_millis());

        let witness = parse_witness(&witness_bytes)?;

        *cache = Some(witness.clone());

        Ok(witness)
    }
}

impl SpartanCircuit<E> for RsaVerifyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let r1cs_path = self.r1cs_path();

        // Detect if we're in setup phase (ShapeCS) or prove phase (SatisfyingAssignment)
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs = load_r1cs(&r1cs_path).map_err(|_| SynthesisError::AssignmentMissing)?;
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        let witness = self.get_or_generate_witness()?;

        let r1cs = load_r1cs(&r1cs_path).map_err(|_| SynthesisError::AssignmentMissing)?;
        synthesize(cs, r1cs, Some(witness))?;
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        // Public values: modulus[0..k-1] at witness indices 1..=k
        // (no outputs in this circuit, so public inputs start at index 1)
        let witness = self.get_or_generate_witness().ok();

        let mut values = Vec::with_capacity(self.k);
        for idx in 1..=self.k {
            values.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(values)
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Standalone circuit — no shared witness commitments
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}
