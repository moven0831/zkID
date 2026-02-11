//! CLI for running the Spartan-2 Prepare and Show circuits.
//!
//! Usage examples:
//!   cargo run --release -- prepare run --input ../circom/inputs/jwt/generated.json
//!   cargo run --release -- show prove --input ../circom/inputs/show/custom.json
//!   cargo run --release -- prepare setup
//!   cargo run --release -- show verify
//!
//! Legacy aliases such as `prepare`, `show`, `prove_prepare`, `setup_show`, etc. remain available.
//!
//! Typical post-keygen flow:
//! 0. `prepare setup` and `show setup` — load proving/verification keys and witnesses for each circuit.
//! 1. `generate_shared_blinds` — derive shared blinding factors used by both circuits.
//! 2. `prove_prepare` — produce the initial Prepare proof.
//! 3. `reblind_prepare` — reblind the Prepare proof without changing its `comm_W_shared`.
//! 4. `prove_show` — produce the Show proof using the shared witness commitment.
//! 5. `reblind_show` — reblind the Show proof; the reblinded proof maintains the same `comm_W_shared` as step 3.
//!
//! Every proof emitted in this sequence (including the reblinded variants) should verify successfully.

use ecdsa_spartan2::{
    load_proof, prove_circuit, prove_circuit_with_pk, run_circuit, save_keys, setup_circuit_keys,
    setup_circuit_keys_no_save, verify_circuit, verify_circuit_with_loaded_data, PathConfig,
};

#[cfg(any(feature = "jwt-circuit", feature = "show-circuit"))]
use ecdsa_spartan2::{
    generate_shared_blinds, load_instance, load_shared_blinds, load_witness, reblind,
    reblind_with_loaded_data, E,
};

#[cfg(feature = "jwt-circuit")]
use ecdsa_spartan2::{
    paths::keys::{
        PREPARE_INSTANCE, PREPARE_PROOF, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY,
        PREPARE_WITNESS, SHARED_BLINDS,
    },
    PrepareCircuit,
};

#[cfg(feature = "show-circuit")]
use ecdsa_spartan2::{
    paths::keys::{
        SHOW_INSTANCE, SHOW_PROOF, SHOW_PROVING_KEY, SHOW_VERIFYING_KEY, SHOW_WITNESS,
    },
    ShowCircuit,
};

#[cfg(feature = "rsa-circuits")]
use ecdsa_spartan2::{
    paths::keys::{
        RSA2048_INSTANCE, RSA2048_PROOF, RSA2048_PROVING_KEY, RSA2048_VERIFYING_KEY,
        RSA2048_WITNESS, RSA4096_INSTANCE, RSA4096_PROOF, RSA4096_PROVING_KEY,
        RSA4096_VERIFYING_KEY, RSA4096_WITNESS,
    },
    RsaVerifyCircuit,
};

#[cfg(feature = "show-circuit")]
use ff::Field;
use std::{env::args, fs, path::PathBuf, process, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(any(feature = "jwt-circuit", feature = "show-circuit"))]
const NUM_SHARED: usize = 1;

/// Helper function to get file size in bytes
fn get_file_size(path: &str) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(all(feature = "jwt-circuit", feature = "show-circuit"))]
#[derive(Debug)]
struct BenchmarkResults {
    prepare_setup_ms: u128,
    show_setup_ms: u128,
    generate_blinds_ms: u128,
    prove_prepare_ms: u128,
    reblind_prepare_ms: u128,
    prove_show_ms: u128,
    reblind_show_ms: u128,
    verify_prepare_ms: u128,
    verify_show_ms: u128,
    // Size measurements in bytes
    prepare_proving_key_bytes: u64,
    prepare_verifying_key_bytes: u64,
    show_proving_key_bytes: u64,
    show_verifying_key_bytes: u64,
    prepare_proof_bytes: u64,
    show_proof_bytes: u64,
    prepare_witness_bytes: u64,
    show_witness_bytes: u64,
}

#[cfg(all(feature = "jwt-circuit", feature = "show-circuit"))]
impl BenchmarkResults {
    fn print_summary(&self) {
        println!("\n╔════════════════════════════════════════════════╗");
        println!("║        BENCHMARK RESULTS SUMMARY               ║");
        println!("╠════════════════════════════════════════════════╣");
        println!("║ TIMING MEASUREMENTS                            ║");
        println!("╠════════════════════════════════════════════════╣");
        println!(
            "║ Prepare Setup:          {:>10} ms      ║",
            self.prepare_setup_ms
        );
        println!(
            "║ Show Setup:             {:>10} ms      ║",
            self.show_setup_ms
        );
        println!(
            "║ Generate Blinds:        {:>10} ms      ║",
            self.generate_blinds_ms
        );
        println!(
            "║ Prove Prepare:          {:>10} ms      ║",
            self.prove_prepare_ms
        );
        println!(
            "║ Reblind Prepare:        {:>10} ms      ║",
            self.reblind_prepare_ms
        );
        println!(
            "║ Prove Show:             {:>10} ms      ║",
            self.prove_show_ms
        );
        println!(
            "║ Reblind Show:           {:>10} ms      ║",
            self.reblind_show_ms
        );
        println!(
            "║ Verify Prepare:         {:>10} ms      ║",
            self.verify_prepare_ms
        );
        println!(
            "║ Verify Show:            {:>10} ms      ║",
            self.verify_show_ms
        );
        println!("╠════════════════════════════════════════════════╣");
        println!("║ SIZE MEASUREMENTS                              ║");
        println!("╠════════════════════════════════════════════════╣");
        println!(
            "║ Prepare Proving Key:    {:>12}       ║",
            format_size(self.prepare_proving_key_bytes)
        );
        println!(
            "║ Prepare Verifying Key:  {:>12}       ║",
            format_size(self.prepare_verifying_key_bytes)
        );
        println!(
            "║ Show Proving Key:       {:>12}       ║",
            format_size(self.show_proving_key_bytes)
        );
        println!(
            "║ Show Verifying Key:     {:>12}       ║",
            format_size(self.show_verifying_key_bytes)
        );
        println!(
            "║ Prepare Proof:          {:>12}       ║",
            format_size(self.prepare_proof_bytes)
        );
        println!(
            "║ Show Proof:             {:>12}       ║",
            format_size(self.show_proof_bytes)
        );
        println!(
            "║ Prepare Witness:        {:>12}       ║",
            format_size(self.prepare_witness_bytes)
        );
        println!(
            "║ Show Witness:           {:>12}       ║",
            format_size(self.show_witness_bytes)
        );
        println!("╚════════════════════════════════════════════════╝\n");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitKind {
    #[cfg(feature = "jwt-circuit")]
    Prepare,
    #[cfg(feature = "show-circuit")]
    Show,
    #[cfg(feature = "rsa-circuits")]
    Rsa2048,
    #[cfg(feature = "rsa-circuits")]
    Rsa4096,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitAction {
    Run,
    Setup,
    Prove,
    Verify,
    Reblind,
    GenerateSharedBlinds,
    Benchmark,
}

#[derive(Debug, Default, Clone)]
struct CommandOptions {
    input: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct ParsedCommand {
    circuit: CircuitKind,
    action: CircuitAction,
    options: CommandOptions,
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let command_args: &[String] = if args.len() > 1 { &args[1..] } else { &[] };

    let command = match parse_command(command_args) {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("Error: {}", err);
            print_usage();
            process::exit(1);
        }
    };

    match command.circuit {
        #[cfg(feature = "jwt-circuit")]
        CircuitKind::Prepare => execute_prepare(command.action, command.options),
        #[cfg(feature = "show-circuit")]
        CircuitKind::Show => execute_show(command.action, command.options),
        #[cfg(feature = "rsa-circuits")]
        CircuitKind::Rsa2048 => execute_rsa(command.action, command.options, true),
        #[cfg(feature = "rsa-circuits")]
        CircuitKind::Rsa4096 => execute_rsa(command.action, command.options, false),
    }
}

/// Run the complete benchmark pipeline for a given input file
#[cfg(all(feature = "jwt-circuit", feature = "show-circuit"))]
fn run_complete_pipeline(input_path: Option<PathBuf>) -> BenchmarkResults {
    let path_config = PathConfig::development();

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║     STARTING COMPLETE BENCHMARK PIPELINE       ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Step 1: Setup Prepare Circuit
    info!("Step 1/9: Setting up Prepare circuit...");
    let prepare_circuit = PrepareCircuit::new(path_config.clone(), input_path.clone());
    let t0 = Instant::now();
    let (prepare_pk, prepare_vk) = setup_circuit_keys_no_save(prepare_circuit);
    let prepare_setup_ms = t0.elapsed().as_millis();
    println!("✓ Prepare setup completed: {} ms\n", prepare_setup_ms);

    // Save Prepare keys after timing
    if let Err(e) = save_keys(
        path_config.key_path(PREPARE_PROVING_KEY),
        path_config.key_path(PREPARE_VERIFYING_KEY),
        &prepare_pk,
        &prepare_vk,
    ) {
        eprintln!("Failed to save Prepare keys: {}", e);
        std::process::exit(1);
    }

    // Step 2: Setup Show Circuit
    info!("Step 2/9: Setting up Show circuit...");
    let show_circuit = ShowCircuit::new(path_config.clone(), input_path.clone());
    let t0 = Instant::now();
    let (show_pk, show_vk) = setup_circuit_keys_no_save(show_circuit);
    let show_setup_ms = t0.elapsed().as_millis();
    println!("✓ Show setup completed: {} ms\n", show_setup_ms);

    // Save Show keys after timing
    if let Err(e) = save_keys(
        path_config.key_path(SHOW_PROVING_KEY),
        path_config.key_path(SHOW_VERIFYING_KEY),
        &show_pk,
        &show_vk,
    ) {
        eprintln!("Failed to save Show keys: {}", e);
        std::process::exit(1);
    }

    // Step 3: Generate Shared Blinds
    info!("Step 3/9: Generating shared blinds...");
    let t0 = Instant::now();
    generate_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS), NUM_SHARED);
    let generate_blinds_ms = t0.elapsed().as_millis();
    println!("✓ Shared blinds generated: {} ms\n", generate_blinds_ms);

    // Note: We already have prepare_pk and show_pk from setup, no need to reload from files

    // Step 4: Prove Prepare Circuit
    info!("Step 4/9: Proving Prepare circuit...");
    let t0 = Instant::now();
    let prepare_circuit = PrepareCircuit::new(path_config.clone(), input_path.clone());
    prove_circuit_with_pk(
        prepare_circuit,
        &prepare_pk,
        path_config.artifact_path(PREPARE_INSTANCE),
        path_config.artifact_path(PREPARE_WITNESS),
        path_config.artifact_path(PREPARE_PROOF),
    );
    let prove_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof generated: {} ms\n", prove_prepare_ms);

    // Step 5: Reblind Prepare
    info!("Step 5/9: Reblinding Prepare proof...");
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let prepare_instance = load_instance(path_config.artifact_path(PREPARE_INSTANCE))
        .expect("load prepare instance failed");
    let prepare_witness = load_witness(path_config.artifact_path(PREPARE_WITNESS))
        .expect("load prepare witness failed");
    let shared_blinds = load_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS))
        .expect("load shared_blinds failed");

    let t0 = Instant::now();
    reblind_with_loaded_data(
        PrepareCircuit::new(path_config.clone(), input_path.clone()),
        &prepare_pk,
        prepare_instance,
        prepare_witness,
        &shared_blinds,
        path_config.artifact_path(PREPARE_INSTANCE),
        path_config.artifact_path(PREPARE_WITNESS),
        path_config.artifact_path(PREPARE_PROOF),
    );
    let reblind_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof reblinded: {} ms\n", reblind_prepare_ms);

    // Step 6: Prove Show Circuit
    info!("Step 6/9: Proving Show circuit...");
    let t0 = Instant::now();
    let show_circuit = ShowCircuit::new(path_config.clone(), input_path.clone());
    prove_circuit_with_pk(
        show_circuit,
        &show_pk,
        path_config.artifact_path(SHOW_INSTANCE),
        path_config.artifact_path(SHOW_WITNESS),
        path_config.artifact_path(SHOW_PROOF),
    );
    let prove_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof generated: {} ms\n", prove_show_ms);

    // Step 7: Reblind Show
    info!("Step 7/9: Reblinding Show proof...");
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let show_instance =
        load_instance(path_config.artifact_path(SHOW_INSTANCE)).expect("load show instance failed");
    let show_witness =
        load_witness(path_config.artifact_path(SHOW_WITNESS)).expect("load show witness failed");
    // Reuse shared_blinds from Prepare step (already loaded)

    let t0 = Instant::now();
    reblind_with_loaded_data(
        ShowCircuit::new(path_config.clone(), input_path.clone()),
        &show_pk,
        show_instance,
        show_witness,
        &shared_blinds,
        path_config.artifact_path(SHOW_INSTANCE),
        path_config.artifact_path(SHOW_WITNESS),
        path_config.artifact_path(SHOW_PROOF),
    );
    let reblind_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof reblinded: {} ms\n", reblind_show_ms);

    // Step 8: Verify Prepare
    info!("Step 8/9: Verifying Prepare proof...");
    // Load proof and verifying key before timing (file I/O should not be part of verify benchmark)
    let prepare_proof =
        load_proof(path_config.artifact_path(PREPARE_PROOF)).expect("load prepare proof failed");
    // Reuse prepare_vk from setup step (already in memory)

    let t0 = Instant::now();
    let _prepare_public_values = verify_circuit_with_loaded_data(&prepare_proof, &prepare_vk);
    let verify_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof verified: {} ms\n", verify_prepare_ms);

    // Step 9: Verify Show
    info!("Step 9/9: Verifying Show proof...");
    // Load proof and verifying key before timing (file I/O should not be part of verify benchmark)
    let show_proof =
        load_proof(path_config.artifact_path(SHOW_PROOF)).expect("load show proof failed");
    // Reuse show_vk from setup step (already in memory)

    let t0 = Instant::now();
    let show_public_values = verify_circuit_with_loaded_data(&show_proof, &show_vk);
    let verify_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof verified: {} ms", verify_show_ms);
    if !show_public_values.is_empty() {
        // println!("Show public IO: {:?}", show_public_values);
        let age_above_18 = show_public_values[0] == Field::ONE;
        println!("  ageAbove18: {}\n", age_above_18);
    }

    // Measure file sizes
    info!("Measuring artifact sizes...");
    let prepare_proving_key_bytes =
        get_file_size(&path_config.key_path(PREPARE_PROVING_KEY).to_string_lossy());
    let prepare_verifying_key_bytes = get_file_size(
        &path_config
            .key_path(PREPARE_VERIFYING_KEY)
            .to_string_lossy(),
    );
    let show_proving_key_bytes =
        get_file_size(&path_config.key_path(SHOW_PROVING_KEY).to_string_lossy());
    let show_verifying_key_bytes =
        get_file_size(&path_config.key_path(SHOW_VERIFYING_KEY).to_string_lossy());
    let prepare_proof_bytes =
        get_file_size(&path_config.artifact_path(PREPARE_PROOF).to_string_lossy());
    let show_proof_bytes = get_file_size(&path_config.artifact_path(SHOW_PROOF).to_string_lossy());
    let prepare_witness_bytes =
        get_file_size(&path_config.artifact_path(PREPARE_WITNESS).to_string_lossy());
    let show_witness_bytes =
        get_file_size(&path_config.artifact_path(SHOW_WITNESS).to_string_lossy());

    BenchmarkResults {
        prepare_setup_ms,
        show_setup_ms,
        generate_blinds_ms,
        prove_prepare_ms,
        reblind_prepare_ms,
        prove_show_ms,
        reblind_show_ms,
        verify_prepare_ms,
        verify_show_ms,
        prepare_proving_key_bytes,
        prepare_verifying_key_bytes,
        show_proving_key_bytes,
        show_verifying_key_bytes,
        prepare_proof_bytes,
        show_proof_bytes,
        prepare_witness_bytes,
        show_witness_bytes,
    }
}

#[cfg(feature = "jwt-circuit")]
fn execute_prepare(action: CircuitAction, options: CommandOptions) {
    let path_config = PathConfig::development();

    match action {
        CircuitAction::Setup => {
            info!(
                input = ?options.input,
                "Setting up Spartan-2 keys for the Prepare circuit"
            );
            let circuit = PrepareCircuit::new(path_config.clone(), options.input.clone());
            setup_circuit_keys(
                circuit,
                path_config.key_path(PREPARE_PROVING_KEY),
                path_config.key_path(PREPARE_VERIFYING_KEY),
            );
        }
        CircuitAction::Run => {
            let circuit = PrepareCircuit::new(path_config, options.input.clone());
            info!("Running Prepare circuit with ZK-Spartan");
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = PrepareCircuit::new(path_config.clone(), options.input.clone());
            info!("Proving Prepare circuit with ZK-Spartan");
            prove_circuit(
                circuit,
                path_config.key_path(PREPARE_PROVING_KEY),
                path_config.artifact_path(PREPARE_INSTANCE),
                path_config.artifact_path(PREPARE_WITNESS),
                path_config.artifact_path(PREPARE_PROOF),
            );
        }
        CircuitAction::Verify => {
            info!("Verifying Prepare proof with ZK-Spartan");
            let _public_values = verify_circuit(
                path_config.artifact_path(PREPARE_PROOF),
                path_config.key_path(PREPARE_VERIFYING_KEY),
            );
        }
        CircuitAction::Reblind => {
            info!("Reblind Spartan sumcheck + Hyrax PCS Prepare");
            reblind(
                PrepareCircuit::default(),
                path_config.key_path(PREPARE_PROVING_KEY),
                path_config.artifact_path(PREPARE_INSTANCE),
                path_config.artifact_path(PREPARE_WITNESS),
                path_config.artifact_path(PREPARE_PROOF),
                path_config.artifact_path(SHARED_BLINDS),
            );
        }
        CircuitAction::GenerateSharedBlinds => {
            info!("Generating shared blinds for Spartan-2 circuits");
            generate_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS), NUM_SHARED);
        }
        CircuitAction::Benchmark => {
            let results = run_complete_pipeline(options.input);
            results.print_summary();
        }
    }
}

#[cfg(feature = "show-circuit")]
fn execute_show(action: CircuitAction, options: CommandOptions) {
    let path_config = PathConfig::development();

    match action {
        CircuitAction::Setup => {
            info!(input = ?options.input, "Setting up Spartan-2 keys for the Show circuit");
            let circuit = ShowCircuit::new(path_config.clone(), options.input.clone());
            setup_circuit_keys(
                circuit,
                path_config.key_path(SHOW_PROVING_KEY),
                path_config.key_path(SHOW_VERIFYING_KEY),
            );
        }
        CircuitAction::Run => {
            let circuit = ShowCircuit::new(path_config, options.input.clone());
            info!("Running Show circuit with ZK-Spartan");
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = ShowCircuit::new(path_config.clone(), options.input.clone());
            info!("Proving Show circuit with ZK-Spartan");
            prove_circuit(
                circuit,
                path_config.key_path(SHOW_PROVING_KEY),
                path_config.artifact_path(SHOW_INSTANCE),
                path_config.artifact_path(SHOW_WITNESS),
                path_config.artifact_path(SHOW_PROOF),
            );
        }
        CircuitAction::Verify => {
            info!("Verifying Show proof with ZK-Spartan");
            let public_values = verify_circuit(
                path_config.artifact_path(SHOW_PROOF),
                path_config.key_path(SHOW_VERIFYING_KEY),
            );
            // Show public IO: [ageAbove18, deviceKeyX, deviceKeyY]
            if !public_values.is_empty() {
                let age_above_18 = public_values[0] == Field::ONE;
                println!("ageAbove18: {} (raw: {:?})", age_above_18, public_values[0]);
            }
        }
        CircuitAction::Reblind => {
            info!("Reblind Spartan sumcheck + Hyrax PCS Show");
            reblind(
                ShowCircuit::default(),
                path_config.key_path(SHOW_PROVING_KEY),
                path_config.artifact_path(SHOW_INSTANCE),
                path_config.artifact_path(SHOW_WITNESS),
                path_config.artifact_path(SHOW_PROOF),
                path_config.artifact_path(SHARED_BLINDS),
            );
        }
        CircuitAction::GenerateSharedBlinds => {
            eprintln!("Error: generate_shared_blinds is only supported for the Prepare circuit");
            process::exit(1);
        }
        CircuitAction::Benchmark => {
            let results = run_complete_pipeline(options.input);
            results.print_summary();
        }
    }
}

#[cfg(feature = "rsa-circuits")]
fn execute_rsa(action: CircuitAction, options: CommandOptions, is_2048: bool) {
    let path_config = PathConfig::development();

    let (pk_key, vk_key, proof_key, witness_key, instance_key) = if is_2048 {
        (
            RSA2048_PROVING_KEY,
            RSA2048_VERIFYING_KEY,
            RSA2048_PROOF,
            RSA2048_WITNESS,
            RSA2048_INSTANCE,
        )
    } else {
        (
            RSA4096_PROVING_KEY,
            RSA4096_VERIFYING_KEY,
            RSA4096_PROOF,
            RSA4096_WITNESS,
            RSA4096_INSTANCE,
        )
    };
    let label = if is_2048 { "RSA-2048" } else { "RSA-4096" };

    let make_circuit = |pc: PathConfig, inp: Option<PathBuf>| -> RsaVerifyCircuit {
        if is_2048 {
            RsaVerifyCircuit::new_2048(pc, inp)
        } else {
            RsaVerifyCircuit::new_4096(pc, inp)
        }
    };

    match action {
        CircuitAction::Setup => {
            info!(input = ?options.input, "Setting up Spartan-2 keys for {} circuit", label);
            let circuit = make_circuit(path_config.clone(), options.input.clone());
            setup_circuit_keys(
                circuit,
                path_config.key_path(pk_key),
                path_config.key_path(vk_key),
            );
        }
        CircuitAction::Run => {
            let circuit = make_circuit(path_config, options.input.clone());
            info!("Running {} circuit with ZK-Spartan", label);
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = make_circuit(path_config.clone(), options.input.clone());
            info!("Proving {} circuit with ZK-Spartan", label);
            prove_circuit(
                circuit,
                path_config.key_path(pk_key),
                path_config.artifact_path(instance_key),
                path_config.artifact_path(witness_key),
                path_config.artifact_path(proof_key),
            );
        }
        CircuitAction::Verify => {
            info!("Verifying {} proof with ZK-Spartan", label);
            let public_values = verify_circuit(
                path_config.artifact_path(proof_key),
                path_config.key_path(vk_key),
            );
            if !public_values.is_empty() {
                println!(
                    "{} public values (modulus limbs): {} values",
                    label,
                    public_values.len()
                );
            }
        }
        CircuitAction::Reblind | CircuitAction::GenerateSharedBlinds => {
            eprintln!(
                "Error: {} does not support reblind or shared blinds (standalone circuit)",
                label
            );
            process::exit(1);
        }
        CircuitAction::Benchmark => {
            run_rsa_benchmark(options.input, is_2048);
        }
    }
}

#[cfg(feature = "rsa-circuits")]
fn run_rsa_benchmark(input_path: Option<PathBuf>, is_2048: bool) {
    let path_config = PathConfig::development();

    let (pk_key, vk_key, proof_key, witness_key, instance_key) = if is_2048 {
        (
            RSA2048_PROVING_KEY,
            RSA2048_VERIFYING_KEY,
            RSA2048_PROOF,
            RSA2048_WITNESS,
            RSA2048_INSTANCE,
        )
    } else {
        (
            RSA4096_PROVING_KEY,
            RSA4096_VERIFYING_KEY,
            RSA4096_PROOF,
            RSA4096_WITNESS,
            RSA4096_INSTANCE,
        )
    };
    let label = if is_2048 { "RSA-2048" } else { "RSA-4096" };

    let make_circuit = |pc: PathConfig, inp: Option<PathBuf>| -> RsaVerifyCircuit {
        if is_2048 {
            RsaVerifyCircuit::new_2048(pc, inp)
        } else {
            RsaVerifyCircuit::new_4096(pc, inp)
        }
    };

    println!("\n╔════════════════════════════════════════════════╗");
    println!(
        "║   STARTING {} BENCHMARK PIPELINE            ║",
        label
    );
    println!("╚════════════════════════════════════════════════╝\n");

    // Step 1: Setup
    info!("Step 1/3: Setting up {} circuit...", label);
    let circuit = make_circuit(path_config.clone(), input_path.clone());
    let t0 = Instant::now();
    let (pk, vk) = setup_circuit_keys_no_save(circuit);
    let setup_ms = t0.elapsed().as_millis();
    println!("✓ {} setup completed: {} ms\n", label, setup_ms);

    if let Err(e) = save_keys(
        path_config.key_path(pk_key),
        path_config.key_path(vk_key),
        &pk,
        &vk,
    ) {
        eprintln!("Failed to save {} keys: {}", label, e);
        std::process::exit(1);
    }

    // Step 2: Prove
    info!("Step 2/3: Proving {} circuit...", label);
    let circuit = make_circuit(path_config.clone(), input_path.clone());
    let t0 = Instant::now();
    prove_circuit_with_pk(
        circuit,
        &pk,
        path_config.artifact_path(instance_key),
        path_config.artifact_path(witness_key),
        path_config.artifact_path(proof_key),
    );
    let prove_ms = t0.elapsed().as_millis();
    println!("✓ {} proof generated: {} ms\n", label, prove_ms);

    // Step 3: Verify
    info!("Step 3/3: Verifying {} proof...", label);
    let proof = load_proof(path_config.artifact_path(proof_key)).expect("load proof failed");
    let t0 = Instant::now();
    let public_values = verify_circuit_with_loaded_data(&proof, &vk);
    let verify_ms = t0.elapsed().as_millis();
    println!("✓ {} proof verified: {} ms", label, verify_ms);
    if !public_values.is_empty() {
        println!(
            "  Public values (modulus limbs): {} values\n",
            public_values.len()
        );
    }

    // Measure artifact sizes
    info!("Measuring artifact sizes...");
    let proving_key_bytes = get_file_size(&path_config.key_path(pk_key).to_string_lossy());
    let verifying_key_bytes = get_file_size(&path_config.key_path(vk_key).to_string_lossy());
    let proof_bytes = get_file_size(&path_config.artifact_path(proof_key).to_string_lossy());
    let witness_bytes = get_file_size(&path_config.artifact_path(witness_key).to_string_lossy());

    // Print summary
    println!("\n╔════════════════════════════════════════════════╗");
    println!(
        "║     {} BENCHMARK RESULTS                    ║",
        label
    );
    println!("╠════════════════════════════════════════════════╣");
    println!("║ TIMING MEASUREMENTS                            ║");
    println!("╠════════════════════════════════════════════════╣");
    println!("║ Setup:                  {:>10} ms      ║", setup_ms);
    println!("║ Prove:                  {:>10} ms      ║", prove_ms);
    println!("║ Verify:                 {:>10} ms      ║", verify_ms);
    println!("╠════════════════════════════════════════════════╣");
    println!("║ SIZE MEASUREMENTS                              ║");
    println!("╠════════════════════════════════════════════════╣");
    println!(
        "║ Proving Key:            {:>12}       ║",
        format_size(proving_key_bytes)
    );
    println!(
        "║ Verifying Key:          {:>12}       ║",
        format_size(verifying_key_bytes)
    );
    println!(
        "║ Proof:                  {:>12}       ║",
        format_size(proof_bytes)
    );
    println!(
        "║ Witness:                {:>12}       ║",
        format_size(witness_bytes)
    );
    println!("╚════════════════════════════════════════════════╝\n");
}

fn parse_command(args: &[String]) -> Result<ParsedCommand, String> {
    if args.is_empty() {
        return Err("No command provided".into());
    }

    match args[0].as_str() {
        "-h" | "--help" => {
            print_usage();
            process::exit(0);
        }
        #[cfg(feature = "jwt-circuit")]
        "prepare" => parse_circuit_command(CircuitKind::Prepare, &args[1..]),
        #[cfg(feature = "show-circuit")]
        "show" => parse_circuit_command(CircuitKind::Show, &args[1..]),
        #[cfg(feature = "rsa-circuits")]
        "rsa2048" => parse_circuit_command(CircuitKind::Rsa2048, &args[1..]),
        #[cfg(feature = "rsa-circuits")]
        "rsa4096" => parse_circuit_command(CircuitKind::Rsa4096, &args[1..]),
        #[cfg(all(feature = "jwt-circuit", feature = "show-circuit"))]
        "benchmark" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare, // Benchmark runs both circuits, but we need to pick one for the enum
            action: CircuitAction::Benchmark,
            options: parse_options(&args[1..])?,
        }),
        #[cfg(feature = "jwt-circuit")]
        "setup_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Setup,
            options: parse_options(&args[1..])?,
        }),
        #[cfg(feature = "show-circuit")]
        "setup_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Setup,
            options: parse_options(&args[1..])?,
        }),
        #[cfg(feature = "jwt-circuit")]
        "prove_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Prove,
            options: parse_options(&args[1..])?,
        }),
        #[cfg(feature = "show-circuit")]
        "prove_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Prove,
            options: parse_options(&args[1..])?,
        }),
        #[cfg(feature = "jwt-circuit")]
        "verify_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Verify,
            options: ensure_no_options(&args[1..])?,
        }),
        #[cfg(feature = "show-circuit")]
        "verify_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Verify,
            options: ensure_no_options(&args[1..])?,
        }),
        #[cfg(feature = "jwt-circuit")]
        "reblind_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Reblind,
            options: ensure_no_options(&args[1..])?,
        }),
        #[cfg(feature = "show-circuit")]
        "reblind_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Reblind,
            options: ensure_no_options(&args[1..])?,
        }),
        #[cfg(feature = "jwt-circuit")]
        "generate_shared_blinds" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::GenerateSharedBlinds,
            options: ensure_no_options(&args[1..])?,
        }),
        other => Err(format!("Unknown command '{other}'")),
    }
}

fn parse_circuit_command(circuit: CircuitKind, tail: &[String]) -> Result<ParsedCommand, String> {
    if tail.is_empty() {
        return Ok(ParsedCommand {
            circuit,
            action: CircuitAction::Run,
            options: CommandOptions::default(),
        });
    }

    let first = &tail[0];
    let (action, option_start) = match first.as_str() {
        "run" => (CircuitAction::Run, 1),
        "setup" => (CircuitAction::Setup, 1),
        "prove" => (CircuitAction::Prove, 1),
        "verify" => (CircuitAction::Verify, 1),
        "reblind" => (CircuitAction::Reblind, 1),
        "generate_shared_blinds" => (CircuitAction::GenerateSharedBlinds, 1),
        "benchmark" => (CircuitAction::Benchmark, 1),
        s if s.starts_with('-') => (CircuitAction::Run, 0),
        other => {
            return Err(format!(
                "Unknown action '{other}' for {:?}. Expected one of run|setup|prove|verify|reblind|generate_shared_blinds|benchmark.",
                circuit
            ))
        }
    };

    #[cfg(feature = "jwt-circuit")]
    if action == CircuitAction::GenerateSharedBlinds && circuit != CircuitKind::Prepare {
        return Err(
            "The generate_shared_blinds action is only supported for the Prepare circuit".into(),
        );
    }

    #[cfg(feature = "rsa-circuits")]
    if action == CircuitAction::Reblind
        && (circuit == CircuitKind::Rsa2048 || circuit == CircuitKind::Rsa4096)
    {
        return Err("RSA circuits do not support reblind (standalone circuit)".into());
    }

    let options_slice = &tail[option_start..];
    let options = match action {
        CircuitAction::Run
        | CircuitAction::Prove
        | CircuitAction::Setup
        | CircuitAction::Benchmark => parse_options(options_slice)?,
        CircuitAction::Verify | CircuitAction::Reblind | CircuitAction::GenerateSharedBlinds => {
            ensure_no_options(options_slice)?
        }
    };

    Ok(ParsedCommand {
        circuit,
        action,
        options,
    })
}

fn ensure_no_options(args: &[String]) -> Result<CommandOptions, String> {
    if args.is_empty() {
        Ok(CommandOptions::default())
    } else {
        Err(format!("Unexpected options: {}", args.join(" ")))
    }
}

fn parse_options(args: &[String]) -> Result<CommandOptions, String> {
    let mut options = CommandOptions::default();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--input" || arg == "-i" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| "Missing value for --input".to_string())?;
            options.input = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--input=") {
            if value.is_empty() {
                return Err("Missing value for --input".into());
            }
            options.input = Some(PathBuf::from(value));
        } else if arg == "--help" || arg == "-h" {
            print_usage();
            process::exit(0);
        } else {
            return Err(format!("Unknown option '{arg}'"));
        }
        index += 1;
    }

    Ok(options)
}

fn print_usage() {
    eprintln!(
        "Usage:
  ecdsa-spartan2 <prepare|show|rsa2048|rsa4096> [run|setup|prove|verify] [options]
  ecdsa-spartan2 benchmark [options]

Commands:
  benchmark            Run complete pipeline with full metrics (setup, prove, reblind, verify)
  prepare <action>     Run action on Prepare circuit
  show <action>        Run action on Show circuit
  rsa2048 <action>     Run action on RSA-2048 verify circuit
  rsa4096 <action>     Run action on RSA-4096 verify circuit

Actions:
  run                  Run the complete circuit (setup, prove, verify)
  setup                Generate proving and verifying keys
  prove                Generate proof
  verify               Verify proof
  reblind              Reblind proof (prepare/show only)
  benchmark            Run complete benchmark pipeline

Options:
  --input, -i <path>   Override the circuit input JSON (run/prove/setup/benchmark)

Examples:
  cargo run --release -- benchmark --input ../circom/inputs/jwt/generated.json
  cargo run --release -- prepare run --input ../circom/inputs/jwt/generated.json
  cargo run --release -- show prove --input ../circom/inputs/show/generated.json
  cargo run --release -- show verify
  cargo run --release -- rsa2048 benchmark --input ../circom/inputs/rsa_verify_2048/default.json
  cargo run --release -- rsa4096 benchmark --input ../circom/inputs/rsa_verify_4096/default.json

Legacy commands like `prepare`, `show`, `prove_prepare`, etc. are still supported."
    );
}
