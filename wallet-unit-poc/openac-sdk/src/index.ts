import { WasmBridge, VcSize } from "./wasm-bridge.js";
import { WitnessCalculator } from "./witness-calculator.js";
import { Prover } from "./prover.js";
import { Verifier } from "./verifier.js";
import type {
  OpenACConfig,
  ProofRequest,
  ProofResult,
  VerificationResult,
  VerifyingKeys,
  KeySet,
  SerializedKeySet,
  SerializedProof,
  PrecomputeRequest,
  PrecomputedCredential,
  PresentRequest,
  PresentationProof,
} from "./types.js";

export class OpenAC {
  private bridge: WasmBridge;
  private prover: Prover;
  private verifier: Verifier;
  private config: OpenACConfig;

  private constructor(
    bridge: WasmBridge,
    prover: Prover,
    verifier: Verifier,
    config: OpenACConfig,
  ) {
    this.bridge = bridge;
    this.prover = prover;
    this.verifier = verifier;
    this.config = config;
  }

  static async init(config: OpenACConfig = {}): Promise<OpenAC> {
    const bridge = new WasmBridge();

    if (config.wasmModule) {
      if (typeof config.wasmModule.default === "function") {
        await config.wasmModule.default();
      }
      bridge.initWithModule(config.wasmModule);
    } else {
      await bridge.init(config.wasmPath);
    }

    // Initialize WitnessCalculator if assetsDir is provided or use default
    let witnessCalculator: WitnessCalculator | undefined;
    try {
      witnessCalculator = new WitnessCalculator(config.assetsDir);
      await witnessCalculator.init();
    } catch {
      // WitnessCalculator initialization is optional - may fail if assets not available
      witnessCalculator = undefined;
    }

    const prover = new Prover(bridge, witnessCalculator);
    const verifier = new Verifier(bridge);

    return new OpenAC(bridge, prover, verifier, config);
  }

  async loadKeysFromUrl(baseUrl: string, vcSize: VcSize): Promise<KeySet> {
    const keys = await this.bridge.loadKeys(baseUrl, vcSize);
    return createKeySet(
      keys.preparePk,
      keys.prepareVk,
      keys.showPk,
      keys.showVk,
    );
  }

  async loadKeys(data: SerializedKeySet): Promise<KeySet> {
    return createKeySet(
      data.prepareProvingKey,
      data.prepareVerifyingKey,
      data.showProvingKey,
      data.showVerifyingKey,
    );
  }

  async precompute(request: PrecomputeRequest): Promise<PrecomputedCredential> {
    return this.prover.precompute(request);
  }

  async present(request: PresentRequest): Promise<PresentationProof> {
    return this.prover.present(request);
  }

  async verify(
    proof: PresentationProof,
    keys: VerifyingKeys,
  ): Promise<VerificationResult> {
    return this.verifier.verifyComponents(
      proof.prepareProof,
      proof.showProof,
      keys,
      proof.prepareInstance,
      proof.showInstance,
    );
  }

  async createProof(request: ProofRequest): Promise<ProofResult> {
    return this.prover.createProof(request);
  }

  async verifyProof(
    proof: SerializedProof,
    keys: VerifyingKeys,
  ): Promise<VerificationResult> {
    return this.verifier.verifyProof(proof, keys);
  }

  async verifyComponents(
    prepareProof: Uint8Array,
    showProof: Uint8Array,
    keys: VerifyingKeys,
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
  ): Promise<VerificationResult> {
    return this.verifier.verifyComponents(
      prepareProof,
      showProof,
      keys,
      prepareInstance,
      showInstance,
    );
  }

  get isReady(): boolean {
    return this.bridge.isInitialized;
  }
}

function createKeySet(
  prepareProvingKey: Uint8Array,
  prepareVerifyingKey: Uint8Array,
  showProvingKey: Uint8Array,
  showVerifyingKey: Uint8Array,
): KeySet {
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,

    verifyingKeys(): VerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey };
    },

    serialize(): SerializedKeySet {
      return {
        prepareProvingKey,
        prepareVerifyingKey,
        showProvingKey,
        showVerifyingKey,
      };
    },
  };
}

// Re-exports
export { Credential } from "./credential.js";
export { WorkerBridge } from "./worker-bridge.js";
export type { WorkerBridgeConfig } from "./worker-bridge.js";
export type { VcSize, SetupKeys } from "./wasm-bridge.js";
export { Prover, deserializePrecomputed } from "./prover.js";
export { Verifier } from "./verifier.js";
export { WitnessCalculator } from "./witness-calculator.js";
export { NativeBackend } from "./native-backend.js";
export type { NativeBackendConfig } from "./native-backend.js";
export { buildJwtCircuitInputs } from "./inputs/jwt-input-builder.js";
export {
  buildShowCircuitInputs,
  signDeviceNonce,
  PredicateOp,
  LogicToken,
} from "./inputs/show-input-builder.js";
export type { ShowInputOptions, PredicateSpec } from "./inputs/show-input-builder.js";

export {
  OpenACError,
  SetupError,
  ProofError,
  VerificationError,
  InputError,
  WasmError,
} from "./errors.js";

export type {
  OpenACConfig,
  ProofRequest,
  ProofResult,
  ProofTiming,
  ProofPublicValues,
  VerificationResult,
  VerifyingKeys,
  KeySet,
  SerializedKeySet,
  SerializedProof,
  SerializedProofJSON,
  DisclosedClaim,
  EcdsaPublicKey,
  EcdsaPrivateKey,
  IssuerPublicKey,
  PemPublicKey,
  JwtCircuitParams,
  ShowCircuitParams,
  JwtCircuitInputs,
  ShowCircuitInputs,
  CircuitArtifacts,
  ErrorCode,
  PrecomputeRequest,
  PrecomputedCredential,
  PrecomputeTiming,
  PresentRequest,
  PresentationProof,
  PresentationTiming,
  SerializedCredential,
  SerializedPrecomputedCredentialJSON,
} from "./types.js";

export {
  base64urlToBase64,
  base64ToBase64url,
  base64Decode,
  base64Encode,
  base64urlEncode,
  base64ToBigInt,
  base64urlToBigInt,
  bigintToBase64url,
  bytesToBigInt,
  bigintToBytes,
  uint8ArrayToBigIntArray,
  stringToPaddedBigIntArray,
  sha256Pad,
  sha256Hash,
  sha256HashString,
  encodeClaims,
  modInverse,
  modScalarField,
  circuitInputsToJson,
  jwkPointToBigInt,
  P256_SCALAR_ORDER,
} from "./utils.js";

export { DEFAULT_JWT_PARAMS, DEFAULT_SHOW_PARAMS } from "./types.js";
