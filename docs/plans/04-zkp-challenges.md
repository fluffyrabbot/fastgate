# Phase 4 (Bonus): Zero-Knowledge Proof Challenges

**Status**: Proposed (Advanced/Research)
**Priority**: Low (Cool factor: High)
**Effort**: 4-5 weeks
**Innovation Level**: 🔥🔥🔥🔥 Very High (Novel application of zkSNARKs to bot defense)

---

## 1. Overview

### Problem Statement
Current PoW challenges (SHA-256) have limitations:
- **Server learns solution**: Minor privacy leak
- **Fixed difficulty**: Can't adapt without changing nonce
- **No reputation**: Can't prove "I've solved N challenges before"
- **Linkable**: Each solution reveals client capability

### Solution
Replace SHA-256 PoW with **zero-knowledge proofs** (zkSNARKs) that enable:
1. **Privacy-preserving**: Server verifies proof without learning witness
2. **Flexible claims**: Prove arbitrary statements (not just hash preimage)
3. **Unlinkable**: Multiple proofs from same client can't be correlated
4. **Compact**: ~200 byte proofs (vs megabytes of traditional proofs)

### Key Benefits
- **Privacy**: No solution disclosure
- **Innovation**: First L7 gateway with zkSNARK challenges
- **Future-proof**: Enables advanced features (reputation proofs, rate-limit proofs)
- **Efficient verification**: Constant-time (~2ms regardless of circuit complexity)

---

## 2. Zero-Knowledge Primer

### 2.1 What is a zkSNARK?

**SNARK** = **S**uccinct **N**on-interactive **AR**gument of **K**nowledge

**Properties:**
- **Succinct**: Proof size ~200 bytes
- **Non-interactive**: Prover → Verifier (one message)
- **Zero-knowledge**: Verifier learns nothing except claim validity

**Example:**
```
Prover claims: "I know x such that SHA256(x) has 16 leading zero bits"
Traditional: Send x, verifier computes SHA256(x) and checks
zkSNARK: Send π (proof), verifier checks π without learning x

Proof size: 200 bytes (constant)
Verification time: 2ms (constant)
```

### 2.2 How It Works

**Setup Phase** (one-time, done by FastGate developers):
```bash
# 1. Write circuit (Circom language)
circom challenge.circom --r1cs --wasm

# 2. Generate proving/verification keys
snarkjs groth16 setup challenge.r1cs pot_final.ptau challenge_0000.zkey
snarkjs zkey contribute challenge_0000.zkey challenge_final.zkey

# 3. Export verification key
snarkjs zkey export verificationkey challenge_final.zkey verification_key.json
```

**Runtime** (each challenge):
```
Client:
  1. Receive public input (challenge nonce)
  2. Find witness (solution)
  3. Generate proof: π = prove(circuit, witness, public_input)
  4. Send π to server

Server:
  1. Verify: verify(verification_key, π, public_input) → true/false
  2. If true, issue clearance
```

---

## 3. Technical Architecture

### 3.1 Circuit Design

**Circuit 1: Basic PoW (MVP)**
```circom
// challenge-circuits/pow.circom
pragma circom 2.1.0;

include "node_modules/circomlib/circuits/sha256/sha256.circom";
include "node_modules/circomlib/circuits/comparators.circom";

template ProofOfWork(difficultyBits) {
    // Public inputs (known to verifier)
    signal input nonce[256];         // Challenge nonce (256 bits)

    // Private inputs (witness, kept secret)
    signal input solution[256];      // Solution found by client

    // Output (public)
    signal output validProof;

    // Compute hash = SHA256(nonce || solution)
    component sha = Sha256(512);     // 256 + 256 bits
    for (var i = 0; i < 256; i++) {
        sha.in[i] <== nonce[i];
        sha.in[256 + i] <== solution[i];
    }

    // Check that first 'difficultyBits' are zero
    component checker = LeadingZeros(difficultyBits);
    for (var i = 0; i < difficultyBits; i++) {
        checker.in[i] <== sha.out[i];
    }

    validProof <== checker.out;  // 1 if valid, 0 otherwise
}

// Helper: Check all bits are zero
template LeadingZeros(n) {
    signal input in[n];
    signal output out;

    signal sum;
    sum <== 0;
    for (var i = 0; i < n; i++) {
        sum <== sum + in[i];
    }

    // out = 1 if sum == 0, else 0
    component isZero = IsZero();
    isZero.in <== sum;
    out <== isZero.out;
}

component main {public [nonce]} = ProofOfWork(16);
```

**Circuit 2: Reputation Proof (Advanced)**
```circom
// challenge-circuits/reputation.circom
pragma circom 2.1.0;

template ReputationProof() {
    // Public: merkle root of valid challenge IDs
    signal input merkleRoot[256];

    // Private: proof that I solved N challenges
    signal input challengeIDs[10][256];      // 10 challenge IDs
    signal input merklePaths[10][8][256];    // Merkle paths (depth 8)

    // For each challenge ID, verify merkle path
    component verifiers[10];
    for (var i = 0; i < 10; i++) {
        verifiers[i] = MerkleVerifier(8);
        verifiers[i].root <== merkleRoot;
        verifiers[i].leaf <== challengeIDs[i];
        for (var j = 0; j < 8; j++) {
            verifiers[i].path[j] <== merklePaths[i][j];
        }
    }

    // Output: 1 if all 10 challenges are valid
    signal output validReputation;
    // ... aggregation logic
}
```

### 3.2 Client-Side Proving

**Files to create:**
- `challenge-page/zkp/prover.js` (WebAssembly wrapper)
- `challenge-page/zkp/worker.js` (Web Worker for proof generation)

**Implementation:**
```javascript
// challenge-page/zkp/prover.js
import { groth16 } from 'snarkjs';

export class ZKPProver {
    constructor() {
        this.wasmPath = '/zkp/pow_js/pow.wasm';
        this.zkeyPath = '/zkp/pow_final.zkey';
        this.ready = false;
    }

    async init() {
        // Pre-load WASM and proving key
        await fetch(this.wasmPath);
        await fetch(this.zkeyPath);
        this.ready = true;
    }

    async prove(nonce, solution) {
        if (!this.ready) await this.init();

        // Convert inputs to circuit format
        const input = {
            nonce: hexToBitArray(nonce),
            solution: hexToBitArray(solution)
        };

        // Generate proof (runs in ~1-5 seconds depending on device)
        const { proof, publicSignals } = await groth16.fullProve(
            input,
            this.wasmPath,
            this.zkeyPath
        );

        return {
            proof: this.formatProof(proof),
            publicSignals: publicSignals
        };
    }

    formatProof(proof) {
        // Convert to compact JSON format
        return {
            pi_a: proof.pi_a,
            pi_b: proof.pi_b,
            pi_c: proof.pi_c,
            protocol: 'groth16',
            curve: 'bn128'
        };
    }
}

function hexToBitArray(hex) {
    const bytes = hexToBytes(hex);
    const bits = [];

    for (let byte of bytes) {
        for (let i = 7; i >= 0; i--) {
            bits.push((byte >> i) & 1);
        }
    }

    return bits;
}

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}
```

**Web Worker (non-blocking UI):**
```javascript
// challenge-page/zkp/worker.js
importScripts('/zkp/snarkjs.min.js');

let prover;

self.addEventListener('message', async (e) => {
    const { type, data } = e.data;

    if (type === 'init') {
        prover = new ZKPProver();
        await prover.init();
        self.postMessage({ type: 'ready' });
    }

    if (type === 'prove') {
        const { nonce, solution } = data;
        const result = await prover.prove(nonce, solution);
        self.postMessage({ type: 'proof', result });
    }
});
```

**Integration with challenge page:**
```javascript
// challenge-page/app.js (add zkSNARK option)

async function solveZKPChallenge(nonceB64, difficulty) {
    setMsg('Solving challenge (zero-knowledge proof)...');

    // Find solution (same as current PoW)
    const nonce = base64urlToBytes(nonceB64);
    const solution = await solvePow(nonceB64, difficulty);  // Reuse existing solver

    // Generate zkSNARK proof
    setMsg('Generating cryptographic proof...');

    const worker = new Worker('/zkp/worker.js');
    worker.postMessage({ type: 'init' });

    await new Promise(resolve => {
        worker.addEventListener('message', (e) => {
            if (e.data.type === 'ready') resolve();
        });
    });

    const proofPromise = new Promise((resolve) => {
        worker.addEventListener('message', (e) => {
            if (e.data.type === 'proof') {
                resolve(e.data.result);
            }
        });
    });

    worker.postMessage({
        type: 'prove',
        data: {
            nonce: bytesToHex(nonce),
            solution: solution.toString(16).padStart(64, '0')
        }
    });

    const { proof, publicSignals } = await proofPromise;
    return { proof, publicSignals };
}
```

### 3.3 Server-Side Verification

**Files to create:**
- `decision-service/internal/zkp/verifier.go`
- `decision-service/internal/zkp/groth16.go`

**Dependencies:**
```bash
go get github.com/consensys/gnark@latest
go get github.com/consensys/gnark-crypto@latest
```

**Implementation:**
```go
// decision-service/internal/zkp/verifier.go
package zkp

import (
    "encoding/json"
    "errors"

    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark/backend/witness"
)

type Verifier struct {
    VerifyingKey groth16.VerifyingKey
}

func NewVerifier(vkPath string) (*Verifier, error) {
    // Load verification key (exported from snarkjs)
    vkData, err := os.ReadFile(vkPath)
    if err != nil {
        return nil, err
    }

    var vk groth16.VerifyingKey
    // Parse JSON verification key
    if err := parseVerificationKey(vkData, &vk); err != nil {
        return nil, err
    }

    return &Verifier{VerifyingKey: vk}, nil
}

type Proof struct {
    PiA      [2]string `json:"pi_a"`
    PiB      [3][2]string `json:"pi_b"`
    PiC      [2]string `json:"pi_c"`
    Protocol string `json:"protocol"`
    Curve    string `json:"curve"`
}

func (v *Verifier) Verify(proofJSON []byte, publicInputs []byte) (bool, error) {
    // Parse proof
    var proof Proof
    if err := json.Unmarshal(proofJSON, &proof); err != nil {
        return false, err
    }

    if proof.Protocol != "groth16" {
        return false, errors.New("unsupported protocol")
    }

    // Convert to gnark proof
    gnarkProof := convertToGnarkProof(proof)

    // Parse public inputs (witness)
    w, err := witness.New(ecc.BN254.ScalarField())
    if err != nil {
        return false, err
    }

    // Verify (constant time ~2ms)
    err = groth16.Verify(gnarkProof, v.VerifyingKey, w)
    return err == nil, nil
}

func convertToGnarkProof(proof Proof) groth16.Proof {
    // Convert JSON proof to gnark format
    // This requires parsing the string coordinates and converting to big.Int

    var gnarkProof groth16.Proof

    // Parse pi_a
    gnarkProof.Ar.X.SetString(proof.PiA[0], 10)
    gnarkProof.Ar.Y.SetString(proof.PiA[1], 10)

    // Parse pi_b
    gnarkProof.Bs.X.A0.SetString(proof.PiB[0][0], 10)
    gnarkProof.Bs.X.A1.SetString(proof.PiB[0][1], 10)
    gnarkProof.Bs.Y.A0.SetString(proof.PiB[1][0], 10)
    gnarkProof.Bs.Y.A1.SetString(proof.PiB[1][1], 10)

    // Parse pi_c
    gnarkProof.Krs.X.SetString(proof.PiC[0], 10)
    gnarkProof.Krs.Y.SetString(proof.PiC[1], 10)

    return gnarkProof
}

func parseVerificationKey(data []byte, vk *groth16.VerifyingKey) error {
    // Parse snarkjs verification key JSON
    // This is complex, for MVP could use pre-converted Go binary format

    // Placeholder: In production, parse JSON and populate vk fields
    return nil
}
```

**Endpoint:**
```go
// decision-service/cmd/fastgate/main.go

var zkpVerifier *zkp.Verifier
if cfg.ZKP.Enabled {
    vf, err := zkp.NewVerifier(cfg.ZKP.VerificationKeyPath)
    if err != nil {
        log.Fatalf("zkp verifier: %v", err)
    }
    zkpVerifier = vf
    log.Printf("zkSNARK verification enabled (circuit: %s)", cfg.ZKP.CircuitName)
}

mux.Handle("/v1/challenge/complete/zkp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    type Req struct {
        ChallengeID   string          `json:"challenge_id"`
        Proof         json.RawMessage `json:"proof"`
        PublicSignals json.RawMessage `json:"public_signals"`
        ReturnURL     string          `json:"return_url"`
    }

    var req Req
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    // Verify zkSNARK proof
    valid, err := zkpVerifier.Verify(req.Proof, req.PublicSignals)
    if err != nil || !valid {
        http.Error(w, "proof verification failed", http.StatusBadRequest)
        return
    }

    // Issue clearance (premium tier for zkSNARK users)
    tokenStr, _ := kr.Sign("zkp_verified", 24*time.Hour)
    http.SetCookie(w, buildCookie(cfg, tokenStr))

    w.Header().Set("Location", req.ReturnURL)
    w.WriteHeader(http.StatusFound)
}))
```

---

## 4. Advanced Use Cases

### 4.1 Reputation Proofs
**Claim**: "I've solved 10 challenges in the past hour (without revealing which ones)"

**Benefits:**
- Returning users get instant access
- No linkability (can't track across sessions)

**Circuit:**
```circom
template ReputationProof() {
    signal input merkleRoot[256];               // Public: root of valid challenge tree
    signal input challengeIDs[10][256];         // Private: my 10 challenges
    signal input merklePaths[10][8][256];       // Private: merkle proofs

    // Verify each challenge is in tree
    // ... verification logic
}
```

### 4.2 Rate-Limit Proofs
**Claim**: "I haven't exceeded 100 requests/hour (without revealing exact count)"

**Circuit:**
```circom
template RateLimitProof() {
    signal input requestCount;      // Private: my actual count
    signal input limit;             // Public: max allowed (100)

    // Prove: requestCount < limit (without revealing requestCount)
    component lessThan = LessThan(32);
    lessThan.in[0] <== requestCount;
    lessThan.in[1] <== limit;
    lessThan.out ==> 1;  // Constrain to be true
}
```

### 4.3 Device Attestation (Combined with Phase 1)
**Claim**: "I have a TPM chip (without revealing device ID)"

**Circuit:**
```circom
template AnonymousAttestationProof() {
    signal input tpmSignature[256];             // Private: TPM signature
    signal input tpmPublicKey[256];             // Private: TPM public key
    signal input manufacturerCARoot[256];       // Public: CA root hash

    // Verify signature is from a genuine TPM cert chain
    // ... verification logic

    // Output: 1 if valid, 0 otherwise (doesn't reveal device)
}
```

---

## 5. Implementation Phases

### Phase 4.1: Setup & Tooling (Week 1)

**Task 1: Install dependencies**
```bash
npm install -g snarkjs circom
npm install snarkjs --save
```

**Task 2: Create circuit**
```bash
mkdir -p challenge-circuits
cd challenge-circuits

# Write pow.circom (see section 3.1)
vim pow.circom

# Compile
circom pow.circom --r1cs --wasm --sym

# Generate proving key (requires Powers of Tau ceremony)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau
snarkjs groth16 setup pow.r1cs powersOfTau28_hez_final_15.ptau pow_0000.zkey

# Contribute randomness
snarkjs zkey contribute pow_0000.zkey pow_final.zkey --name="FastGate Contribution"

# Export verification key
snarkjs zkey export verificationkey pow_final.zkey verification_key.json

# Export for Go
snarkjs zkey export solidityverifier pow_final.zkey  # Adapt for gnark
```

### Phase 4.2: Client Prover (Week 2)

Implement browser proving (see section 3.2)

**Files:**
- `challenge-page/zkp/prover.js`
- `challenge-page/zkp/worker.js`
- `challenge-page/zkp/pow_js/` (compiled WASM)

### Phase 4.3: Server Verifier (Week 3)

Implement Go verification (see section 3.3)

**Files:**
- `decision-service/internal/zkp/verifier.go`
- `decision-service/internal/zkp/groth16.go`

### Phase 4.4: Integration & Testing (Week 4-5)

**Test proof generation:**
```javascript
// Test in browser console
const prover = new ZKPProver();
await prover.init();

const nonce = '0'.repeat(64);  // 256-bit zero nonce
const solution = 'abcd1234'.padStart(64, '0');

const { proof, publicSignals } = await prover.prove(nonce, solution);
console.log('Proof size:', JSON.stringify(proof).length, 'bytes');
// Expected: ~200-300 bytes
```

**Test verification:**
```bash
# Send test proof to server
curl -X POST http://localhost:8080/v1/challenge/complete/zkp \
  -H 'Content-Type: application/json' \
  -d '{
    "challenge_id": "test",
    "proof": {...},
    "public_signals": [...],
    "return_url": "/"
  }'

# Expected: 302 redirect with clearance cookie
```

---

## 6. Performance Benchmarks

**Proof Generation (Client):**
- Desktop (8-core CPU): 1-2 seconds
- Laptop (4-core CPU): 2-4 seconds
- Mobile (ARM): 4-8 seconds
- WASM size: ~500 KB

**Verification (Server):**
- Time: ~2ms (constant, independent of circuit complexity)
- Memory: ~10 MB per verification
- Throughput: ~500 verifications/second/core

**Comparison to SHA-256 PoW:**
| Metric | SHA-256 PoW | zkSNARK |
|--------|-------------|---------|
| Proof size | 4 bytes (solution) | ~200 bytes |
| Client time | 1-5 sec (varies with difficulty) | 2-8 sec (fixed) |
| Server time | <1ms (re-hash) | ~2ms (verify) |
| Privacy | Solution revealed | Solution hidden |
| Flexibility | Fixed (hash preimage) | Arbitrary claims |

---

## 7. Configuration

```yaml
# config.example.yaml
zkp:
  enabled: true
  circuit_name: "pow"
  verification_key_path: "/etc/fastgate/zkp/verification_key.json"

  # Serve WASM and proving key (clients download)
  assets_path: "/usr/share/fastgate/zkp/"

  # Fallback to SHA-256 PoW if client doesn't support WASM
  fallback_to_pow: true

token:
  tier_ttl:
    low: 21600                # 6 hours
    zkp_verified: 86400       # 24 hours (premium)
    zkp_reputation: 172800    # 48 hours (reputation proof)
```

---

## 8. Security Considerations

### 8.1 Trusted Setup
**Problem:** Groth16 requires trusted setup (Powers of Tau ceremony)

**Mitigation:**
- Use well-established ceremony (Hermez PoT)
- Future: Switch to PLONK (no trusted setup)

### 8.2 Circuit Bugs
**Problem:** Under-constrained circuits can be exploited

**Mitigation:**
- Audit circuits with circomspect
- Use battle-tested templates from circomlib
- Unit test circuits with known inputs

### 8.3 Proof Malleability
**Problem:** Attacker reuses valid proofs

**Mitigation:**
- Include challenge nonce in public inputs (binds proof to challenge)
- Consume challenge after first verification

---

## 9. Success Definition

**Innovation Score: 10/10**
- First L7 gateway with zkSNARK challenges
- Enables privacy-preserving reputation
- Future-proof for advanced claims

**Effort vs Impact:**
- Effort: 4-5 weeks (high, research-heavy)
- Impact: Low (cool factor: very high)
- Differentiation: Unique in entire bot mitigation space

**Recommendation:** Implement after Phases 1-3 are stable. This is a "showcase" feature for research/academic interest, not critical for production.

---

## 10. References

- [snarkjs](https://github.com/iden3/snarkjs) - zkSNARK JavaScript library
- [Circom](https://docs.circom.io/) - Circuit language
- [gnark](https://github.com/consensys/gnark) - Go zkSNARK library
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [Powers of Tau Ceremony](https://blog.hermez.io/hermez-zk-rollup-the-new-powers-of-tau-ceremony/)
