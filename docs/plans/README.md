# FastGate Planning Documents

## Active Plans

### Phase 4: Zero-Knowledge Proof Challenges (Proposed)

See `04-zkp-challenges.md` for the detailed implementation plan.

**Status**: Research phase - not yet implemented

This phase proposes adding zkSNARK-based challenges using browser-side proving (snarkjs) and backend verification (gnark). This is an advanced feature that would add significant cryptographic depth to FastGate's bot detection capabilities.

## Completed Phases

Phases 1-2 have been successfully implemented:
- ✅ Phase 1: Hardware-backed attestation (WebAuthn)
- ✅ Phase 2: Federated threat intelligence (STIX/TAXII)

**Phase 3 (Behavioral entropy fingerprinting)** was partially implemented (client collection + server heuristic analyzer) but never produced any enforceable signals — the resulting "tier" was ignored by all authorization, rate-limiting, and policy logic. The ineffective code and misleading documentation were removed for integrity. Historical design docs remain in `/docs/archived/`.

For the current research proposal, see the Phase 4 document (`04-zkp-challenges.md`).
