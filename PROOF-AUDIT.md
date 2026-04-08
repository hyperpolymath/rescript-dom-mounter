# Proof Audit Framework for rescript-dom-mounter

## Current Proof Coverage

### ✅ Completed Proofs
- [x] Safety level definitions (10 levels adapted for DOM mounting)
- [x] Proof certificate structure
- [x] Level-specific attestations
- [x] Certificate construction for all mounting methods
- [x] Proof erasure guarantee
- [x] Safety level hierarchy proofs
- [x] Defence-in-depth composition

### 📝 Proofs Needing Expansion

#### 1. Detailed Function-Level Proofs
Each major function should have a dedicated proof showing it satisfies specific safety levels:

```idris
-- Needed: mountStringFunctionProof : mountString =⇒ standardMountCert
-- Needed: mountParsedFunctionProof : mountParsed =⇒ domParserMountCert
-- Needed: mountWithNonceFunctionProof : mountWithNonce =⇒ nonceMountCert
```

#### 2. Sanitisation Effectiveness Proofs
Need formal proofs that the regex blocklist covers all OWASP Top 10 DOM XSS vectors:

```idris
-- Needed: regexBlocksAllScriptTags : ∀html. containsScriptTags(html) =⇒ regexSanitise(html) = noScriptTags
-- Needed: regexBlocksAllEventHandlers : ∀html. containsEventHandlers(html) =⇒ regexSanitise(html) = noEventHandlers
```

#### 3. Tag Nesting Correctness Proofs
Need proof that stack-based validation correctly handles all HTML nesting cases:

```idris
-- Needed: stackValidatorSound : ∀html. checkTagNesting(html) = Ok ⇒ isWellNested(html)
-- Needed: stackValidatorComplete : ∀html. isWellNested(html) ⇒ checkTagNesting(html) = Ok
```

#### 4. Defence-in-Depth Redundancy Proofs
Need proofs showing that multiple layers provide independent protection:

```idris
-- Needed: domPurifyIndependentOfRegex : ∃html. regexSanitise(html) ≠ DOMPurify.sanitize(html)
-- Needed: trustedTypesIndependentOfSanitisation : ∃html. sanitisationFails(html) ∧ trustedTypesBlocks(html)
```

#### 5. Atomicity Proofs for Batch Operations
Need proof that batch operations are truly atomic:

```idris
-- Needed: batchMountAtomic : ∀specs. mountBatch(specs) = Error ⇒ noDOMChanges
-- Needed: batchMountAllOrNothing : ∀specs. mountBatch(specs) = Ok ⇒ allSpecsMounted
```

## Audit Methodology

### Step 1: Function Inventory
List all public functions that need proofs:
- `mount`
- `mountParsed`
- `mountString`
- `mountStringParsed`
- `mountSafe`
- `mountBatch`
- `mountWhenReady`
- `unmount`
- `remount`
- `mountWithNonce`

### Step 2: Safety Level Mapping
For each function, identify which safety levels apply:

| Function | L1 | L2 | L3 | L4 | L5 | L6 | L7 | L8 | L9 | L10 |
|----------|----|----|----|----|----|----|----|----|----|-----|
| mount | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| mountParsed | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| mountWithNonce | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |

### Step 3: Proof Gap Analysis
Identify missing proofs by comparing current coverage to ideal coverage.

### Step 4: Prioritization
Prioritize proofs based on:
1. Security criticality
2. Complexity of implementation
3. Likelihood of bugs
4. Regulatory requirements

## Recommended Next Steps

1. **Implement function-level proofs** for each major function
2. **Add sanitisation effectiveness proofs** for the regex blocklist
3. **Create tag nesting correctness proofs** for the stack validator
4. **Develop defence-in-depth redundancy proofs**
5. **Add atomicity proofs** for batch operations

## Proof Implementation Pattern

```idris
-- Example pattern for function-level proof
mountStringSafetyProof : ProofCertificate
mountStringSafetyProof =
  let selectorProof = proveSelectorValidation mountString
  let htmlProof = proveHTMLSanitisation mountString
  let nestingProof = proveTagNesting mountString
  let sizeProof = proveSizeLimit mountString
  let trustedTypesProof = proveTrustedTypes mountString
  let traceProof = proveTracing mountString
  let atomicityProof = proveAtomicity mountString
  let lengthProof = proveSelectorLength mountString
  in MkCertificate
    [ selectorProof
    , htmlProof
    , nestingProof
    , sizeProof
    , trustedTypesProof
    , traceProof
    , atomicityProof
    , lengthProof
    ] L5_TrustedTypesUsed
```

## Verification Checklist

- [ ] All public functions have dedicated proofs
- [ ] All safety levels have at least one proof
- [ ] Defence-in-depth redundancy is proven
- [ ] Atomic operations are formally verified
- [ ] Proofs compile without warnings in Idris2
- [ ] Proof coverage documented in README

## Maintenance Plan

1. **Add proof requirements** to pull request template
2. **Create GitHub issue template** for missing proofs
3. **Add proof coverage** to CI/CD pipeline
4. **Document proof patterns** for contributors
5. **Schedule quarterly proof audits**