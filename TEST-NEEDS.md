# TEST-NEEDS.md — rescript-dom-mounter

## CRG Grade: C — ACHIEVED 2026-04-04

## Current Test State

| Category | Count | Notes |
|----------|-------|-------|
| JavaScript tests | 3 | `tests/{safedom,panic_attack,bench}_test.js` |
| Zig FFI tests | 1 | `ffi/zig/test/integration_test.zig` |
| Verification tests | Present | `verification/tests/` |
| FFI interface tests | Present | `src/interface/ffi/test/` |

## What's Covered

- [x] DOM safety verification tests
- [x] Panic attack integration tests
- [x] Benchmark test suite
- [x] FFI integration layer
- [x] Zig compatibility tests

## Still Missing (for CRG B+)

- [ ] Property-based DOM testing
- [ ] Cross-browser compatibility matrix
- [ ] Performance regression tests
- [ ] Memory leak detection

## Run Tests

```bash
cd /var/mnt/eclipse/repos/rescript-dom-mounter && npm test
```
