<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk> -->
# TOPOLOGY.md — rescript-dom-mounter

## Purpose

Formally verified DOM mounting library for ReScript with compile-time guarantees that DOM operations cannot fail. Uses Idris2 ABI definitions and Zig FFI to provide a mathematically sound mounting layer. Eliminates runtime DOM errors through dependent type proofs.

## Module Map

```
rescript-dom-mounter/
├── src/
│   ├── abi/          # Idris2 ABI definitions (formal proofs)
│   ├── core/         # Core mounting logic (ReScript)
│   ├── Core/         # Top-level Core module
│   ├── interface/    # Public API surface
│   └── (aspects, bridges, contracts, definitions, errors)
├── ffi/
│   └── zig/          # Zig FFI implementation (C-compatible)
├── examples/         # Usage examples
└── ABI-FFI-README.md # ABI/FFI architecture documentation
```

## Data Flow

```
[ReScript component] ──► [DOM Mounter API] ──► [Idris2 ABI proofs]
                                                        │
                                               [Zig FFI layer]
                                                        │
                                               [Browser DOM operations]
```
