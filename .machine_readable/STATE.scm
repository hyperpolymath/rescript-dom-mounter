; SPDX-License-Identifier: PMPL-1.0-or-later
; Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
;
; STATE.scm — Project state checkpoint for rescript-dom-mounter

(state
  (metadata
    (project "rescript-dom-mounter")
    (version "1.0.0")
    (last-updated "2026-03-09")
    (status "active"))

  (project-context
    (name "rescript-dom-mounter")
    (purpose "Highest-assurance DOM mounting library for ReScript with 4-layer defence-in-depth: DOMPurify, regex sanitiser, structural validation, and W3C Trusted Types.")
    (completion-percentage 90))

  (position
    (phase "implementation")
    (maturity "alpha"))

  (route-to-mvp
    (milestones
      ((name "Core SafeDOMCore module") (completion 100))
      ((name "DOMPurify FFI bindings") (completion 100))
      ((name "TrustedTypes bindings") (completion 100))
      ((name "Public API (SafeDOM.res)") (completion 100))
      ((name "Test suite") (completion 100))
      ((name "Build configuration") (completion 100))
      ((name "ABI/FFI standard files") (completion 100))
      ((name "npm/deno packaging") (completion 80))
      ((name "Documentation and examples") (completion 50))))

  (blockers-and-issues)

  (critical-next-actions
    (actions
      ("Publish to npm/jsr registry"
       "Add browser integration tests"
       "Write usage examples in examples/ directory"
       "Add DOMPurify version pinning guidance"))))
