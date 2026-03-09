; SPDX-License-Identifier: PMPL-1.0-or-later
; Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
;
; ECOSYSTEM.scm — Project ecosystem position for rescript-dom-mounter

(ecosystem
  (metadata
    (version "1.0.0")
    (last-updated "2026-03-09"))

  (project
    (name "rescript-dom-mounter")
    (purpose "Standalone highest-assurance DOM mounting library for ReScript applications, extracted from PanLL's SafeDOMCore.")
    (role "library"))

  (position-in-ecosystem
    (tier "infrastructure"))

  (related-projects
    ((name "panll") (relationship "parent") (note "SafeDOMCore was originally developed as part of PanLL's core"))
    ((name "idaptik") (relationship "potential-consumer") (note "IDApTIK game could use for safe DOM rendering"))
    ((name "developer-ecosystem/rescript-ecosystem") (relationship "sibling-standard") (note "Part of the ReScript ecosystem tooling")))

  (integration-points
    ((system "dompurify") (direction "inbound") (protocol "global-scope-ffi") (note "Optional runtime dependency for Layer 1 sanitisation"))
    ((system "trusted-types") (direction "inbound") (protocol "browser-api") (note "W3C Trusted Types for Layer 4 enforcement"))))
