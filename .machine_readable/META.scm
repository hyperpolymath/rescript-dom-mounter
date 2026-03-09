; SPDX-License-Identifier: PMPL-1.0-or-later
; Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
;
; META.scm — Project meta-level information for rescript-dom-mounter

(meta
  (metadata
    (version "1.0.0")
    (last-updated "2026-03-09"))

  (project-info
    (type "library")
    (languages ("rescript"))
    (license "PMPL-1.0-or-later")
    (author "Jonathan D.A. Jewell (hyperpolymath)"))

  (architecture-decisions
    ((id "ADR-001")
     (title "Four-layer defence-in-depth for DOM XSS prevention")
     (status "accepted")
     (date "2026-03-09")
     (rationale "No single sanitisation layer is sufficient. DOMPurify handles mXSS, regex catches known patterns, structural validation catches misnesting, and Trusted Types provides browser-engine-level enforcement."))
    ((id "ADR-002")
     (title "DOMParser-based mounting as alternative to innerHTML")
     (status "accepted")
     (date "2026-03-09")
     (rationale "DOMParser does not execute scripts in parsed content, making it the safest mounting strategy for untrusted HTML."))
    ((id "ADR-003")
     (title "Graceful degradation when DOMPurify/TrustedTypes unavailable")
     (status "accepted")
     (date "2026-03-09")
     (rationale "Library must work in all environments including SSR, tests, and older browsers. Each layer degrades independently.")))

  (development-practices
    (build-tool "deno")
    (ci-platform "github-actions")
    (package-manager "deno"))

  (design-rationale
    (core-principle "Defence-in-depth: every layer assumes all other layers have bugs.")
    (audit-trail "MountTracer provides monotonic-timestamped append-only audit log for observability.")
    (type-safety "ValidSelector and ValidHTML opaque wrappers prevent accidental use of unvalidated strings.")))
