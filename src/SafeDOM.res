// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// SafeDOM.res — Public API for rescript-dom-mounter.
//
// Re-exports the core modules and convenience functions for consumers.
// Import this module for the full API surface:
//
//   open SafeDOM
//   let result = mountString("#app", "<p>Hello</p>")

/// Core DOM mounting with 4-layer defence-in-depth.
module Core = SafeDOMCore

/// DOMPurify FFI bindings (cure53 sanitiser).
module Purify = DOMPurify

/// W3C Trusted Types API bindings.
module TrustedTypes = TrustedTypes

// -- Re-export core types --

/// Validated CSS selector (opaque wrapper).
type validSelector = SafeDOMCore.validSelector

/// Validated HTML content (opaque wrapper).
type validHtml = SafeDOMCore.validHtml

/// Result of a mount operation.
type mountResult = SafeDOMCore.mountResult

/// Specification for batch mount operations.
type mountSpec = SafeDOMCore.mountSpec

/// Sanitisation method used during validation.
type sanitisationMethod = SafeDOMCore.sanitisationMethod

/// Safety layer diagnostics report.
type safetyReport = SafeDOMCore.safetyReport

// -- Re-export key functions --

/// Initialise the Trusted Types policy. Call once at app startup.
let initTrustedTypes = SafeDOMCore.initTrustedTypes

/// Mount validated HTML into a validated selector's element.
let mount = SafeDOMCore.mount

/// Mount using DOMParser (no innerHTML sink).
let mountParsed = SafeDOMCore.mountParsed

/// Convenience: validate selector + HTML, then mount via innerHTML.
let mountString = SafeDOMCore.mountString

/// Convenience: validate and mount via DOMParser.
let mountStringParsed = SafeDOMCore.mountStringParsed

/// Mount with success/error callbacks.
let mountSafe = SafeDOMCore.mountSafe

/// Atomically mount to multiple selectors.
let mountBatch = SafeDOMCore.mountBatch

/// Execute callback when DOM is ready.
let onDOMReady = SafeDOMCore.onDOMReady

/// Mount HTML once the DOM is ready.
let mountWhenReady = SafeDOMCore.mountWhenReady

/// Clear content from a mount point.
let unmount = SafeDOMCore.unmount

/// Atomic content swap (validate before unmounting old content).
let remount = SafeDOMCore.remount

/// Mount with CSP nonce applied to style tags.
let mountWithNonce = SafeDOMCore.mountWithNonce

/// Generate a report of all active safety layers.
let safetyDiagnostics = SafeDOMCore.safetyDiagnostics
