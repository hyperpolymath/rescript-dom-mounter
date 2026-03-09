// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

/**
 * SafeDOM Benchmarks
 *
 * Performance benchmarks for the core SafeDOM operations:
 * - Selector validation (simple, complex, malicious)
 * - HTML sanitisation (small, medium, large, XSS payloads)
 * - Tag nesting validation (shallow, deep, wide)
 * - Full pipeline (selector + sanitise + validate combined)
 *
 * Run with: deno bench --no-check --allow-all tests/bench_test.js
 */

import {
  ProvenSelector,
  ProvenHTML,
  MountTracer,
} from "../src/Core/SafeDOMCore.res.js";

// ---------------------------------------------------------------------------
// Test data generators
// ---------------------------------------------------------------------------

/** Generate a nested HTML string with the given depth. */
function generateDeepHTML(depth) {
  let open = "";
  let close = "";
  for (let i = 0; i < depth; i++) {
    open += "<div>";
    close = "</div>" + close;
  }
  return open + "<p>leaf</p>" + close;
}

/** Generate a wide HTML string with the given number of sibling elements. */
function generateWideHTML(width) {
  let html = "<div>";
  for (let i = 0; i < width; i++) {
    html += `<span>item ${i}</span>`;
  }
  html += "</div>";
  return html;
}

/** Generate a realistic HTML page fragment of approximately the given size. */
function generateHTMLOfSize(approxBytes) {
  const unit = '<div class="card"><h3>Title</h3><p>Content paragraph with some text.</p></div>\n';
  const repeats = Math.max(1, Math.ceil(approxBytes / unit.length));
  return "<section>" + unit.repeat(repeats) + "</section>";
}

/** Generate a payload stuffed with XSS vectors. */
function generateXSSPayload(vectorCount) {
  const vectors = [
    '<script>alert(1)</script>',
    '<img src=x onerror="alert(1)">',
    '<svg onload="alert(1)"></svg>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<div onclick="alert(1)">x</div>',
    '<a href="javascript:void(0)">x</a>',
    '<template><script>alert(1)</script></template>',
    '<object data="evil.swf"></object>',
    '<embed src="evil.swf">',
    '<form action="evil.php"><input></form>',
  ];
  let payload = "";
  for (let i = 0; i < vectorCount; i++) {
    payload += vectors[i % vectors.length];
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Pre-generate test data (avoid allocation in hot loops)
// ---------------------------------------------------------------------------

const simpleSelector = "#app";
const complexSelector = "div.container > ul.list > li.item:nth-child(2n+1) > a[href]";
const maliciousSelector = '<script>alert(1)</script><div onclick="steal()">';

const smallHTML = "<p>Hello <strong>world</strong></p>";
const mediumHTML = generateHTMLOfSize(5_000);
const largeHTML = generateHTMLOfSize(100_000);

const xssPayload10 = generateXSSPayload(10);
const xssPayload50 = generateXSSPayload(50);
const xssPayload200 = generateXSSPayload(200);

const shallowNesting = "<div><p><span>text</span></p></div>";
const deepNesting = generateDeepHTML(50);
const veryDeepNesting = generateDeepHTML(200);
const wideNesting = generateWideHTML(100);
const veryWideNesting = generateWideHTML(500);

// =========================================================================
// 1. Selector Validation Benchmarks
// =========================================================================

Deno.bench("selector: simple (#app)", { group: "selector", baseline: true }, () => {
  ProvenSelector.validate(simpleSelector);
});

Deno.bench("selector: complex (descendant chain)", { group: "selector" }, () => {
  ProvenSelector.validate(complexSelector);
});

Deno.bench("selector: malicious (script injection)", { group: "selector" }, () => {
  ProvenSelector.validate(maliciousSelector);
});

Deno.bench("selector: empty string (rejected)", { group: "selector" }, () => {
  ProvenSelector.validate("");
});

Deno.bench("selector: max length (255 chars)", { group: "selector" }, () => {
  ProvenSelector.validate("#" + "a".repeat(254));
});

Deno.bench("selector: over max length (rejected)", { group: "selector" }, () => {
  ProvenSelector.validate("#" + "a".repeat(300));
});

// =========================================================================
// 2. HTML Sanitisation Benchmarks
// =========================================================================

Deno.bench("sanitise: small HTML (~50B)", { group: "sanitise", baseline: true }, () => {
  ProvenHTML.regexSanitise(smallHTML);
});

Deno.bench("sanitise: medium HTML (~5KB)", { group: "sanitise" }, () => {
  ProvenHTML.regexSanitise(mediumHTML);
});

Deno.bench("sanitise: large HTML (~100KB)", { group: "sanitise" }, () => {
  ProvenHTML.regexSanitise(largeHTML);
});

Deno.bench("sanitise: XSS payload (10 vectors)", { group: "sanitise-xss", baseline: true }, () => {
  ProvenHTML.regexSanitise(xssPayload10);
});

Deno.bench("sanitise: XSS payload (50 vectors)", { group: "sanitise-xss" }, () => {
  ProvenHTML.regexSanitise(xssPayload50);
});

Deno.bench("sanitise: XSS payload (200 vectors)", { group: "sanitise-xss" }, () => {
  ProvenHTML.regexSanitise(xssPayload200);
});

// =========================================================================
// 3. Tag Nesting Validation Benchmarks
// =========================================================================

Deno.bench("nesting: shallow (3 deep)", { group: "nesting", baseline: true }, () => {
  ProvenHTML.checkTagNesting(shallowNesting);
});

Deno.bench("nesting: deep (50 deep)", { group: "nesting" }, () => {
  ProvenHTML.checkTagNesting(deepNesting);
});

Deno.bench("nesting: very deep (200 deep)", { group: "nesting" }, () => {
  ProvenHTML.checkTagNesting(veryDeepNesting);
});

Deno.bench("nesting: wide (100 siblings)", { group: "nesting" }, () => {
  ProvenHTML.checkTagNesting(wideNesting);
});

Deno.bench("nesting: very wide (500 siblings)", { group: "nesting" }, () => {
  ProvenHTML.checkTagNesting(veryWideNesting);
});

Deno.bench("nesting: misnested (error path)", { group: "nesting" }, () => {
  ProvenHTML.checkTagNesting("<b><i></b></i>");
});

// =========================================================================
// 4. Full Pipeline Benchmarks (selector + sanitise + validate)
// =========================================================================

Deno.bench("pipeline: simple selector + small HTML", { group: "pipeline", baseline: true }, () => {
  ProvenSelector.validate(simpleSelector);
  ProvenHTML.validate(smallHTML);
});

Deno.bench("pipeline: complex selector + medium HTML", { group: "pipeline" }, () => {
  ProvenSelector.validate(complexSelector);
  ProvenHTML.validate(mediumHTML);
});

Deno.bench("pipeline: complex selector + large HTML", { group: "pipeline" }, () => {
  ProvenSelector.validate(complexSelector);
  ProvenHTML.validate(largeHTML);
});

Deno.bench("pipeline: malicious selector + XSS payload", { group: "pipeline" }, () => {
  ProvenSelector.validate(maliciousSelector);
  ProvenHTML.validate(xssPayload50);
});

Deno.bench("pipeline: full sanitise() call (not just regex)", { group: "pipeline" }, () => {
  ProvenHTML.sanitise(smallHTML);
});

Deno.bench("pipeline: full sanitise() + validate with XSS", { group: "pipeline" }, () => {
  ProvenSelector.validate(simpleSelector);
  ProvenHTML.validate(xssPayload10);
});

// =========================================================================
// 5. MountTracer Benchmarks
// =========================================================================

Deno.bench("tracer: record single entry", { group: "tracer", baseline: true }, () => {
  MountTracer.record("bench-event", "bench-detail");
});

Deno.bench("tracer: record + clear cycle", { group: "tracer" }, () => {
  MountTracer.record("bench-event", "bench-detail");
  MountTracer.clear();
});

Deno.bench("tracer: filterByPrefix on populated log", { group: "tracer" }, () => {
  MountTracer.filterByPrefix("bench");
});

// Clean up tracer after benchmarks
MountTracer.clear();
