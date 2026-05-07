from __future__ import annotations

import json
from typing import Any


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=1100, initial-scale=1">
<title>__TITLE__</title>
<style>
:root {
  --paper: #f4f1ea;
  --paper-dark: #ece7dc;
  --ink: #1a1814;
  --ink-soft: #4a423a;
  --rule: rgba(26, 24, 20, 0.18);
  --rule-strong: rgba(26, 24, 20, 0.55);
  --marg: #8c857c;
  --accent: #8a1a0e;
  --crit: #8a1a0e;
  --high: #b8351e;
  --med: #b97817;
  --low: #5a6f3d;
  --info: #4a5568;
  --origin-customer: #8a1a0e;
  --origin-system: #b97817;
  --origin-app: #4a5568;
  --origin-instance: #8c857c;
}

* { box-sizing: border-box; }

html, body {
  margin: 0;
  padding: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-size: 15px;
  line-height: 1.5;
  font-feature-settings: "tnum" 1, "lnum" 1, "kern" 1, "liga" 1;
  -webkit-font-smoothing: antialiased;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 1;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 0.04 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>");
  opacity: 0.7;
  mix-blend-mode: multiply;
}

.page {
  max-width: 1080px;
  margin: 0 auto;
  padding: 80px 60px 120px 180px;
  position: relative;
  z-index: 2;
}

.masthead {
  border-bottom: 2px solid var(--ink);
  padding-bottom: 28px;
  margin-bottom: 64px;
  position: relative;
}

.masthead::before {
  content: "";
  position: absolute;
  inset: auto 0 -6px 0;
  border-bottom: 1px solid var(--ink);
}

.masthead .eyebrow {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--marg);
  margin-bottom: 18px;
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.masthead h1 {
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-weight: 400;
  font-size: 84px;
  letter-spacing: -0.025em;
  line-height: 0.95;
  margin: 0;
}

.masthead h1 em {
  font-style: italic;
  color: var(--accent);
}

.masthead .subtitle {
  margin-top: 26px;
  font-size: 17px;
  font-style: italic;
  color: var(--ink-soft);
  max-width: 580px;
}

.masthead .meta {
  margin-top: 36px;
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12px;
}

.meta .field .label {
  display: block;
  text-transform: uppercase;
  letter-spacing: 0.18em;
  color: var(--marg);
  font-size: 10px;
  margin-bottom: 4px;
}

.meta .field .value {
  color: var(--ink);
  font-size: 13px;
  word-break: break-all;
}

.section {
  margin: 72px 0;
  position: relative;
}

.section .label {
  position: absolute;
  left: -120px;
  top: 4px;
  width: 100px;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--marg);
  text-align: right;
  line-height: 1.4;
}

.section .label .num {
  display: block;
  font-size: 28px;
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  letter-spacing: 0;
  font-style: italic;
  color: var(--ink);
}

.section h2 {
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-weight: 400;
  font-size: 36px;
  letter-spacing: -0.01em;
  margin: 0 0 8px 0;
  line-height: 1.1;
}

.section .lede {
  font-style: italic;
  color: var(--ink-soft);
  margin: 0 0 32px 0;
  max-width: 620px;
  font-size: 15.5px;
}

.rule {
  border: 0;
  border-top: 1px solid var(--ink);
  margin: 28px 0;
}

.hairline {
  border: 0;
  border-top: 1px solid var(--rule);
  margin: 16px 0;
}

table.spec {
  width: 100%;
  border-collapse: collapse;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12.5px;
}

table.spec th, table.spec td {
  text-align: left;
  padding: 8px 14px 8px 0;
  border-bottom: 1px solid var(--rule);
  vertical-align: top;
}

table.spec th {
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-size: 10.5px;
  color: var(--marg);
  border-bottom: 1px solid var(--ink);
  padding-bottom: 6px;
}

table.spec tr:hover td {
  background: var(--paper-dark);
}

table.spec td.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}

.warn {
  color: var(--high);
}

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 24px;
  margin: 28px 0 12px 0;
  padding: 14px 0;
  border-top: 1px solid var(--ink);
  border-bottom: 1px solid var(--rule);
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.legend .filter {
  cursor: pointer;
  user-select: none;
  display: flex;
  align-items: baseline;
  gap: 8px;
  color: var(--ink);
  border-bottom: 2px solid transparent;
  padding-bottom: 4px;
  transition: opacity 0.12s;
}

.legend .filter[data-active="false"] {
  opacity: 0.35;
}

.legend .filter .swatch {
  width: 12px;
  height: 12px;
  display: inline-block;
  border: 1px solid var(--ink);
}

.legend .filter[data-sev="CRITICAL"] .swatch { background: var(--crit); }
.legend .filter[data-sev="HIGH"] .swatch { background: var(--high); }
.legend .filter[data-sev="MEDIUM"] .swatch { background: var(--med); }
.legend .filter[data-sev="LOW"] .swatch { background: var(--low); }
.legend .filter[data-sev="INFO"] .swatch { background: var(--info); }

.legend .count {
  color: var(--marg);
}

.empty {
  font-style: italic;
  color: var(--marg);
  padding: 28px 0;
}

.findings {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.finding {
  border-top: 1px solid var(--rule);
  padding: 32px 0 28px 0;
  display: grid;
  grid-template-columns: 1fr 140px;
  gap: 28px;
  position: relative;
}

.finding[data-hidden="true"] {
  display: none;
}

.finding:first-of-type {
  border-top: 1px solid var(--ink);
}

.finding .index {
  position: absolute;
  left: -120px;
  top: 36px;
  width: 100px;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  letter-spacing: 0.2em;
  color: var(--marg);
  text-align: right;
  text-transform: uppercase;
}

.finding h3 {
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-weight: 400;
  font-size: 22px;
  margin: 0 0 6px 0;
  line-height: 1.2;
}

.finding .rule-meta {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--marg);
  margin-bottom: 18px;
}

.finding .rule-meta .sep {
  margin: 0 14px;
  color: var(--rule-strong);
}

.finding .summary {
  font-size: 14.5px;
  margin: 0 0 22px 0;
  max-width: 620px;
  color: var(--ink-soft);
}

.finding .stamp {
  justify-self: end;
  align-self: start;
  border: 2px solid currentColor;
  padding: 6px 12px 5px 12px;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  transform: rotate(-1.2deg);
  position: relative;
}

.finding .stamp::after {
  content: "";
  position: absolute;
  inset: -3px;
  border: 2px solid currentColor;
  opacity: 0.35;
  pointer-events: none;
}

.finding[data-sev="CRITICAL"] .stamp { color: var(--crit); }
.finding[data-sev="HIGH"] .stamp { color: var(--high); }
.finding[data-sev="MEDIUM"] .stamp { color: var(--med); }
.finding[data-sev="LOW"] .stamp { color: var(--low); }
.finding[data-sev="INFO"] .stamp { color: var(--info); }

.evidence {
  margin: 0 0 18px 0;
  padding: 0;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12.5px;
}

.evidence .block-label {
  font-size: 10.5px;
  letter-spacing: 0.18em;
  color: var(--marg);
  text-transform: uppercase;
  margin-bottom: 8px;
}

.evidence .row {
  display: flex;
  align-items: baseline;
  border-bottom: 1px dotted rgba(26, 24, 20, 0.35);
  padding: 4px 0;
}

.evidence .key {
  background: var(--paper);
  padding-right: 6px;
  color: var(--ink-soft);
}

.evidence .val {
  margin-left: auto;
  background: var(--paper);
  padding-left: 6px;
  color: var(--ink);
  text-align: right;
  word-break: break-all;
}

.remediation {
  background: rgba(184, 53, 30, 0.05);
  border-left: 3px solid var(--accent);
  padding: 12px 16px;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12.5px;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
}

.remediation .block-label {
  font-size: 10.5px;
  letter-spacing: 0.18em;
  color: var(--accent);
  text-transform: uppercase;
  margin-bottom: 8px;
  font-weight: 700;
}

.atlas {
  margin-top: 8px;
}

.atlas-controls {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  color: var(--marg);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 12px;
}

.atlas-svg {
  width: 100%;
  height: 540px;
  display: block;
  background: linear-gradient(to bottom, var(--paper) 0%, var(--paper-dark) 100%);
  border: 1px solid var(--ink);
}

.atlas-svg .band-label {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 10px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  fill: var(--marg);
}

.atlas-svg .band-rule {
  stroke: var(--rule);
  stroke-width: 1;
  stroke-dasharray: 2 4;
}

.atlas-svg .edge {
  fill: none;
  stroke: rgba(26, 24, 20, 0.18);
  stroke-width: 1;
}

.atlas-svg .edge.highlight {
  stroke: var(--accent);
  stroke-width: 2;
  opacity: 1;
}

.atlas-svg .node {
  cursor: pointer;
}

.atlas-svg .node circle {
  stroke: var(--ink);
  stroke-width: 1;
}

.atlas-svg .node.dim {
  opacity: 0.18;
}

.atlas-svg .node.highlight circle {
  stroke-width: 2;
  fill: var(--accent) !important;
}

.atlas-svg .node text {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 9.5px;
  fill: var(--ink);
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.12s;
}

.atlas-svg .node:hover text,
.atlas-svg .node.highlight text {
  opacity: 1;
}

.atlas-side {
  margin-top: 18px;
  padding: 18px 0;
  border-top: 1px solid var(--ink);
  border-bottom: 1px solid var(--rule);
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12.5px;
  min-height: 60px;
}

.atlas-side .empty-state {
  font-style: italic;
  color: var(--marg);
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-size: 14px;
}

.atlas-side h4 {
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-weight: 400;
  font-size: 19px;
  margin: 0 0 10px 0;
}

.atlas-side .h4-meta {
  font-size: 10.5px;
  letter-spacing: 0.18em;
  color: var(--marg);
  text-transform: uppercase;
  margin-bottom: 6px;
}

.atlas-side .neighbor-list {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 24px;
  margin-top: 10px;
}

.atlas-side .neighbor {
  border-bottom: 1px dotted var(--rule-strong);
  padding: 4px 0;
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.atlas-side .neighbor .arr {
  color: var(--marg);
  margin: 0 8px;
}

.path-card {
  border-top: 1px solid var(--rule);
  padding: 22px 0;
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 24px;
}

.path-card:first-of-type {
  border-top: 1px solid var(--ink);
}

.path-card .who {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 13px;
  letter-spacing: 0.05em;
}

.path-card .who .role-tag {
  display: block;
  font-size: 10px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--marg);
  margin-bottom: 4px;
}

.path-card .what {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12.5px;
  display: flex;
  flex-wrap: wrap;
  gap: 4px 8px;
  align-items: center;
}

.path-card .hop {
  display: inline-block;
}

.path-card .arr {
  color: var(--marg);
}

.path-card .role-name {
  border-bottom: 1px solid currentColor;
}

.path-card .priv-tag {
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--accent);
  font-weight: 600;
}

.rule-group {
  border-top: 1px solid var(--rule);
  padding: 24px 0;
}

.rule-group:first-of-type {
  border-top: 1px solid var(--ink);
}

.rule-group-head {
  display: grid;
  grid-template-columns: 1fr 130px 80px;
  gap: 24px;
  align-items: baseline;
  cursor: pointer;
  user-select: none;
}

.rule-group-head h3 {
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-weight: 400;
  font-size: 22px;
  margin: 0 0 4px 0;
  line-height: 1.2;
}

.rule-group-head .rule-meta {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--marg);
}

.rule-group-head .stamp {
  justify-self: end;
  align-self: start;
}

.rule-group-head .count {
  text-align: right;
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-style: italic;
  font-size: 28px;
  color: var(--ink);
  font-feature-settings: "tnum" 1, "lnum" 1;
}

.rule-group-head .toggle {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 10px;
  letter-spacing: 0.18em;
  color: var(--marg);
  text-transform: uppercase;
  margin-top: 6px;
}

.audit-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}

.audit-badge {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 10px;
  letter-spacing: 0.08em;
  border: 1px solid currentColor;
  padding: 1px 6px;
  white-space: nowrap;
}

.policy-badge {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 9px;
  letter-spacing: 0.08em;
  border: 1px solid currentColor;
  padding: 0px 4px;
  margin-left: 4px;
  white-space: nowrap;
}
.policy-badge.masking { color: #8a1a0e; }
.policy-badge.row-access { color: #b8351e; }
.policy-badge.aggregation { color: #b97817; }
.policy-badge.tag { color: #5a6f3d; }

.audit-badge[data-pack="cis"] { color: #4a5568; }
.audit-badge[data-pack="soc2"] { color: #5a6f3d; }
.audit-badge[data-pack="sox"] { color: #b97817; }
.audit-badge[data-pack="hipaa"] { color: #4a5568; }
.audit-badge[data-pack="unc5537"] { color: #b8351e; }

.rule-group .summary {
  font-size: 14.5px;
  margin: 12px 0 16px 0;
  max-width: 720px;
  color: var(--ink-soft);
}

.rule-group-children {
  display: none;
  margin-top: 18px;
  padding-left: 18px;
  border-left: 2px solid var(--rule);
}

.rule-group[data-expanded="true"] .rule-group-children {
  display: block;
}

.rule-group-children .child {
  padding: 12px 0;
  border-bottom: 1px dotted var(--rule-strong);
}

.rule-group-children .child:last-child {
  border-bottom: 0;
}

.rule-group-children .child .title {
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-size: 16px;
  margin-bottom: 4px;
}

.rule-group-children .child .ev {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11.5px;
  color: var(--ink-soft);
}

.census {
  margin-top: 12px;
}

.census-controls {
  display: flex;
  gap: 16px;
  align-items: baseline;
  margin-bottom: 12px;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12px;
}

.census-controls input[type="text"] {
  flex: 1;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 13px;
  background: var(--paper);
  border: 1px solid var(--ink);
  padding: 6px 10px;
  color: var(--ink);
  border-radius: 0;
  outline: none;
}

.census-controls input:focus {
  background: var(--paper-dark);
}

.census-controls .origin-select {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.census-controls .origin-toggle {
  cursor: pointer;
  border: 1px solid var(--ink);
  padding: 4px 8px;
  font-size: 10.5px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  user-select: none;
}

.census-controls .origin-toggle[data-active="false"] {
  opacity: 0.3;
}

table.census-table {
  width: 100%;
  border-collapse: collapse;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12px;
}

table.census-table th {
  text-align: left;
  padding: 8px 14px 6px 0;
  border-bottom: 1px solid var(--ink);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-size: 10px;
  color: var(--marg);
  cursor: pointer;
  user-select: none;
}

table.census-table th .sort-arrow {
  color: var(--accent);
  margin-left: 4px;
}

table.census-table td {
  padding: 5px 14px 5px 0;
  border-bottom: 1px solid var(--rule);
  vertical-align: top;
}

table.census-table td.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}

table.census-table tr:hover td {
  background: var(--paper-dark);
}

table.census-table tr[data-hidden="true"] {
  display: none;
}

.census-stats {
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  color: var(--marg);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 8px;
}

footer {
  margin-top: 96px;
  padding-top: 24px;
  border-top: 2px solid var(--ink);
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 11px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--marg);
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 20px;
}

footer .colophon {
  font-style: italic;
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  font-size: 13px;
  letter-spacing: 0;
  text-transform: none;
  color: var(--ink-soft);
  max-width: 460px;
}

.origin-pill {
  display: inline-block;
  font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  border: 1px solid currentColor;
  padding: 1px 6px;
  margin-right: 6px;
}

.origin-pill[data-origin="customer"] { color: var(--origin-customer); }
.origin-pill[data-origin="system"] { color: var(--origin-system); }
.origin-pill[data-origin="snowflake-application"] { color: var(--origin-app); }
.origin-pill[data-origin="snowflake-instance"] { color: var(--origin-instance); }
.origin-pill[data-origin="snowflake-shipped"] { color: var(--origin-instance); }

@media (max-width: 1024px) {
  .page {
    padding: 40px 24px 80px 24px;
  }
  .section .label, .finding .index {
    position: static;
    width: auto;
    text-align: left;
    margin-bottom: 8px;
  }
  .finding {
    grid-template-columns: 1fr;
  }
  .finding .stamp {
    justify-self: start;
  }
  .masthead h1 { font-size: 56px; }
  .masthead .meta { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>
<body>
<div class="page">

<header class="masthead">
  <div class="eyebrow">
    <span>Specification &mdash; Snowflake Access Audit</span>
    <span id="snapshot-time"></span>
  </div>
  <h1>&Uuml;ber<em>blick</em></h1>
  <p class="subtitle">A read-only field report on the role &amp; access topology of a single Snowflake account, captured at a single moment.</p>
  <div class="meta">
    <div class="field"><span class="label">Account</span><span class="value" id="m-account"></span></div>
    <div class="field"><span class="label">Captured</span><span class="value" id="m-captured"></span></div>
    <div class="field"><span class="label">Snapshot Role</span><span class="value" id="m-role"></span></div>
    <div class="field"><span class="label">Lookback</span><span class="value" id="m-lookback"></span></div>
  </div>
</header>

<section class="section">
  <div class="label"><span class="num">01</span>Snapshot &middot; Inventory</div>
  <h2>What was captured.</h2>
  <p class="lede">Eleven views from <code>SNOWFLAKE.ACCOUNT_USAGE</code>, plus two derived layers: role-origin classification and a cycle-safe role hierarchy closure. Per-view freshness is reported below; documented per-view max lag from Snowflake's docs is shown alongside.</p>
  <table class="spec" id="view-table">
    <thead><tr><th>View</th><th class="num">Rows</th><th class="num">Latest Record</th><th class="num">Max Lag (Doc)</th><th>Status</th></tr></thead>
    <tbody></tbody>
  </table>

  <hr class="hairline">

  <table class="spec" id="origin-table" style="max-width: 480px; margin-top: 24px;">
    <thead><tr><th>Role Origin</th><th class="num">Roles</th></tr></thead>
    <tbody></tbody>
  </table>
</section>

<section class="section">
  <div class="label"><span class="num">02</span>Findings</div>
  <h2>Where the account is exposed.</h2>
  <p class="lede">Each finding is the output of a deterministic rule run against the snapshot. Severity is intrinsic to the rule, not to your specific account &mdash; a HIGH may be benign in context. Click a severity below to filter.</p>
  <div class="legend" id="severity-legend"></div>
  <div class="findings" id="findings-list"></div>
</section>

<section class="section">
  <div class="label"><span class="num">03</span>Privileged &middot; Reach</div>
  <h2>Who can become an admin.</h2>
  <p class="lede">For each user, the set of administrative roles they can activate &mdash; directly granted or via role inheritance. Shorter reach is safer; depth&nbsp;0 means the user holds the admin role directly.</p>
  <div id="admin-reach"></div>
</section>

<section class="section">
  <div class="label"><span class="num">04</span>Direct &middot; User Grants</div>
  <h2>Privileges granted directly to users.</h2>
  <p class="lede">Snowflake creates per-user objects (e.g. <code>USER$&lt;name&gt;</code>) with grants pointing at the user, not at a role. They&rsquo;re typically benign but worth seeing once.</p>
  <div id="direct-grants"></div>
</section>

<section class="section" id="diff-section">
  <div class="label"><span class="num">03b</span>Snapshot &middot; Diff</div>
  <h2>What changed since last snapshot.</h2>
  <p class="lede">If a previous snapshot for this account exists in <code>~/.uberblick/history</code>, this section diffs the current snapshot against the most recent older one. Privilege creep, terminations, MFA toggles, and grant churn surface here directly.</p>
  <div id="diff-content"></div>
</section>

<section class="section">
  <div class="label"><span class="num">04</span>Path &middot; Finder</div>
  <h2>Who can reach what.</h2>
  <p class="lede">Two filters: leave both blank to see nothing. Type a user to see every object they can reach, or type an object name to see every user who can reach it. Type both to see the specific paths between them. Search is substring-match across user names, role names, database/schema/table names. Paths trace the role inheritance chain.</p>
  <div class="impersonation">
    <div class="census-controls">
      <input type="text" id="path-user" placeholder="From USER (optional)..." autocomplete="off" style="flex: 1;" />
      <input type="text" id="path-object" placeholder="To OBJECT (DB.SCHEMA.TABLE or partial)..." autocomplete="off" style="flex: 1;" />
      <span class="census-stats" id="path-status"></span>
    </div>
    <div id="path-content"></div>
  </div>
</section>

<section class="section">
  <div class="label"><span class="num">04a</span>Role &middot; Impersonation</div>
  <h2>What does each role actually see?</h2>
  <p class="lede">Pick a role from the dropdown to step inside it &mdash; without granting it to yourself. You will see every role it inherits, every object grant it (or its inherited roles) carries, and every user who holds it. This is the answer to "if I were CUSTOMER_ANALYST, what would my Snowflake look like?"</p>
  <div class="impersonation">
    <div class="census-controls">
      <input type="text" id="impersonate-search" placeholder="Search for a role to impersonate..." autocomplete="off" />
      <span class="census-stats" id="impersonate-status"></span>
    </div>
    <div id="impersonate-content"></div>
  </div>
</section>

<section class="section">
  <div class="label"><span class="num">04b</span>Secondary &middot; Roles</div>
  <h2>What happens with USE SECONDARY ROLES ALL.</h2>
  <p class="lede">When a user activates all granted roles simultaneously, the union of privileges can exceed any single role. This is where dangerous combinations emerge &mdash; PII read in one role plus export privilege in another lets the user exfiltrate, even though neither role alone would. Below: per-user breakdown showing which role contributes what, with the unique privileges each role brings (privileges <em>only</em> available through that role).</p>
  <div id="secondary-content"></div>
</section>

<section class="section">
  <div class="label"><span class="num">04c</span>User &middot; Blast Radius</div>
  <h2>If this account were compromised, what would attackers reach?</h2>
  <p class="lede">For the highest-reach users in this snapshot (those reaching admin roles or many roles transitively), this view enumerates <em>every</em> object grant they can exercise across <em>every</em> role they hold. This is the full reachable surface &mdash; the answer to "what is the worst case if this user&rsquo;s credentials leak?". Pick a user; the table shows object, privilege, the direct role they hold, and the inherited role that actually carries the grant.</p>
  <div class="impersonation">
    <div class="census-controls">
      <input type="text" id="blast-search" placeholder="Search a high-reach user..." autocomplete="off" />
      <span class="census-stats" id="blast-status"></span>
    </div>
    <div id="blast-content"></div>
  </div>
</section>

<section class="section">
  <div class="label"><span class="num">05a</span>User &middot; Census</div>
  <h2>Every user, with reach.</h2>
  <p class="lede">Every user with their direct role count, transitive reachable role count, max path depth, and named binary flags. Sort by <code>reaches_admin</code> first to see who can become privileged. Click a row to expand the user&rsquo;s direct role list.</p>
  <div class="census">
    <div class="census-controls">
      <input type="text" id="user-search" placeholder="Search users by name (regex ok)..." />
      <div class="origin-select" id="user-flags"></div>
    </div>
    <div class="census-stats" id="user-stats"></div>
    <table class="census-table" id="user-table">
      <thead><tr>
        <th data-sort="name">Name</th>
        <th data-sort="type">Type</th>
        <th data-sort="has_mfa">MFA</th>
        <th data-sort="default_role">Default role</th>
        <th data-sort="direct_role_count" class="num">Direct</th>
        <th data-sort="reachable_role_count" class="num">Reachable</th>
        <th data-sort="max_path_depth" class="num">Depth</th>
        <th data-sort="flags">Flags</th>
        <th data-sort="last_login">Last login</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>
</section>

<section class="section">
  <div class="label"><span class="num">05b</span>Role &middot; Census</div>
  <h2>Every role, sortable.</h2>
  <p class="lede">Tabular view of every role with edge counts and direct user grants. Search by name, toggle origin filters, click any column header to sort. Designed to scale: works the same with 5 roles or 5,000.</p>
  <div class="census">
    <div class="census-controls">
      <input type="text" id="census-search" placeholder="Search roles by name (regex ok)..." />
      <div class="origin-select" id="census-origin"></div>
    </div>
    <div class="census-stats" id="census-stats"></div>
    <table class="census-table" id="census-table">
      <thead><tr>
        <th data-sort="name">Name</th>
        <th data-sort="origin">Origin</th>
        <th data-sort="role_type">Type</th>
        <th data-sort="owner">Owner</th>
        <th data-sort="inherits_count" class="num">Inherits</th>
        <th data-sort="inherited_by_count" class="num">Inherited by</th>
        <th data-sort="user_count" class="num">Users</th>
        <th data-sort="max_reach_depth" class="num">Max reach</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>
</section>

<section class="section">
  <div class="label"><span class="num">06</span>Role &middot; Atlas</div>
  <h2>The shape of the role graph.</h2>
  <p class="lede">Roles are stratified by origin: customer-created at the bottom, then Snowflake&rsquo;s system roles, instance roles, and application roles above. Edges are USAGE inheritance grants. Click any node to highlight its 1-hop neighborhood.</p>
  <div class="atlas-controls" id="atlas-stats"></div>
  <div class="atlas">
    <svg class="atlas-svg" id="atlas-svg" viewBox="0 0 1080 540" preserveAspectRatio="xMidYMid meet"></svg>
    <div class="atlas-side" id="atlas-side"><span class="empty-state">Select a role to inspect.</span></div>
  </div>
</section>

<footer>
  <div class="colophon">&Uuml;berblick is read-only by design. Nothing in this report touches your data; everything is metadata from <code>SNOWFLAKE.ACCOUNT_USAGE</code>. Snapshot &amp; report kept local; no telemetry.</div>
  <div id="footer-build"></div>
</footer>

</div>

<script id="report-data" type="application/json">__DATA__</script>
<script>
"use strict";
const DATA = JSON.parse(document.getElementById("report-data").textContent);

function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === "class") e.className = attrs[k];
    else if (k === "html") e.innerHTML = attrs[k];
    else if (k.startsWith("data-")) e.setAttribute(k, attrs[k]);
    else e[k] = attrs[k];
  }
  if (children) for (const c of children) {
    if (c == null) continue;
    if (typeof c === "string") e.appendChild(document.createTextNode(c));
    else e.appendChild(c);
  }
  return e;
}

function fmt(n) {
  if (n == null) return "—";
  return n.toLocaleString();
}

function escHTML(s) {
  if (s == null) return "";
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[c]));
}

document.getElementById("m-account").textContent = DATA.snapshot.account || "—";
document.getElementById("m-captured").textContent = DATA.snapshot.snapshot_at || "—";
document.getElementById("m-role").textContent = (DATA.snapshot.user || "?") + " @ " + (DATA.snapshot.role || "?");
document.getElementById("m-lookback").textContent = (DATA.snapshot.lookback_days || 30) + " days";
document.getElementById("snapshot-time").textContent = "Captured " + (DATA.snapshot.snapshot_at || "");
document.getElementById("footer-build").textContent =
  "Snapshot " + (DATA.snapshot.account || "?") + " • Generated " + new Date().toISOString();

(function renderViews() {
  const tbody = document.querySelector("#view-table tbody");
  for (const v of DATA.views) {
    const lagWarn = v.documented_max_lag_minutes != null
      && v.minutes_since_latest_record != null
      && v.minutes_since_latest_record > v.documented_max_lag_minutes * 4;
    const row = el("tr", null, [
      el("td", null, [v.name]),
      el("td", { class: "num" }, [fmt(v.rows)]),
      el("td", { class: "num" + (lagWarn ? " warn" : "") }, [
        v.minutes_since_latest_record == null ? "—" : fmt(v.minutes_since_latest_record) + " m"
      ]),
      el("td", { class: "num" }, [
        v.documented_max_lag_minutes == null ? "—" : fmt(v.documented_max_lag_minutes) + " m"
      ]),
      el("td", null, [v.error ? "✗ " + v.error : "✓ ok"]),
    ]);
    tbody.appendChild(row);
  }
})();

(function renderOrigin() {
  const tbody = document.querySelector("#origin-table tbody");
  for (const o of DATA.role_origins) {
    const row = el("tr", null, [
      el("td", null, [
        el("span", { class: "origin-pill", "data-origin": o.origin }, [o.origin])
      ]),
      el("td", { class: "num" }, [fmt(o.count)]),
    ]);
    tbody.appendChild(row);
  }
})();

(function renderFindings() {
  const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const counts = {};
  for (const s of SEVERITIES) counts[s] = 0;
  for (const f of DATA.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const legend = document.getElementById("severity-legend");
  legend.innerHTML = "";
  if (DATA.findings.length === 0) {
    const list = document.getElementById("findings-list");
    list.appendChild(el("div", { class: "empty" }, ["No findings produced."]));
    legend.style.display = "none";
    return;
  }

  const filterState = {};
  for (const s of SEVERITIES) filterState[s] = true;
  for (const s of SEVERITIES) {
    const f = el("div", {
      class: "filter", "data-sev": s, "data-active": "true",
    }, [
      el("span", { class: "swatch" }, []),
      el("span", null, [s]),
      el("span", { class: "count" }, ["(" + counts[s] + ")"]),
    ]);
    f.addEventListener("click", () => {
      filterState[s] = !filterState[s];
      f.setAttribute("data-active", filterState[s] ? "true" : "false");
      applyFilter();
    });
    legend.appendChild(f);
  }

  const groups = new Map();
  for (const finding of DATA.findings) {
    if (!groups.has(finding.rule_id)) groups.set(finding.rule_id, []);
    groups.get(finding.rule_id).push(finding);
  }
  const groupList = Array.from(groups.entries()).sort((a, b) => {
    const ra = SEVERITIES.indexOf(a[1][0].severity);
    const rb = SEVERITIES.indexOf(b[1][0].severity);
    if (ra !== rb) return ra - rb;
    return b[1].length - a[1].length;
  });

  const list = document.getElementById("findings-list");
  list.innerHTML = "";
  let gi = 0;
  for (const [rule_id, items] of groupList) {
    gi += 1;
    const sample = items[0];
    const num = String(gi).padStart(2, "0");
    const group = el("div", {
      class: "rule-group",
      "data-sev": sample.severity,
      "data-rule": rule_id,
      "data-expanded": "false",
    });
    const head = el("div", { class: "rule-group-head" });
    const titleColumn = el("div", null);
    titleColumn.appendChild(el("h3", null, [
      sample.title + (items.length > 1 ? " (+ " + (items.length - 1) + " more)" : "")
    ]));
    titleColumn.appendChild(el("div", { class: "rule-meta" }, [
      "§ " + num + "  •  Rule " + rule_id + "  •  " + sample.category
    ]));
    if (sample.audit_packs && sample.audit_packs.length) {
      const badges = el("div", { class: "audit-badges" });
      for (const ap of sample.audit_packs) {
        badges.appendChild(el("span", {
          class: "audit-badge",
          "data-pack": ap.pack,
          title: ap.pack.toUpperCase() + ": " + ap.control,
        }, [ap.pack.toUpperCase() + " · " + ap.control]));
      }
      titleColumn.appendChild(badges);
    }
    head.appendChild(titleColumn);

    const right = el("div", null, [
      el("div", { class: "count" }, [String(items.length)]),
      el("div", { class: "toggle" }, [items.length === 1 ? "open" : "expand all"]),
    ]);
    head.appendChild(right);

    head.appendChild(el("div", { class: "stamp" }, [sample.severity]));
    group.appendChild(head);

    if (sample.summary) {
      group.appendChild(el("p", { class: "summary" }, [sample.summary]));
    }

    const children = el("div", { class: "rule-group-children" });
    for (const finding of items) {
      const child = el("div", { class: "child" });
      child.appendChild(el("div", { class: "title" }, [finding.title]));
      if (finding.evidence && Object.keys(finding.evidence).length > 0) {
        const evRow = el("div", { class: "ev" });
        const parts = [];
        for (const k in finding.evidence) {
          const v = finding.evidence[k];
          const vStr = (v == null) ? "—" : (typeof v === "object") ? JSON.stringify(v) : String(v);
          parts.push(k + " = " + vStr);
        }
        evRow.textContent = parts.join("  •  ");
        child.appendChild(evRow);
      }
      if (finding.remediation && items.length === 1) {
        const r = el("div", { class: "remediation", style: "margin-top: 10px;" });
        r.appendChild(el("div", { class: "block-label" }, ["Remediation"]));
        r.appendChild(document.createTextNode(finding.remediation));
        child.appendChild(r);
      }
      children.appendChild(child);
    }
    group.appendChild(children);

    head.addEventListener("click", () => {
      const cur = group.getAttribute("data-expanded") === "true";
      group.setAttribute("data-expanded", cur ? "false" : "true");
      const tg = group.querySelector(".toggle");
      if (tg) tg.textContent = cur ? (items.length === 1 ? "open" : "expand all") : "collapse";
    });

    if (items.length === 1) {
      group.setAttribute("data-expanded", "true");
      const tg = group.querySelector(".toggle");
      if (tg) tg.textContent = "collapse";
    }

    list.appendChild(group);
  }

  function applyFilter() {
    const groups = list.querySelectorAll(".rule-group");
    groups.forEach(g => {
      const sev = g.getAttribute("data-sev");
      g.setAttribute("data-hidden", filterState[sev] ? "false" : "true");
      g.style.display = filterState[sev] ? "" : "none";
    });
  }
})();

(function renderAdminReach() {
  const root = document.getElementById("admin-reach");
  root.innerHTML = "";
  if (!DATA.admin_reach || DATA.admin_reach.length === 0) {
    root.appendChild(el("div", { class: "empty" }, ["No users reach administrative roles."]));
    return;
  }
  const grouped = {};
  for (const r of DATA.admin_reach) {
    if (!grouped[r.user]) grouped[r.user] = [];
    grouped[r.user].push(r);
  }
  for (const user in grouped) {
    const card = el("div", { class: "path-card" });
    card.appendChild(el("div", { class: "who" }, [
      el("span", { class: "role-tag" }, ["User"]),
      user,
    ]));
    const what = el("div");
    for (const r of grouped[user]) {
      const row = el("div", { class: "what", style: "margin-bottom: 8px;" });
      row.appendChild(el("span", { class: "priv-tag" }, ["depth " + r.shortest_depth]));
      row.appendChild(el("span", { class: "arr" }, ["→"]));
      row.appendChild(el("span", { class: "role-name" }, [r.admin_role]));
      row.appendChild(el("span", { class: "arr" }, ["via"]));
      row.appendChild(el("span", null, [r.via_roles.join(", ")]));
      what.appendChild(row);
    }
    card.appendChild(what);
    root.appendChild(card);
  }
})();

(function renderDirectGrants() {
  const root = document.getElementById("direct-grants");
  root.innerHTML = "";
  if (!DATA.direct_grants || DATA.direct_grants.length === 0) {
    root.appendChild(el("div", { class: "empty" }, ["No direct user grants in this snapshot."]));
    return;
  }
  const grouped = {};
  for (const g of DATA.direct_grants) {
    if (!grouped[g.user]) grouped[g.user] = [];
    grouped[g.user].push(g);
  }
  for (const user in grouped) {
    const card = el("div", { class: "path-card" });
    card.appendChild(el("div", { class: "who" }, [
      el("span", { class: "role-tag" }, ["User"]),
      user,
    ]));
    const what = el("div");
    for (const g of grouped[user]) {
      const row = el("div", { class: "what", style: "margin-bottom: 6px;" });
      row.appendChild(el("span", { class: "priv-tag" }, [g.privilege + (g.with_grant_option ? " *" : "")]));
      row.appendChild(el("span", { class: "arr" }, ["on " + g.object_type.toLowerCase()]));
      row.appendChild(el("span", { class: "role-name" }, [g.object_name]));
      what.appendChild(row);
    }
    card.appendChild(what);
    root.appendChild(card);
  }
})();

let _policyMapsCache = null;
function _getPolicyMaps() {
  if (_policyMapsCache) return _policyMapsCache;
  const policyTables = (DATA.policy_protections || {}).tables || {};
  const policyCols = (DATA.policy_protections || {}).columns || {};
  const tagTables = (DATA.tag_classifications || {}).tables || {};
  const tagCols = (DATA.tag_classifications || {}).columns || {};
  const tablePolicyByPrefix = {};
  for (const colKey in policyCols) {
    const idx = colKey.lastIndexOf(".");
    if (idx < 0) continue;
    const tableKey = colKey.slice(0, idx);
    if (!tablePolicyByPrefix[tableKey]) tablePolicyByPrefix[tableKey] = [];
    tablePolicyByPrefix[tableKey].push(...policyCols[colKey]);
  }
  const tableTagsByPrefix = {};
  for (const colKey in tagCols) {
    const idx = colKey.lastIndexOf(".");
    if (idx < 0) continue;
    const tableKey = colKey.slice(0, idx);
    if (!tableTagsByPrefix[tableKey]) tableTagsByPrefix[tableKey] = [];
    tableTagsByPrefix[tableKey].push(...tagCols[colKey]);
  }
  _policyMapsCache = {
    policyTables, policyCols, tagTables, tagCols,
    tablePolicyByPrefix, tableTagsByPrefix,
  };
  return _policyMapsCache;
}

(function renderDiff() {
  const root = document.getElementById("diff-content");
  if (!root) return;
  const d = DATA.diff;
  const section = document.getElementById("diff-section");
  if (!d) {
    if (section) section.style.display = "none";
    return;
  }
  root.innerHTML = "";
  const totalChanges = (
    (d.added_roles?.length || 0)
    + (d.removed_roles?.length || 0)
    + (d.added_users?.length || 0)
    + (d.removed_users?.length || 0)
    + (d.added_user_role_grants?.length || 0)
    + (d.removed_user_role_grants?.length || 0)
    + (d.added_role_grants?.length || 0)
    + (d.removed_role_grants?.length || 0)
    + (d.user_mfa_toggled?.length || 0)
    + (d.user_default_role_changed?.length || 0)
  );
  const meta = el("div", { class: "census-stats" }, [
    `Comparing ${d.from_at || "?"} -> ${d.to_at || "?"} • ${fmt(totalChanges)} total changes`
  ]);
  root.appendChild(meta);
  if (totalChanges === 0) {
    root.appendChild(el("div", { class: "empty" }, ["No changes since the previous snapshot."]));
    return;
  }

  function diffSection(title, items, formatter, severity) {
    if (!items || items.length === 0) return;
    const card = el("div", { class: "path-card" });
    const left = el("div", { class: "who" });
    left.appendChild(el("span", { class: "role-tag" }, [title]));
    left.appendChild(document.createTextNode(`${items.length}`));
    if (severity === "danger") {
      left.style.color = "var(--accent)";
    } else if (severity === "good") {
      left.style.color = "#5a6f3d";
    }
    card.appendChild(left);
    const right = el("div");
    const list = el("div", { style: "font-family: 'SF Mono', monospace; font-size: 12px; line-height: 1.7;" });
    for (const it of items.slice(0, 30)) {
      list.appendChild(el("div", null, [formatter(it)]));
    }
    if (items.length > 30) {
      list.appendChild(el("div", { style: "font-style: italic; color: var(--marg);" }, [
        `... ${items.length - 30} more`
      ]));
    }
    right.appendChild(list);
    card.appendChild(right);
    root.appendChild(card);
  }

  diffSection("Removed roles", d.removed_roles,
    (x) => `- ${x.name} (owner: ${x.owner || "—"})`, "danger");
  diffSection("Added roles", d.added_roles,
    (x) => `+ ${x.name} (owner: ${x.owner || "—"})`, "good");
  diffSection("Removed users", d.removed_users,
    (x) => `- ${x.name} (${x.type || "?"})`, "danger");
  diffSection("Added users", d.added_users,
    (x) => `+ ${x.name} (${x.type || "?"})`, "good");
  diffSection("Revoked user-role grants", d.removed_user_role_grants,
    (x) => `- ${x.user} -> ${x.role}`, "good");
  diffSection("New user-role grants", d.added_user_role_grants,
    (x) => `+ ${x.user} -> ${x.role}`, "danger");
  diffSection("MFA toggled", d.user_mfa_toggled,
    (x) => `${x.user}: ${x.from_mfa} -> ${x.to_mfa}`, null);
  diffSection("Default role changed", d.user_default_role_changed,
    (x) => `${x.user}: ${x.from_default} -> ${x.to_default}`, null);
  diffSection("Revoked role grants", d.removed_role_grants,
    (x) => `- ${x.grantee} ${x.privilege} on ${x.granted_on} ${x.object}`, "good");
  diffSection("New role grants", d.added_role_grants,
    (x) => `+ ${x.grantee} ${x.privilege} on ${x.granted_on} ${x.object}`, "danger");
})();

function policyBadgesForObject(qualifiedName) {
  const badges = [];
  const m = _getPolicyMaps();
  const directPolicies = (m.policyTables[qualifiedName] || [])
    .concat(m.policyCols[qualifiedName] || []);
  const inheritedPolicies = m.tablePolicyByPrefix[qualifiedName] || [];
  const directTags = (m.tagTables[qualifiedName] || [])
    .concat(m.tagCols[qualifiedName] || []);
  const inheritedTags = m.tableTagsByPrefix[qualifiedName] || [];
  const seenKinds = new Set();
  for (const p of directPolicies) {
    const kind = (p.kind || "POLICY").toLowerCase();
    let cssClass = "masking";
    let label = "MASKED";
    if (kind.includes("row")) { cssClass = "row-access"; label = "ROW-ACCESS"; }
    else if (kind.includes("aggregation")) { cssClass = "aggregation"; label = "AGG-LIMIT"; }
    else if (kind.includes("masking")) { cssClass = "masking"; label = "MASKED"; }
    else { cssClass = "masking"; label = kind.toUpperCase(); }
    const dedupe = cssClass + ":" + (p.policy || "");
    if (seenKinds.has(dedupe)) continue;
    seenKinds.add(dedupe);
    const span = document.createElement("span");
    span.className = "policy-badge " + cssClass;
    span.textContent = label;
    span.title = p.policy + (p.via_tag ? " (via tag " + p.via_tag + ")" : "");
    badges.push(span);
  }
  if (inheritedPolicies.length && !badges.some(b => b.className.includes("masking") || b.className.includes("row-access"))) {
    const policyKinds = new Set();
    for (const p of inheritedPolicies) {
      const kind = (p.kind || "POLICY").toLowerCase();
      if (kind.includes("row")) policyKinds.add("row-access");
      else if (kind.includes("aggregation")) policyKinds.add("aggregation");
      else policyKinds.add("masking");
    }
    for (const cssClass of policyKinds) {
      const label = cssClass === "row-access" ? "ROW-ACCESS"
        : cssClass === "aggregation" ? "AGG-LIMIT" : "MASKED COLS";
      const span = document.createElement("span");
      span.className = "policy-badge " + cssClass;
      span.textContent = label;
      span.title = inheritedPolicies.map(p => p.policy).join(", ");
      badges.push(span);
    }
  }
  const tagSeen = new Set();
  for (const t of directTags) {
    const key = t.tag + ":" + (t.value || "");
    if (tagSeen.has(key)) continue;
    tagSeen.add(key);
    const span = document.createElement("span");
    span.className = "policy-badge tag";
    span.textContent = "TAG:" + (t.value || t.tag.split(".").pop() || t.tag);
    span.title = t.tag + (t.value ? " = " + t.value : "");
    badges.push(span);
  }
  if (inheritedTags.length && directTags.length === 0) {
    const tagSet = new Set();
    for (const t of inheritedTags) {
      tagSet.add(t.value || t.tag.split(".").pop() || t.tag);
    }
    for (const tagLabel of tagSet) {
      const span = document.createElement("span");
      span.className = "policy-badge tag";
      span.textContent = "COL-TAG:" + tagLabel;
      span.title = "Tagged columns within this table";
      badges.push(span);
    }
  }
  return badges;
}

(function renderPathFinder() {
  const userMap = {};
  for (const u of (DATA.user_census || [])) userMap[u.name] = u;
  const roleMap = DATA.role_impersonation_details || {};

  const userInput = document.getElementById("path-user");
  const objInput = document.getElementById("path-object");
  const status = document.getElementById("path-status");
  const content = document.getElementById("path-content");
  if (!userInput || !objInput || !content) return;

  function qualified(g) {
    if (g.object_type === "DATABASE") return g.name;
    if (g.object_type === "SCHEMA") {
      return [g.database, g.name].filter(Boolean).join(".");
    }
    return [g.database, g.schema, g.name].filter(Boolean).join(".");
  }

  function search() {
    const userQ = userInput.value.trim().toUpperCase();
    const objQ = objInput.value.trim().toUpperCase();

    if (!userQ && !objQ) {
      content.innerHTML = "";
      status.textContent = "Type a user or object to begin.";
      return;
    }

    const matchedUsers = userQ
      ? Object.keys(userMap).filter(n => n.toUpperCase().includes(userQ))
      : Object.keys(userMap);

    const paths = [];
    let scanned = 0;
    const userLimit = Math.min(matchedUsers.length, 200);
    outer:
    for (let i = 0; i < userLimit; i++) {
      const userName = matchedUsers[i];
      const u = userMap[userName];
      if (!u || !u.direct_roles) continue;
      for (const directRole of u.direct_roles) {
        const detail = roleMap[directRole];
        if (!detail) continue;
        for (const g of detail.object_grants) {
          scanned++;
          const obj = qualified(g);
          if (objQ && !obj.toUpperCase().includes(objQ)) continue;
          paths.push({
            user: userName,
            direct_role: directRole,
            via_role: g.via_role,
            object: obj,
            privilege: g.privilege,
            object_type: g.object_type,
            with_grant_option: g.with_grant_option,
          });
          if (paths.length >= 500) break outer;
        }
      }
    }

    content.innerHTML = "";

    if (!paths.length) {
      status.textContent = `No paths found (${scanned} grant rows scanned across ${matchedUsers.length} users).`;
      content.appendChild(el("div", { class: "empty" }, [
        userQ && objQ
          ? `No path from ${userQ}* to ${objQ}*.`
          : userQ ? `User ${userQ}* reaches no objects.`
          : `No user reaches ${objQ}*.`
      ]));
      return;
    }

    const byUser = {};
    for (const p of paths) {
      if (!byUser[p.user]) byUser[p.user] = [];
      byUser[p.user].push(p);
    }

    const userKeys = Object.keys(byUser).sort((a, b) => byUser[b].length - byUser[a].length);
    status.textContent = `${paths.length} path(s) across ${userKeys.length} user(s)`
      + (paths.length === 500 ? " (capped at 500)" : "")
      + (matchedUsers.length > userLimit ? `, ${matchedUsers.length - userLimit} more users skipped` : "");

    for (const userName of userKeys) {
      const card = el("div", { class: "path-card" });
      const left = el("div", { class: "who" });
      left.appendChild(el("span", { class: "role-tag" }, ["User"]));
      left.appendChild(document.createTextNode(userName));
      const u = userMap[userName];
      if (u && u.default_role) {
        left.appendChild(el("div", {
          style: "margin-top: 6px; font-size: 11px; color: var(--marg);"
        }, [`default: ${u.default_role}`]));
      }
      left.appendChild(el("div", {
        style: "margin-top: 4px; font-size: 11px; color: var(--accent);"
      }, [`${byUser[userName].length} path(s)`]));
      card.appendChild(left);

      const right = el("div");
      const tbl = el("table", { class: "census-table" });
      const head = el("thead");
      head.appendChild(el("tr", null, [
        el("th", null, ["Object"]),
        el("th", null, ["Privilege"]),
        el("th", null, ["Path"]),
      ]));
      tbl.appendChild(head);
      const body = el("tbody");
      const userPaths = byUser[userName].slice(0, 50);
      for (const p of userPaths) {
        const pathStr = p.via_role === p.direct_role
          ? `${p.direct_role} ↓`
          : `${p.direct_role} → ${p.via_role}`;
        const objCell = el("td", null, [
          el("span", { style: "font-size: 10px; color: var(--marg); margin-right: 6px;" }, [p.object_type]),
          p.object,
        ]);
        for (const b of policyBadgesForObject(p.object)) {
          objCell.appendChild(b);
        }
        body.appendChild(el("tr", null, [
          objCell,
          el("td", null, [p.privilege + (p.with_grant_option ? " ★" : "")]),
          el("td", null, [pathStr]),
        ]));
      }
      if (byUser[userName].length > 50) {
        body.appendChild(el("tr", null, [
          el("td", { colspan: "3", style: "font-style: italic; color: var(--marg);" }, [
            `... ${byUser[userName].length - 50} more paths hidden`
          ]),
        ]));
      }
      tbl.appendChild(body);
      right.appendChild(tbl);
      card.appendChild(right);
      content.appendChild(card);
    }
  }

  let searchTimer = null;
  function debouncedSearch() {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(search, 200);
  }
  userInput.addEventListener("input", debouncedSearch);
  objInput.addEventListener("input", debouncedSearch);
  status.textContent = "Type a user or object to begin.";
})();

(function renderImpersonation() {
  const details = DATA.role_impersonation_details || {};
  const surface = DATA.role_impersonation || [];
  const search = document.getElementById("impersonate-search");
  const status = document.getElementById("impersonate-status");
  const content = document.getElementById("impersonate-content");
  if (!search || !content) return;

  const allRoles = surface.map(r => r.role).sort();
  if (!allRoles.length) {
    status.textContent = "No roles in snapshot.";
    return;
  }
  status.textContent = `${fmt(allRoles.length)} roles available • start typing to pick one`;

  function render(roleName) {
    const detail = details[roleName];
    if (!detail) {
      content.innerHTML = "";
      content.appendChild(el("div", { class: "empty" }, [
        `No impersonation data for ${roleName}.`
      ]));
      return;
    }
    content.innerHTML = "";

    const surfaceRow = surface.find(r => r.role === roleName) || {};
    const stats = el("div", { class: "census-stats" }, [
      `${fmt(detail.inherited_roles.length)} inherited roles`
      + ` • ${fmt(detail.object_grants.length)} object grants`
      + ` • ${fmt(detail.users_holding_role.length)} users holding`
      + (surfaceRow.reaches_admin ? "  •  ⚠ reaches admin" : "")
      + (surfaceRow.has_grant_admin ? "  •  ⚠ can grant" : "")
      + (surfaceRow.has_ownership ? "  •  has ownership" : "")
      + (surfaceRow.has_write ? "  •  has write" : "")
    ]);
    content.appendChild(stats);

    const grid = el("div", { style: "display: grid; grid-template-columns: 280px 1fr; gap: 32px; margin-top: 16px;" });

    const left = el("div");
    left.appendChild(el("div", { class: "h4-meta" }, [
      `Inherited roles • ${detail.inherited_roles.length}`
    ]));
    const inhTable = el("table", { class: "census-table" });
    const inhBody = el("tbody");
    for (const r of detail.inherited_roles) {
      inhBody.appendChild(el("tr", null, [
        el("td", null, [r.name]),
        el("td", { class: "num" }, [r.depth === 0 ? "self" : `↳ ${r.depth}`]),
      ]));
    }
    inhTable.appendChild(inhBody);
    left.appendChild(inhTable);

    if (detail.users_holding_role.length) {
      left.appendChild(el("div", { class: "h4-meta", style: "margin-top: 18px;" }, [
        `Users holding • ${detail.users_holding_role.length}`
      ]));
      const ul = el("div");
      for (const u of detail.users_holding_role.slice(0, 50)) {
        ul.appendChild(el("div", { class: "neighbor" }, [
          el("span", null, [u]),
        ]));
      }
      if (detail.users_holding_role.length > 50) {
        ul.appendChild(el("div", { class: "neighbor" }, [
          el("span", null, [`... ${detail.users_holding_role.length - 50} more`]),
        ]));
      }
      left.appendChild(ul);
    }

    grid.appendChild(left);

    const right = el("div");
    right.appendChild(el("div", { class: "h4-meta" }, [
      `Object grants • ${detail.object_grants.length}`
    ]));
    const grTable = el("table", { class: "census-table" });
    const grBody = el("tbody");
    const grHead = el("thead");
    grHead.appendChild(el("tr", null, [
      el("th", null, ["Type"]),
      el("th", null, ["Object"]),
      el("th", null, ["Privilege"]),
      el("th", null, ["Via role"]),
    ]));
    grTable.appendChild(grHead);
    const showGrants = detail.object_grants.slice(0, 200);
    for (const g of showGrants) {
      let qualified;
      if (g.object_type === "DATABASE") {
        qualified = g.name;
      } else if (g.object_type === "SCHEMA") {
        qualified = [g.database, g.name].filter(p => p).join(".");
      } else {
        qualified = [g.database, g.schema, g.name].filter(p => p).join(".");
      }
      const objCell = el("td", null, [qualified]);
      for (const b of policyBadgesForObject(qualified)) {
        objCell.appendChild(b);
      }
      grBody.appendChild(el("tr", null, [
        el("td", null, [g.object_type]),
        objCell,
        el("td", null, [
          g.privilege + (g.with_grant_option ? " ★" : "")
        ]),
        el("td", null, [
          g.via_role === roleName ? el("em", null, ["direct"]) : g.via_role
        ]),
      ]));
    }
    if (detail.object_grants.length > 200) {
      grBody.appendChild(el("tr", null, [
        el("td", { colspan: "4", style: "font-style: italic; color: var(--marg);" }, [
          `... ${detail.object_grants.length - 200} more rows hidden`
        ]),
      ]));
    }
    grTable.appendChild(grBody);
    right.appendChild(grTable);
    grid.appendChild(right);
    content.appendChild(grid);
  }

  let lastRender = "";
  search.addEventListener("input", () => {
    const v = search.value.trim().toUpperCase();
    if (!v) { content.innerHTML = ""; lastRender = ""; return; }
    const exact = allRoles.find(r => r.toUpperCase() === v);
    if (exact) { render(exact); lastRender = exact; return; }
    const partial = allRoles.filter(r => r.toUpperCase().includes(v));
    if (partial.length === 1) { render(partial[0]); lastRender = partial[0]; return; }
    if (partial.length === 0) {
      content.innerHTML = "";
      content.appendChild(el("div", { class: "empty" }, [`No role matches "${v}"`]));
      lastRender = "";
      return;
    }
    content.innerHTML = "";
    const list = el("div");
    list.appendChild(el("div", { class: "h4-meta" }, [`${partial.length} matches:`]));
    for (const p of partial.slice(0, 30)) {
      const link = el("a", {
        href: "#",
        style: "display: block; padding: 4px 0; color: var(--accent); text-decoration: none; border-bottom: 1px dotted var(--rule-strong);",
      }, [p]);
      link.addEventListener("click", (e) => {
        e.preventDefault();
        search.value = p;
        render(p);
        lastRender = p;
      });
      list.appendChild(link);
    }
    content.appendChild(list);
  });
})();

(function renderSecondaryRoles() {
  const breakdown = DATA.secondary_role_breakdown || [];
  const reach = DATA.user_secondary_reach || [];
  const root = document.getElementById("secondary-content");
  if (!root) return;
  root.innerHTML = "";
  if (!breakdown.length) {
    root.appendChild(el("div", { class: "empty" }, [
      "No users hold multiple roles in this snapshot."
    ]));
    return;
  }

  const reachByUser = {};
  for (const r of reach) reachByUser[r.user] = r;

  const byUser = {};
  for (const b of breakdown) {
    if (!byUser[b.user]) byUser[b.user] = [];
    byUser[b.user].push(b);
  }

  const ordered = Object.keys(byUser).sort((a, b) => {
    const da = reachByUser[a] ? (reachByUser[a].secondary_priv_count - reachByUser[a].primary_priv_count) : 0;
    const db = reachByUser[b] ? (reachByUser[b].secondary_priv_count - reachByUser[b].primary_priv_count) : 0;
    return db - da;
  });

  for (const user of ordered) {
    const roles = byUser[user];
    const r = reachByUser[user] || {};
    const card = el("div", { class: "path-card" });
    const left = el("div", { class: "who" });
    left.appendChild(el("span", { class: "role-tag" }, ["User"]));
    left.appendChild(document.createTextNode(user));
    if (r.default_role) {
      left.appendChild(el("div", { style: "margin-top: 8px; font-size: 11px; color: var(--marg);" }, [
        `default: ${r.default_role}`
      ]));
    }
    if (r.primary_priv_count != null) {
      left.appendChild(el("div", { style: "margin-top: 4px; font-size: 11px; color: var(--marg);" }, [
        `primary: ${fmt(r.primary_priv_count)} privs`
      ]));
      left.appendChild(el("div", { style: "margin-top: 2px; font-size: 11px; color: var(--accent);" }, [
        `secondary all: ${fmt(r.secondary_priv_count)} privs (+${fmt(r.delta)})`
      ]));
    }
    card.appendChild(left);

    const right = el("div");
    const tbl = el("table", { class: "census-table" });
    const head = el("thead");
    head.appendChild(el("tr", null, [
      el("th", null, ["Role"]),
      el("th", { class: "num" }, ["Total privs"]),
      el("th", { class: "num" }, ["Unique to this role"]),
      el("th", null, ["If revoked, user loses..."]),
    ]));
    tbl.appendChild(head);
    const body = el("tbody");
    for (const b of roles) {
      const lossPct = b.role_priv_count > 0
        ? Math.round((b.unique_priv_count / b.role_priv_count) * 100)
        : 0;
      const lossText = b.unique_priv_count === 0
        ? "0 (subsumed by other roles)"
        : `${fmt(b.unique_priv_count)} privileges (${lossPct}% of this role)`;
      body.appendChild(el("tr", null, [
        el("td", null, [b.role]),
        el("td", { class: "num" }, [fmt(b.role_priv_count)]),
        el("td", { class: "num" }, [fmt(b.unique_priv_count)]),
        el("td", null, [lossText]),
      ]));
    }
    tbl.appendChild(body);
    right.appendChild(tbl);
    card.appendChild(right);
    root.appendChild(card);
  }
})();

(function renderBlastRadius() {
  const blast = DATA.user_blast_radius || {};
  const search = document.getElementById("blast-search");
  const status = document.getElementById("blast-status");
  const content = document.getElementById("blast-content");
  if (!search || !content) return;

  const users = Object.keys(blast).sort((a, b) => {
    return (blast[b].grants || []).length - (blast[a].grants || []).length;
  });
  if (!users.length) {
    status.textContent = "No high-reach users in this snapshot.";
    return;
  }
  status.textContent = `${fmt(users.length)} high-reach users analyzed • start typing to pick one`;

  function render(userName) {
    const detail = blast[userName];
    content.innerHTML = "";
    if (!detail) {
      content.appendChild(el("div", { class: "empty" }, [
        `No blast radius data for ${userName}.`
      ]));
      return;
    }
    const grants = detail.grants || [];
    const objectsBy = {};
    const privByObject = {};
    const rolesUsed = new Set();
    const inheritedRolesUsed = new Set();
    for (const g of grants) {
      let qualified;
      if (g.object_type === "DATABASE") {
        qualified = g.name;
      } else if (g.object_type === "SCHEMA") {
        qualified = [g.database, g.name].filter(p => p).join(".");
      } else {
        qualified = [g.database, g.schema, g.name].filter(p => p).join(".") || g.name;
      }
      const key = `${g.object_type}|${qualified}`;
      if (!objectsBy[key]) {
        objectsBy[key] = { object_type: g.object_type, qualified, privs: new Set(), via: new Set() };
      }
      objectsBy[key].privs.add(g.privilege + (g.with_grant_option ? " ★" : ""));
      objectsBy[key].via.add(`${g.via_direct_role} → ${g.via_inherited_role}`);
      privByObject[g.object_type] = (privByObject[g.object_type] || 0) + 1;
      rolesUsed.add(g.via_direct_role);
      inheritedRolesUsed.add(g.via_inherited_role);
    }
    const objCount = Object.keys(objectsBy).length;
    const stats = el("div", { class: "census-stats" }, [
      `${fmt(grants.length)} grants • ${fmt(objCount)} distinct objects`
      + ` • ${fmt(rolesUsed.size)} direct roles`
      + ` • ${fmt(inheritedRolesUsed.size)} inherited roles`
    ]);
    content.appendChild(stats);

    const typeBreakdown = Object.entries(privByObject)
      .sort((a, b) => b[1] - a[1])
      .map(([t, c]) => `${t}: ${fmt(c)}`)
      .join("  •  ");
    if (typeBreakdown) {
      content.appendChild(el("div", { class: "h4-meta", style: "margin-top: 12px;" }, [typeBreakdown]));
    }

    const tbl = el("table", { class: "census-table" });
    const head = el("thead");
    head.appendChild(el("tr", null, [
      el("th", null, ["Type"]),
      el("th", null, ["Object"]),
      el("th", null, ["Privileges"]),
      el("th", null, ["Via direct role"]),
      el("th", null, ["Carried by inherited role"]),
    ]));
    tbl.appendChild(head);
    const body = el("tbody");
    const sortedKeys = Object.keys(objectsBy).sort();
    const showKeys = sortedKeys.slice(0, 500);
    for (const k of showKeys) {
      const o = objectsBy[k];
      const objCell = el("td", null, [o.qualified]);
      for (const b of policyBadgesForObject(o.qualified)) {
        objCell.appendChild(b);
      }
      const viaList = Array.from(o.via).sort();
      const viaText = viaList.length > 3
        ? `${viaList.slice(0, 3).join(", ")} (+${viaList.length - 3} more)`
        : viaList.join(", ");
      const directs = new Set(viaList.map(v => v.split(" → ")[0]));
      const inherits = new Set(viaList.map(v => v.split(" → ")[1]));
      const privList = Array.from(o.privs).sort();
      const privCell = el("td");
      const PRIV_LIMIT = 8;
      if (privList.length <= PRIV_LIMIT) {
        privCell.appendChild(document.createTextNode(privList.join(", ")));
      } else {
        const shown = el("span", null, [privList.slice(0, PRIV_LIMIT).join(", ") + ", "]);
        const hiddenSpan = el("span", { style: "display: none;" }, [privList.slice(PRIV_LIMIT).join(", ")]);
        const toggle = el("a", {
          href: "#",
          style: "color: var(--accent); text-decoration: none; border-bottom: 1px dotted var(--accent);"
        }, [`+${privList.length - PRIV_LIMIT} more`]);
        toggle.addEventListener("click", (e) => {
          e.preventDefault();
          if (hiddenSpan.style.display === "none") {
            hiddenSpan.style.display = "";
            toggle.textContent = "show less";
          } else {
            hiddenSpan.style.display = "none";
            toggle.textContent = `+${privList.length - PRIV_LIMIT} more`;
          }
        });
        privCell.appendChild(shown);
        privCell.appendChild(hiddenSpan);
        privCell.appendChild(document.createTextNode(" "));
        privCell.appendChild(toggle);
      }
      body.appendChild(el("tr", null, [
        el("td", null, [o.object_type]),
        objCell,
        privCell,
        el("td", null, [Array.from(directs).sort().join(", ")]),
        el("td", null, [Array.from(inherits).sort().join(", ")]),
      ]));
    }
    if (sortedKeys.length > 500) {
      body.appendChild(el("tr", null, [
        el("td", { colspan: "5", style: "font-style: italic; color: var(--marg);" }, [
          `... ${sortedKeys.length - 500} more objects hidden`
        ]),
      ]));
    }
    tbl.appendChild(body);
    content.appendChild(tbl);
  }

  let lastRender = "";
  search.addEventListener("input", () => {
    const v = search.value.trim().toUpperCase();
    if (!v) { content.innerHTML = ""; lastRender = ""; return; }
    const exact = users.find(u => u.toUpperCase() === v);
    if (exact) { render(exact); lastRender = exact; return; }
    const partial = users.filter(u => u.toUpperCase().includes(v));
    if (partial.length === 1) { render(partial[0]); lastRender = partial[0]; return; }
    if (partial.length === 0) {
      content.innerHTML = "";
      content.appendChild(el("div", { class: "empty" }, [`No high-reach user matches "${v}"`]));
      lastRender = "";
      return;
    }
    content.innerHTML = "";
    const list = el("div");
    list.appendChild(el("div", { class: "h4-meta" }, [`${partial.length} matches:`]));
    for (const p of partial.slice(0, 30)) {
      const link = el("a", {
        href: "#",
        style: "display: block; padding: 4px 0; color: var(--accent); text-decoration: none; border-bottom: 1px dotted var(--rule-strong);",
      }, [p]);
      link.addEventListener("click", (e) => {
        e.preventDefault();
        search.value = p;
        render(p);
        lastRender = p;
      });
      list.appendChild(link);
    }
    content.appendChild(list);
  });
})();

(function renderUserCensus() {
  const data = (DATA.user_census || []).slice();
  const tbody = document.querySelector("#user-table tbody");
  const stats = document.getElementById("user-stats");
  const search = document.getElementById("user-search");
  const flagsSel = document.getElementById("user-flags");
  if (!data.length) {
    if (stats) stats.textContent = "No users in census.";
    return;
  }

  const ALL_FLAGS = ["reaches_admin", "person_no_mfa", "legacy_password_auth", "disabled_with_grants", "never_logged_in"];
  const flagActive = {};
  ALL_FLAGS.forEach(f => flagActive[f] = null);
  for (const f of ALL_FLAGS) {
    const t = el("span", {
      class: "origin-toggle",
      "data-active": "true",
      "data-flag": f,
    }, [f]);
    let state = null;
    t.addEventListener("click", () => {
      if (state === null) state = true;
      else if (state === true) state = false;
      else state = null;
      flagActive[f] = state;
      t.setAttribute("data-active", state === null ? "true" : (state ? "true" : "false"));
      t.style.background = state === true ? "rgba(184, 53, 30, 0.15)" : "";
      t.title = state === null ? "any" : (state ? "must have flag" : "must NOT have flag");
      apply();
    });
    flagsSel.appendChild(t);
  }

  let sortKey = "reachable_role_count";
  let sortDir = -1;
  let searchRe = null;

  function apply() {
    let view = data.filter(r => {
      if (searchRe && !searchRe.test(r.name)) return false;
      for (const f of ALL_FLAGS) {
        if (flagActive[f] === true && !r.flags.includes(f)) return false;
        if (flagActive[f] === false && r.flags.includes(f)) return false;
      }
      return true;
    });
    view.sort((a, b) => {
      let av = a[sortKey];
      let bv = b[sortKey];
      if (sortKey === "flags") {
        av = (a.flags || []).length;
        bv = (b.flags || []).length;
      }
      if (av == null) av = -Infinity;
      if (bv == null) bv = -Infinity;
      if (typeof av === "string" || typeof bv === "string") {
        return String(av).localeCompare(String(bv)) * sortDir;
      }
      if (typeof av === "boolean") av = av ? 1 : 0;
      if (typeof bv === "boolean") bv = bv ? 1 : 0;
      return (av - bv) * sortDir;
    });
    tbody.innerHTML = "";
    for (const r of view) {
      const flagPills = el("span", null);
      for (const f of (r.flags || [])) {
        flagPills.appendChild(el("span", {
          class: "origin-pill",
          "data-origin": f === "reaches_admin" ? "customer" : (f === "person_no_mfa" || f === "legacy_password_auth") ? "system" : "snowflake-instance",
          style: "margin-right: 4px;"
        }, [f.replace(/_/g, " ")]));
      }
      const tr = el("tr", { style: "cursor: pointer;" }, [
        el("td", null, [r.name]),
        el("td", null, [r.type || "—"]),
        el("td", null, [r.has_mfa === true ? "✓" : r.has_mfa === false ? "✗" : "?"]),
        el("td", null, [r.default_role || "—"]),
        el("td", { class: "num" }, [fmt(r.direct_role_count)]),
        el("td", { class: "num" }, [fmt(r.reachable_role_count)]),
        el("td", { class: "num" }, [fmt(r.max_path_depth)]),
        el("td", null, [flagPills]),
        el("td", null, [r.last_login ? r.last_login.split(" ")[0] : "—"]),
      ]);
      let expanded = false;
      let expansionRow = null;
      tr.addEventListener("click", () => {
        if (expanded && expansionRow) {
          expansionRow.remove();
          expansionRow = null;
          expanded = false;
          return;
        }
        expansionRow = el("tr");
        const cell = el("td", { colspan: "9", style: "background: var(--paper-dark); padding: 14px 18px; border-bottom: 1px solid var(--ink);" });
        const inner = el("div", null);
        const blastSet = DATA.user_blast_radius || {};
        if (blastSet[r.name]) {
          const blastLink = el("a", {
            href: "#",
            style: "display: inline-block; margin-bottom: 10px; font-family: 'SF Mono', monospace; font-size: 11.5px; padding: 3px 8px; border: 1px solid var(--accent); background: var(--accent); color: var(--paper); text-decoration: none;",
          }, [`Blast radius for ${r.name} →`]);
          blastLink.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            const bs = document.getElementById("blast-search");
            if (bs) {
              bs.value = r.name;
              bs.dispatchEvent(new Event("input"));
              bs.scrollIntoView({block: "center", behavior: "smooth"});
            }
          });
          inner.appendChild(blastLink);
        }
        inner.appendChild(el("div", {
          class: "h4-meta",
          style: "margin-bottom: 6px;",
        }, [
          `Direct roles for ${r.name} (${r.direct_role_count}) — click any to impersonate:`
        ]));
        const roleList = el("div", { style: "display: flex; flex-wrap: wrap; gap: 6px;" });
        for (const role of (r.direct_roles || [])) {
          const link = el("a", {
            href: "#",
            style: "font-family: 'SF Mono', monospace; font-size: 11.5px; padding: 3px 8px; border: 1px solid var(--accent); color: var(--accent); text-decoration: none;",
          }, [role]);
          link.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            const search = document.getElementById("impersonate-search");
            if (search) {
              search.value = role;
              search.dispatchEvent(new Event("input"));
              search.scrollIntoView({block: "center", behavior: "smooth"});
            }
          });
          roleList.appendChild(link);
        }
        inner.appendChild(roleList);
        cell.appendChild(inner);
        expansionRow.appendChild(cell);
        tr.parentNode.insertBefore(expansionRow, tr.nextSibling);
        expanded = true;
      });
      tbody.appendChild(tr);
    }
    stats.textContent = `Showing ${fmt(view.length)} of ${fmt(data.length)} users • sorted by ${sortKey} ${sortDir === 1 ? "asc" : "desc"}`;
    document.querySelectorAll("#user-table th").forEach(th => {
      const key = th.getAttribute("data-sort");
      th.querySelector(".sort-arrow")?.remove();
      if (key === sortKey) {
        th.appendChild(el("span", { class: "sort-arrow" }, [sortDir === 1 ? "▲" : "▼"]));
      }
    });
  }

  search.addEventListener("input", () => {
    const v = search.value.trim();
    if (!v) searchRe = null;
    else { try { searchRe = new RegExp(v, "i"); } catch { searchRe = null; } }
    apply();
  });

  document.querySelectorAll("#user-table th").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.getAttribute("data-sort");
      if (sortKey === key) sortDir = -sortDir;
      else { sortKey = key; sortDir = (["name","type","default_role","last_login","flags"].includes(key)) ? 1 : -1; }
      apply();
    });
  });

  apply();
})();

(function renderCensus() {
  const data = (DATA.role_census || []).slice();
  const tbody = document.querySelector("#census-table tbody");
  const stats = document.getElementById("census-stats");
  const search = document.getElementById("census-search");
  const originSel = document.getElementById("census-origin");
  if (!data.length) {
    stats.textContent = "No roles in census.";
    return;
  }

  const origins = Array.from(new Set(data.map(r => r.origin))).sort();
  const originActive = {};
  origins.forEach(o => originActive[o] = true);
  for (const o of origins) {
    const t = el("span", {
      class: "origin-toggle",
      "data-active": "true",
      "data-origin": o,
    }, [o]);
    t.addEventListener("click", () => {
      originActive[o] = !originActive[o];
      t.setAttribute("data-active", originActive[o] ? "true" : "false");
      apply();
    });
    originSel.appendChild(t);
  }

  let sortKey = "user_count";
  let sortDir = -1;
  let searchRe = null;

  function apply() {
    let view = data.filter(r => originActive[r.origin]);
    if (searchRe) view = view.filter(r => searchRe.test(r.name));
    view.sort((a, b) => {
      const av = a[sortKey] == null ? -Infinity : a[sortKey];
      const bv = b[sortKey] == null ? -Infinity : b[sortKey];
      if (typeof av === "string" || typeof bv === "string") {
        return String(av).localeCompare(String(bv)) * sortDir;
      }
      return (av - bv) * sortDir;
    });
    tbody.innerHTML = "";
    for (const r of view) {
      const tr = el("tr", null, [
        el("td", null, [r.name]),
        el("td", null, [
          el("span", { class: "origin-pill", "data-origin": r.origin }, [r.origin])
        ]),
        el("td", null, [r.role_type || "—"]),
        el("td", null, [r.owner || "—"]),
        el("td", { class: "num" }, [fmt(r.inherits_count)]),
        el("td", { class: "num" }, [fmt(r.inherited_by_count)]),
        el("td", { class: "num" }, [fmt(r.user_count)]),
        el("td", { class: "num" }, [fmt(r.max_reach_depth)]),
      ]);
      tbody.appendChild(tr);
    }
    stats.textContent = `Showing ${fmt(view.length)} of ${fmt(data.length)} roles • sorted by ${sortKey} ${sortDir === 1 ? "asc" : "desc"}`;
    document.querySelectorAll("#census-table th").forEach(th => {
      const key = th.getAttribute("data-sort");
      th.querySelector(".sort-arrow")?.remove();
      if (key === sortKey) {
        th.appendChild(el("span", { class: "sort-arrow" }, [sortDir === 1 ? "▲" : "▼"]));
      }
    });
  }

  search.addEventListener("input", () => {
    const v = search.value.trim();
    if (!v) { searchRe = null; }
    else {
      try { searchRe = new RegExp(v, "i"); }
      catch (e) { searchRe = null; }
    }
    apply();
  });

  document.querySelectorAll("#census-table th").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.getAttribute("data-sort");
      if (sortKey === key) sortDir = -sortDir;
      else { sortKey = key; sortDir = (key === "name" || key === "origin" || key === "role_type" || key === "owner") ? 1 : -1; }
      apply();
    });
  });

  apply();
})();

(function renderAtlas() {
  const svg = document.getElementById("atlas-svg");
  const side = document.getElementById("atlas-side");
  const statsEl = document.getElementById("atlas-stats");
  const SVG_NS = "http://www.w3.org/2000/svg";
  const W = 1080, H = 540;
  const PADDING_X = 36;
  const BAND_TOP = 36;
  const BAND_BOTTOM = 36;

  const grp = DATA.role_groupings || null;
  if (!grp || (grp.functional.length + grp.database_groups.length + grp.system.length) === 0) {
    statsEl.textContent = "Empty role graph.";
    return;
  }

  const COLOR = {
    "system": "#b97817",
    "functional": "#4a5568",
    "database": "#8a1a0e",
  };

  const bands = [
    { id: "system", label: "system", nodes: grp.system.map(n => ({ id: n.name, kind: "system", payload: n })) },
    { id: "functional", label: "functional", nodes: grp.functional.map(n => ({ id: n.name, kind: "functional", payload: n })) },
    { id: "database", label: "database groups", nodes: grp.database_groups.map(n => ({ id: n.id, kind: "database", payload: n })) },
  ].filter(b => b.nodes.length);

  const bandHeight = (H - BAND_TOP - BAND_BOTTOM) / bands.length;
  const bandY = {};
  bands.forEach((b, i) => { bandY[b.id] = BAND_TOP + i * bandHeight + bandHeight / 2; });

  const nodePos = {};
  for (const b of bands) {
    const usable = W - PADDING_X * 2;
    b.nodes.forEach((n, i) => {
      const x = PADDING_X + ((i + 1) * usable) / (b.nodes.length + 1);
      nodePos[n.id] = { x, y: bandY[b.id], band: b.id, node: n };
    });
  }

  for (let i = 0; i < bands.length; i++) {
    const b = bands[i];
    const yLine = BAND_TOP + (i + 1) * bandHeight;
    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("x1", PADDING_X);
    line.setAttribute("x2", W - PADDING_X);
    line.setAttribute("y1", yLine);
    line.setAttribute("y2", yLine);
    line.setAttribute("class", "band-rule");
    svg.appendChild(line);

    const lbl = document.createElementNS(SVG_NS, "text");
    lbl.setAttribute("x", PADDING_X);
    lbl.setAttribute("y", BAND_TOP + i * bandHeight + 14);
    lbl.setAttribute("class", "band-label");
    lbl.textContent = b.label + " — " + b.nodes.length;
    svg.appendChild(lbl);
  }

  const edgesByNode = {};
  for (const b of bands) for (const n of b.nodes) edgesByNode[n.id] = { in: [], out: [] };

  const aggEdges = grp.edges || [];
  for (const e of aggEdges) {
    if (!nodePos[e.source] || !nodePos[e.target]) continue;
    const a = nodePos[e.source];
    const c = nodePos[e.target];
    const ep = document.createElementNS(SVG_NS, "path");
    const dx = c.x - a.x;
    const cy = (a.y + c.y) / 2;
    ep.setAttribute("d", `M ${a.x} ${a.y} C ${a.x + dx * 0.2} ${cy}, ${c.x - dx * 0.2} ${cy}, ${c.x} ${c.y}`);
    ep.setAttribute("class", "edge");
    ep.setAttribute("data-source", e.source);
    ep.setAttribute("data-target", e.target);
    if ((e.weight || 1) > 1) {
      ep.setAttribute("stroke-width", String(Math.min(4, 1 + Math.log2(e.weight))));
    }
    svg.appendChild(ep);
    edgesByNode[e.source]?.out.push({ to: e.target, weight: e.weight });
    edgesByNode[e.target]?.in.push({ from: e.source, weight: e.weight });
  }

  for (const b of bands) {
    for (const n of b.nodes) {
      const p = nodePos[n.id];
      const g = document.createElementNS(SVG_NS, "g");
      g.setAttribute("class", "node");
      g.setAttribute("data-id", n.id);
      g.setAttribute("data-kind", n.kind);
      g.setAttribute("transform", `translate(${p.x}, ${p.y})`);

      const isDb = n.kind === "database";
      const r = isDb ? Math.max(6, Math.min(14, 4 + Math.sqrt(n.payload.role_count || 0))) : 4.5;
      const c = document.createElementNS(SVG_NS, "circle");
      c.setAttribute("r", String(r));
      c.setAttribute("fill", COLOR[n.kind]);
      g.appendChild(c);

      if (isDb) {
        const badge = document.createElementNS(SVG_NS, "text");
        badge.setAttribute("x", "0");
        badge.setAttribute("y", String(r + 12));
        badge.setAttribute("text-anchor", "middle");
        badge.setAttribute("font-family", "SF Mono, JetBrains Mono, monospace");
        badge.setAttribute("font-size", "10");
        badge.setAttribute("fill", "#1a1814");
        badge.textContent = n.id + " (" + n.payload.role_count + ")";
        g.appendChild(badge);
      } else {
        const t = document.createElementNS(SVG_NS, "text");
        t.setAttribute("x", "0");
        t.setAttribute("y", "-9");
        t.setAttribute("text-anchor", "middle");
        t.textContent = n.id;
        g.appendChild(t);
      }

      g.addEventListener("click", () => selectNode(n.id));
      g.addEventListener("dblclick", (e) => {
        e.preventDefault();
        if (n.kind === "system" || n.kind === "functional") {
          const search = document.getElementById("impersonate-search");
          if (search) {
            search.value = n.id;
            search.dispatchEvent(new Event("input"));
            search.scrollIntoView({block: "center", behavior: "smooth"});
            search.focus();
          }
        }
      });
      svg.appendChild(g);
    }
  }

  function selectNode(id) {
    const node = nodePos[id]?.node;
    if (!node) return;
    const neighborSet = new Set([id]);
    (edgesByNode[id]?.in || []).forEach(x => neighborSet.add(x.from));
    (edgesByNode[id]?.out || []).forEach(x => neighborSet.add(x.to));

    svg.querySelectorAll(".node").forEach(n => {
      const nid = n.getAttribute("data-id");
      if (nid === id) {
        n.classList.add("highlight");
        n.classList.remove("dim");
      } else if (neighborSet.has(nid)) {
        n.classList.remove("dim", "highlight");
      } else {
        n.classList.add("dim");
        n.classList.remove("highlight");
      }
    });
    svg.querySelectorAll(".edge").forEach(e => {
      const s = e.getAttribute("data-source");
      const t = e.getAttribute("data-target");
      if (s === id || t === id) e.classList.add("highlight");
      else e.classList.remove("highlight");
    });

    side.innerHTML = "";

    if (node.kind === "database") {
      const dbg = node.payload;
      side.appendChild(el("div", { class: "h4-meta" }, [
        "DATABASE GROUP • " + dbg.schema_count + " schemas • " + dbg.role_count + " access roles"
      ]));
      side.appendChild(el("h4", null, [dbg.id]));

      const ins = edgesByNode[id]?.in || [];
      const outs = edgesByNode[id]?.out || [];
      const head = el("div", { class: "h4-meta", style: "margin-top: 8px;" }, [
        "Inherits from " + outs.length + " parent role(s)  •  Granted to " + ins.length + " consumer role(s)"
      ]);
      side.appendChild(head);

      const grid = el("div", { class: "neighbor-list" });
      const col1 = el("div");
      col1.appendChild(el("div", { class: "h4-meta" }, ["Schemas"]));
      for (const s of dbg.schemas) {
        const sname = s.schema || "(no schema)";
        const roleStr = s.roles.map(r => r.name + " [" + r.envelope + "]").join(", ");
        col1.appendChild(el("div", { class: "neighbor" }, [
          el("span", null, [sname]),
          el("span", { class: "arr" }, ["·"]),
          el("span", null, [roleStr]),
        ]));
      }
      grid.appendChild(col1);

      const col2 = el("div");
      col2.appendChild(el("div", { class: "h4-meta" }, [
        outs.length ? "Inherits from " + outs.length : "Inherits from —"
      ]));
      for (const o of outs.sort((a, b) => a.to.localeCompare(b.to))) {
        col2.appendChild(el("div", { class: "neighbor" }, [
          el("span", null, ["this"]),
          el("span", { class: "arr" }, ["←"]),
          el("span", null, [o.to + (o.weight > 1 ? " (×" + o.weight + ")" : "")]),
        ]));
      }
      col2.appendChild(el("div", { class: "h4-meta", style: "margin-top: 12px;" }, [
        ins.length ? "Granted to " + ins.length : "Granted to —"
      ]));
      for (const i2 of ins.sort((a, b) => a.from.localeCompare(b.from))) {
        col2.appendChild(el("div", { class: "neighbor" }, [
          el("span", null, ["this"]),
          el("span", { class: "arr" }, ["→"]),
          el("span", null, [i2.from + (i2.weight > 1 ? " (×" + i2.weight + ")" : "")]),
        ]));
      }
      grid.appendChild(col2);
      side.appendChild(grid);
    } else {
      side.appendChild(el("div", { class: "h4-meta" }, [
        "ROLE • " + (node.kind === "system" ? "system" : (node.payload.origin || "customer"))
      ]));
      const heading = el("h4", null, [id]);
      side.appendChild(heading);
      const impersonateLink = el("a", {
        href: "#",
        style: "display: inline-block; margin: 4px 0 8px 0; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); text-decoration: none; border-bottom: 1px dotted var(--accent);",
      }, ["→ Impersonate this role"]);
      impersonateLink.addEventListener("click", (e) => {
        e.preventDefault();
        const search = document.getElementById("impersonate-search");
        if (search) {
          search.value = id;
          search.dispatchEvent(new Event("input"));
          search.scrollIntoView({block: "center", behavior: "smooth"});
        }
      });
      side.appendChild(impersonateLink);

      const ins = edgesByNode[id]?.in || [];
      const outs = edgesByNode[id]?.out || [];
      const grid = el("div", { class: "neighbor-list" });
      const col1 = el("div");
      col1.appendChild(el("div", { class: "h4-meta" }, [
        outs.length ? "Inherits from " + outs.length : "Inherits from —"
      ]));
      for (const o of outs.sort((a, b) => a.to.localeCompare(b.to))) {
        col1.appendChild(el("div", { class: "neighbor" }, [
          el("span", null, ["this"]),
          el("span", { class: "arr" }, ["←"]),
          el("span", null, [o.to + (o.weight > 1 ? " (×" + o.weight + ")" : "")]),
        ]));
      }
      grid.appendChild(col1);

      const col2 = el("div");
      col2.appendChild(el("div", { class: "h4-meta" }, [
        ins.length ? "Granted to " + ins.length : "Granted to —"
      ]));
      for (const i2 of ins.sort((a, b) => a.from.localeCompare(b.from))) {
        col2.appendChild(el("div", { class: "neighbor" }, [
          el("span", null, ["this"]),
          el("span", { class: "arr" }, ["→"]),
          el("span", null, [i2.from + (i2.weight > 1 ? " (×" + i2.weight + ")" : "")]),
        ]));
      }
      grid.appendChild(col2);
      side.appendChild(grid);
    }
  }

  const totalRoles = grp.functional.length + grp.database_groups.reduce((a, b) => a + b.role_count, 0) + grp.system.length;
  statsEl.textContent =
    fmt(totalRoles) + " roles aggregated to "
    + fmt(grp.functional.length + grp.database_groups.length + grp.system.length) + " atlas nodes ("
    + fmt(grp.system.length) + " system • " + fmt(grp.functional.length) + " functional • "
    + fmt(grp.database_groups.length) + " database groups) • "
    + fmt((grp.edges || []).length) + " aggregated edges";
})();
</script>
</body>
</html>
"""


def render_report(data: dict[str, Any], title: str = "Uberblick Report") -> str:
    payload = json.dumps(data, default=str)
    return _TEMPLATE.replace("__DATA__", payload).replace("__TITLE__", title)
