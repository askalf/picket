/**
 * The injection detector.
 *
 * Pure, synchronous, no I/O: an Observation in, a Detection out. Everything
 * here is deterministic and unit-testable. The mental model is Simon Willison's
 * "lethal trifecta" — an attack needs (1) the agent reachable by untrusted
 * content, (2) access to private data, and (3) a way to exfiltrate it. Page
 * content is untrusted by construction, so we score each node for the other
 * two legs plus the imperative that fuses them, and flag co-location.
 */

import {
  INSTRUCTION_TO_AI, AUTHORITY_SPOOF, TOOL_CALL, EXFIL_VERB, SENSITIVE,
  SUSPICIOUS_SINKS, stripInvisible, stripSinks, matchAny, matchedLabels,
  extractUrls, extractEmails, hostOf,
} from './patterns.mjs';

/** Verdict / per-node action lattice, strongest last. */
export const ACTIONS = ['allow', 'flag', 'quarantine', 'block'];
export const actionRank = (a) => ACTIONS.indexOf(a);
export const worstAction = (a, b) => (actionRank(a) >= actionRank(b) ? a : b);

const WEIGHTS = {
  instructionToAI: 3,
  authoritySpoof: 3,
  exfilTarget: 3,
  toolCall: 2,
  hidden: 2,
  zeroWidth: 2,
  sensitive: 1,
};

function severityFor(score, trifecta) {
  // block is reserved for the lethal trifecta or an overwhelming pile-up of
  // strong signals; a dangerous-but-non-exfil instruction quarantines instead.
  if (trifecta || score >= 8) return 'critical';
  if (score >= 5) return 'high';
  if (score >= 3) return 'medium';
  if (score >= 1) return 'low';
  return 'info';
}

export function severityToAction(sev) {
  switch (sev) {
    case 'critical': return 'block';
    case 'high':
    case 'medium': return 'quarantine';
    case 'low': return 'flag';
    default: return 'allow';
  }
}

/**
 * Analyze one node. Returns a Finding, or null when the node is benign.
 * The null path is where false-positive discipline lives: visible marketing
 * text that merely contains a URL or the word "email" must not trip the wire.
 */
export function analyzeNode(node, ctx) {
  const raw = node.text || '';
  const clean = stripInvisible(raw);
  const zeroWidth = clean.length !== raw.length;

  const signals = {
    hidden: !!node.hidden,
    zeroWidth,
    instructionToAI: matchAny(clean, INSTRUCTION_TO_AI),
    authoritySpoof: matchAny(clean, AUTHORITY_SPOOF),
    toolCall: matchAny(clean, TOOL_CALL),
    sensitive: matchAny(clean, SENSITIVE),
    exfilTarget: false,
  };

  // Exfil leg: an outbound verb AND a sink that leaves our origin.
  const urls = extractUrls(clean);
  const emails = extractEmails(clean);
  const offOriginUrl = urls.some((u) => {
    const h = hostOf(u);
    return h && h !== ctx.originHost;
  });
  const knownSink = SUSPICIOUS_SINKS.some((re) => re.test(clean));
  const externalSink = offOriginUrl || emails.length > 0 || knownSink;
  // verb must appear in PROSE, not inside the sink's own URL/email text
  signals.exfilTarget = externalSink && matchAny(stripSinks(clean), EXFIL_VERB);

  // A node is only a Finding if it carries a command signal, OR it is hidden
  // with substance, OR it fuses exfil with a reason to care. Pure-hidden
  // boilerplate (sr-only labels, layout comments) — and a hidden node that
  // merely contains a bare URL — are intentionally ignored.
  const commandSignal = signals.instructionToAI || signals.authoritySpoof || signals.toolCall || signals.zeroWidth;
  const hiddenSubstance = signals.hidden && (signals.sensitive || signals.exfilTarget);
  const exfilCombo = signals.exfilTarget && (signals.sensitive || signals.instructionToAI || signals.hidden);
  if (!commandSignal && !hiddenSubstance && !exfilCombo) return null;

  let score = 0;
  for (const k of Object.keys(WEIGHTS)) if (signals[k]) score += WEIGHTS[k];

  // The jackpot: a single node that instructs, names secrets, and exfiltrates.
  const trifecta =
    (signals.instructionToAI || signals.authoritySpoof || signals.toolCall) &&
    signals.sensitive &&
    signals.exfilTarget;

  const severity = severityFor(score, trifecta);

  const categories = [];
  if (signals.instructionToAI) categories.push('instruction-to-ai');
  if (signals.authoritySpoof) categories.push('authority-spoof');
  if (signals.toolCall) categories.push('tool-call');
  if (signals.exfilTarget) categories.push('exfil-lure');
  if (signals.sensitive) categories.push('sensitive-data');
  if (signals.zeroWidth) categories.push('zero-width-smuggling');
  if (signals.hidden) categories.push('hidden-text');

  return {
    nodeId: node.id,
    source: node.source,
    tag: node.tag,
    path: node.path,
    hidden: node.hidden,
    hiddenReasons: node.hiddenReasons || [],
    excerpt: clean.replace(/\s+/g, ' ').trim().slice(0, 160),
    categories,
    signals,
    matched: {
      instructionToAI: matchedLabels(clean, INSTRUCTION_TO_AI),
      authoritySpoof: matchedLabels(clean, AUTHORITY_SPOOF),
      toolCall: matchedLabels(clean, TOOL_CALL),
    },
    sinks: [...new Set([...urls.filter((u) => hostOf(u) && hostOf(u) !== ctx.originHost), ...emails])].slice(0, 5),
    score,
    trifecta,
    severity,
    action: severityToAction(severity),
  };
}

/**
 * Detect over a whole Observation.
 * @param {import('./observation.mjs').Observation} obs
 * @returns {Detection}
 */
export function detect(obs) {
  const ctx = { originHost: hostOf(obs.url) || hostOf(obs.origin) || null };
  const findings = [];
  for (const node of obs.nodes) {
    const f = analyzeNode(node, ctx);
    if (f) findings.push(f);
  }
  findings.sort((a, b) => actionRank(b.action) - actionRank(a.action) || b.score - a.score);

  const verdict = findings.reduce((acc, f) => worstAction(acc, f.action), 'allow');
  const trifecta = findings.some((f) => f.trifecta);
  const totalScore = findings.reduce((s, f) => s + f.score, 0);

  const counts = findings.reduce((m, f) => ((m[f.severity] = (m[f.severity] || 0) + 1), m), {});
  const summary = findings.length === 0
    ? 'clean — no injection signals'
    : `${findings.length} finding(s): ` +
      ['critical', 'high', 'medium', 'low'].filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(', ') +
      (trifecta ? ' — LETHAL TRIFECTA present' : '');

  return { verdict, trifecta, totalScore, findings, counts, summary, capturedBy: obs.capturedBy };
}

/**
 * @typedef {Object} Detection
 * @property {('allow'|'flag'|'quarantine'|'block')} verdict
 * @property {boolean} trifecta
 * @property {number}  totalScore
 * @property {Object[]} findings
 * @property {Object}  counts
 * @property {string}  summary
 */
