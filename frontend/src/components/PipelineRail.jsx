import { useState } from 'react';

/**
 * The signature view: one uploaded file's journey through the filter, drawn as
 * a spine with a node per layer.
 *
 * Why a rail and not a table: the pipeline is fail-fast, so where the file
 * STOPPED is the most important fact about it. A spine that simply ends at the
 * rejecting layer shows that directly; a table of rows would leave the reader
 * to work it out.
 *
 * Layer names arrive wrapped when a layer is cached — "Cached(SignatureScanning)".
 * The wrapper is unwrapped for display and replaced by a tag shown only on an
 * actual cache HIT, so the tag reports what happened rather than what was
 * merely possible.
 *
 * EVIDENCE
 * Each layer also reports the observations behind its decision. Those are shown
 * expanded on the layer that REJECTED and collapsed everywhere else: every layer
 * now carries evidence, including the ones that passed, and showing all of it at
 * once buries the one entry that explains the outcome. The counts stay visible so
 * a passing layer still shows that it measured something.
 */

const DECISION_CLASS = {
    Accepted: 'pass',
    Sanitized: 'rewrite',
    Rejected: 'fail',
};

// Severity comes from the detecting rule, not from the UI. 'unknown' is kept
// visually distinct because it marks a SCANNER FAILURE rather than a finding —
// the two must never read alike.
const SEVERITY_CLASS = {
    critical: 'ev-high',
    high: 'ev-high',
    medium: 'ev-medium',
    low: 'ev-low',
    info: 'ev-info',
    unknown: 'ev-unknown',
};

function unwrap(layerName) {
    const match = /^Cached\((.+)\)$/.exec(layerName);
    return match ? match[1] : layerName;
}

function hex(offset) {
    if (offset === null || offset === undefined) return null;
    return `0x${Number(offset).toString(16)}`;
}

function EvidenceList({ items }) {
    return (
        <ul className="rail-ev">
            {items.map((e, i) => {
                const severity = SEVERITY_CLASS[e.severity] || 'ev-info';
                const at = hex(e.offset);

                return (
                    <li key={`${e.kind}-${e.label}-${i}`} className={`rail-ev-item ${severity}`}>
                        <div className="rail-ev-head">
                            <span className="rail-ev-label">{e.label}</span>
                            {at && <span className="rail-ev-at">{at}</span>}
                            <span className="rail-ev-kind">{e.kind}</span>
                        </div>
                        <p className="rail-ev-detail">{e.detail}</p>
                        {e.reference && <p className="rail-ev-ref">{e.reference}</p>}
                    </li>
                );
            })}
        </ul>
    );
}

function RailNode({ trace, index }) {
    const state = DECISION_CLASS[trace.decision] || 'pass';
    const rejected = trace.decision === 'Rejected';
    const evidence = trace.evidence || [];

    // The rejecting layer opens itself: it is the answer to "why".
    const [open, setOpen] = useState(rejected);

    const notable = evidence.filter(
        (e) => e.severity === 'high' || e.severity === 'medium',
    ).length;

    return (
        <li
            className={`rail-node ${state}`}
            style={{ animationDelay: `${index * 28}ms` }}
        >
            <span className="rail-layer">{unwrap(trace.layer)}</span>
            {trace.fromCache ? <span className="rail-tag">cache hit</span> : <span />}
            <span className="rail-ms">{(trace.elapsedMs ?? 0).toFixed(2)} ms</span>

            {rejected && trace.reason && <p className="rail-reason">{trace.reason}</p>}

            {evidence.length > 0 && (
                <>
                    <button
                        type="button"
                        className="rail-ev-toggle"
                        aria-expanded={open}
                        onClick={() => setOpen((v) => !v)}
                    >
                        {open ? 'Hide' : 'Show'} {evidence.length}{' '}
                        {evidence.length === 1 ? 'observation' : 'observations'}
                        {notable > 0 && <span className="rail-ev-count">{notable} notable</span>}
                    </button>

                    {open && <EvidenceList items={evidence} />}
                </>
            )}
        </li>
    );
}

export default function PipelineRail({ traces }) {
    if (!traces || traces.length === 0) return null;

    const total = traces.reduce((sum, t) => sum + (t.elapsedMs || 0), 0);

    return (
        <>
            <ol className="rail">
                {traces.map((t, i) => (
                    <RailNode key={`${t.layer}-${i}`} trace={t} index={i} />
                ))}
            </ol>

            <div className="rail-total">
                <span>{traces.length} layers run</span>
                <span>{total.toFixed(2)} ms total</span>
            </div>
        </>
    );
}