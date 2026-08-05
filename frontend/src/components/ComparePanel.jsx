import { useRef, useState } from 'react';
import { compareFile } from '../api.js';

/**
 * The evaluation view: one file, every scanner, side by side.
 *
 * The point of the table is the DIVERGENCE down a column — the same bytes that
 * a weak comparator accepts are rejected, or neutralized, by stronger ones. So
 * the outcome cell carries three states, and our own filter's row is marked,
 * because the comparison only means something relative to it.
 */

function outcomeOf(entry) {
    if (!entry.accepted) return { cls: 'fail', text: 'Rejected' };
    if (entry.contentRewritten) return { cls: 'rewrite', text: 'Neutralized' };
    return { cls: 'pass', text: 'Accepted' };
}

// The layered filter's row, highlighted as the reference point.
const OURS = 'SecureUploader (layered filter)';

export default function ComparePanel() {
    const inputRef = useRef(null);
    const [file, setFile] = useState(null);
    const [category, setCategory] = useState('profile');
    const [status, setStatus] = useState('idle');
    const [run, setRun] = useState(null);
    const [dragOver, setDragOver] = useState(false);

    function choose(f) {
        if (!f) return;
        setFile(f);
        setRun(null);
    }

    async function submit() {
        if (!file) return;
        setStatus('running');
        const res = await compareFile(file, category);
        setRun(res.body || null);
        setStatus('done');
    }

    return (
        <div>
            <p className="eyebrow">Evaluation harness</p>
            <p className="lede">
                Run one file through every scanner at once. Each keeps its own copy of what
                it would have stored, so the difference in verdicts is the whole point.
            </p>

            <div className="notice">
                <strong>Handle with care</strong>
                The weak comparators store whatever they accept, unchanged. Run hostile
                samples here only in the isolated test environment — these files are never
                served back over the web.
            </div>

            <div className="card">
                <div
                    className={`dropzone ${dragOver ? 'drag' : ''}`}
                    onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={(e) => { e.preventDefault(); setDragOver(false); choose(e.dataTransfer.files?.[0]); }}
                    onClick={() => inputRef.current?.click()}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') inputRef.current?.click(); }}
                >
                    <div className="dz-empty">
                        <span className="dz-icon">↑</span>
                        <span>{file ? file.name : 'Drop a file here, or click to browse'}</span>
                        <span className="dz-hint">any file — the point is to see what each scanner does with it</span>
                    </div>
                    <input ref={inputRef} type="file" hidden onChange={(e) => choose(e.target.files?.[0])} />
                </div>

                <div className="actions">
                    <label className="pill" style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                        category:&nbsp;
                        <select
                            value={category}
                            onChange={(e) => setCategory(e.target.value)}
                            style={{ background: 'transparent', color: 'inherit', border: 0, fontFamily: 'inherit' }}
                        >
                            <option value="profile">profile</option>
                            <option value="id">id</option>
                        </select>
                    </label>
                    <button className="btn primary" disabled={!file || status === 'running'} onClick={submit}>
                        {status === 'running' ? 'Running…' : 'Run comparison'}
                    </button>
                </div>
            </div>

            {run && <ComparisonTable run={run} />}
        </div>
    );
}

function ComparisonTable({ run }) {
    return (
        <div style={{ marginTop: 22 }}>
            <div className="run-meta">
                <span>file: <code>{run.originalName}</code></span>
                <span>declared: <code>{run.declaredContentType || '—'}</code></span>
                <span>size: <code>{run.originalSize} B</code></span>
                <span>sha256: <code>{run.sha256?.slice(0, 16)}…</code></span>
            </div>

            <div className="matrix-wrap">
                <table className="matrix">
                    <thead>
                        <tr>
                            <th>Scanner</th>
                            <th>Outcome</th>
                            <th>Reason</th>
                            <th>Time</th>
                            <th>Stored</th>
                        </tr>
                    </thead>
                    <tbody>
                        {run.results.map((entry, i) => {
                            const o = outcomeOf(entry);
                            const ours = entry.scanner === OURS;
                            return (
                                <tr key={i} className={ours ? 'ours' : ''}>
                                    <td className="scanner-name">
                                        {ours && <span className="ours-mark">▸</span>}
                                        {entry.scanner}
                                    </td>
                                    <td>
                                        <span className="outcome">
                                            <span className={`dot ${o.cls}`} />
                                            <span className={`outcome-text ${o.cls}`}>{o.text}</span>
                                        </span>
                                    </td>
                                    <td className="cell-reason">{entry.reason}</td>
                                    <td className="cell-ms">{(entry.elapsedMs ?? 0).toFixed(2)} ms</td>
                                    <td className="cell-ms">{entry.accepted ? `${entry.storedSize} B` : '—'}</td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>

            <div className="legend">
                <span className="legend-item"><span className="dot pass" /> Accepted — stored as-is</span>
                <span className="legend-item"><span className="dot rewrite" /> Neutralized — accepted but content rebuilt</span>
                <span className="legend-item"><span className="dot fail" /> Rejected — refused</span>
            </div>
        </div>
    );
}