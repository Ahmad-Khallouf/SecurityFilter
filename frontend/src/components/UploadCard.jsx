import { useRef, useState } from 'react';
import { uploadFile } from '../api.js';
import PipelineRail from './PipelineRail.jsx';

export default function UploadCard({ category, title, subtitle, accept, onUploaded }) {
    const inputRef = useRef(null);
    const [file, setFile] = useState(null);
    const [preview, setPreview] = useState(null);
    const [status, setStatus] = useState('idle'); // idle | uploading | done
    const [result, setResult] = useState(null);
    const [dragOver, setDragOver] = useState(false);

    function choose(f) {
        if (!f) return;
        setFile(f);
        setResult(null);
        setStatus('idle');

        // Raster images preview; SVG deliberately does not. Rendering an untrusted
        // SVG here would execute its script in this page — the exact attack the
        // filter exists to stop.
        if (f.type.startsWith('image/') && f.type !== 'image/svg+xml') {
            setPreview(URL.createObjectURL(f));
        } else {
            setPreview(null);
        }
    }

    function onDrop(e) {
        e.preventDefault();
        setDragOver(false);
        choose(e.dataTransfer.files?.[0]);
    }

    async function submit() {
        if (!file) return;
        setStatus('uploading');
        const res = await uploadFile(file, category);
        setResult(res);
        setStatus('done');
        if (res.ok && res.body?.accepted) onUploaded?.();
    }

    function reset() {
        setFile(null);
        setPreview(null);
        setResult(null);
        setStatus('idle');
        if (inputRef.current) inputRef.current.value = '';
    }

    return (
        <section className="card">
            <div className="card-head">
                <h2>{title}</h2>
                <p>{subtitle}</p>
            </div>

            <div
                className={`dropzone ${dragOver ? 'drag' : ''}`}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={onDrop}
                onClick={() => inputRef.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') inputRef.current?.click(); }}
            >
                {preview ? (
                    <img className="preview" src={preview} alt="Selected file" />
                ) : (
                    <div className="dz-empty">
                        <span className="dz-icon">↑</span>
                        <span>Drop a file here, or click to browse</span>
                        <span className="dz-hint">{accept}</span>
                    </div>
                )}
                <input
                    ref={inputRef}
                    type="file"
                    hidden
                    onChange={(e) => choose(e.target.files?.[0])}
                />
            </div>

            {file && (
                <div className="filemeta">
                    <strong>{file.name}</strong>
                    <span className="muted">{(file.size / 1024).toFixed(1)} KB</span>
                    <span className="muted">{file.type || 'type not declared'}</span>
                </div>
            )}

            <div className="actions">
                <button className="btn primary" disabled={!file || status === 'uploading'} onClick={submit}>
                    {status === 'uploading' ? 'Scanning…' : 'Upload'}
                </button>
                <button className="btn" disabled={!file} onClick={reset}>Clear</button>
            </div>

            {result && <ResultPanel res={result} />}
        </section>
    );
}

function ResultPanel({ res }) {
    const b = res.body || {};
    const accepted = res.ok && b.accepted;
    const rewritten = accepted && b.contentRewritten;

    // Three outcomes, not two: a file can pass every detection layer and still
    // have had its payload destroyed by re-encoding. Collapsing that into
    // "accepted" would hide the distinction the project is built on.
    const state = !accepted ? 'fail' : rewritten ? 'rewrite' : 'pass';
    const label = !accepted ? 'Rejected' : rewritten ? 'Accepted' : 'Accepted';

    return (
        <div className="result">
            <div className="verdict">
                <span className={`dot ${state}`} />
                <span className={`verdict-label ${accepted ? 'pass' : 'fail'}`}>{label}</span>
                {rewritten && <span className="badge">content rewritten</span>}
                <span className="badge neutral">HTTP {res.status}</span>
            </div>

            {b.message && <p className="result-msg">{b.message}</p>}

            {accepted && b.storedName && (
                <div className="filemeta">
                    <span className="muted">Stored as</span>
                    <strong>{b.storedName}</strong>
                </div>
            )}

            <PipelineRail traces={b.traces} />
        </div>
    );
}