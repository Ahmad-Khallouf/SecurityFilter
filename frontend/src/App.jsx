import { useEffect, useState } from 'react';
import { getDemoStatus, listFiles } from './api.js';
import UploadCard from './components/UploadCard.jsx';
import ComparePanel from './components/ComparePanel.jsx';
import './styles.css';

export default function App() {
    const [tab, setTab] = useState('upload');
    const [demoMode, setDemoMode] = useState(false);
    const [files, setFiles] = useState([]);

    // Ask the server whether demo features exist. The UI reflects the real state
    // instead of assuming — when demo mode is off, the comparison tab is not shown
    // because the endpoint behind it genuinely is not there.
    useEffect(() => {
        getDemoStatus().then((s) => setDemoMode(!!s.demoMode));
    }, []);

    function refreshFiles() {
        listFiles().then(setFiles);
    }

    useEffect(() => {
        if (tab === 'files') refreshFiles();
    }, [tab]);

    return (
        <div className="app">
            <header className="topbar">
                <h1 className="wordmark">SECURE<span>UPLOADER</span></h1>
                <p className="tagline">Layered upload validation — a byte-level look at each check.</p>
                <span className={`demo-flag ${demoMode ? '' : 'off'}`}>
                    {demoMode ? 'demo mode on' : 'demo mode off'}
                </span>
            </header>

            <nav className="tabs">
                <button className={`tab ${tab === 'upload' ? 'active' : ''}`} onClick={() => setTab('upload')}>
                    Upload
                </button>
                {demoMode && (
                    <button className={`tab ${tab === 'compare' ? 'active' : ''}`} onClick={() => setTab('compare')}>
                        Compare filters
                    </button>
                )}
                <button className={`tab ${tab === 'files' ? 'active' : ''}`} onClick={() => setTab('files')}>
                    Stored files
                </button>
            </nav>

            {tab === 'upload' && (
                <div>
                    <p className="eyebrow">Upload</p>
                    <p className="lede">
                        Files run through the full filter. Accepted images are re-encoded before
                        storage, so anything hidden alongside the pixels does not survive — even
                        when no layer flagged it.
                    </p>
                    <div className="grid">
                        <UploadCard
                            category="profile"
                            title="Profile picture"
                            subtitle="JPEG, PNG, WebP, or SVG"
                            accept="jpg · jpeg · png · webp · svg"
                            onUploaded={refreshFiles}
                        />
                        <UploadCard
                            category="id"
                            title="ID document"
                            subtitle="PDF or image"
                            accept="pdf · jpg · jpeg · png"
                            onUploaded={refreshFiles}
                        />
                    </div>
                </div>
            )}

            {tab === 'compare' && demoMode && <ComparePanel />}

            {tab === 'files' && (
                <div>
                    <p className="eyebrow">Stored files</p>
                    <p className="lede">Everything the filter accepted and kept.</p>
                    {files.length === 0 ? (
                        <div className="empty">Nothing stored yet. Accepted uploads show up here.</div>
                    ) : (
                        <ul className="file-list">
                            {files.map((f, i) => (
                                <li key={i} className="file-row">
                                    <span className={`pill ${f.category}`}>{f.category}</span>
                                    <span className="file-name">
                                        <a href={f.url} target="_blank" rel="noreferrer">{f.storedName}</a>
                                    </span>
                                    <span className="file-size">{(f.size / 1024).toFixed(1)} KB</span>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            )}

            <footer className="foot">
                Static-analysis pipeline · rejections return a generic message in production ·
                per-layer detail shown here only while demo mode is on.
            </footer>
        </div>
    );
}