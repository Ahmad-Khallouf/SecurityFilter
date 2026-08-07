# SecureUploader

A defense-in-depth file-upload security filter for web applications.

SecureUploader turns an untrusted uploaded file into one of three outcomes — **rejected** with a
per-layer evidence trail, **neutralized** (rewritten so the payload is gone but the legitimate
content survives), or **accepted** — by running it through nine ordered inspection layers.

Conventional upload validators apply a single check: an extension allow-list, a MIME sniff, or one
signature scan. Any input crafted to satisfy that one check slips an executable payload past it.
Nine layers reasoning about nine different properties have to be defeated simultaneously.

> Senior Project II — Syrian Private University, Faculty of Artificial Intelligence Engineering,
> Intelligent Information Security Systems Engineering.
> **Ahmad Khalluof · Talal Alhelou** — supervised by Dr. Wasim Juneidi and Eng. Mohammed Yamen Hallak.

---

## Table of contents

- [The pipeline](#the-pipeline)
- [Results](#results)
- [Requirements](#requirements)
- [Setup](#setup)
- [Running](#running)
- [Configuration](#configuration)
- [API](#api)
- [Reproducing the evaluation](#reproducing-the-evaluation)
- [Project structure](#project-structure)
- [Design notes](#design-notes)
- [Limitations](#limitations)
- [Safety notice](#safety-notice)
- [References](#references)

---

## The pipeline

Every layer implements one interface, so the orchestrator can treat all nine uniformly:

```csharp
public interface IScanLayer
{
    string     Name { get; }
    ScanResult Scan(FileScanContext context);
}
```

A layer returns `Accepted`, `Rejected`, or `Sanitized`. A rejection **short-circuits** the pipeline;
a sanitization **swaps the stream**, so every later layer reads the cleaned bytes.

| # | Layer | Group | Responsibility |
|---|---|---|---|
| 1 | `ExtensionWhitelist` | Structural | Reject disallowed extensions |
| 2 | `MagicBytes` | Structural | Match leading bytes to the claimed type; pins the detected type |
| 3 | `HeaderContentMatching` | Structural | Declared `Content-Type` vs. the type detected in layer 2 |
| 4 | `DoubleExtension` | Structural | Detect double / disguised extensions |
| 5 | `SignatureScanning` | Detection | YARA scan over raw bytes (24 rules) |
| 5b | `PdfFlateDecode` | Detection | Bounded recursive stream inflation, then scan at every level |
| 5c | `EmbeddedLink` | Detection | Inspect embedded links and actions |
| 6 | `ImageReEncoding` | Transformation | Decode to pixels and rebuild; optional LSB clearing |
| 7 | `SvgSanitization` | Transformation | Strip `<script>`, `<foreignObject>`, `on*` handlers; DTD disabled |

**Ordering is security-relevant.** Cheap structural checks run first so a file already eliminated
never reaches the expensive YARA scan or the inflation layer. Layers 5, 5b and 5c are wrapped in
`CachedScanLayer`; the filename-dependent layers deliberately stay outside the cache so identical
bytes submitted under a different filename cannot inherit a cached verdict.

The cache key binds three things together:

```
layer name  |  SHA-256(content)  |  rules-file fingerprint
```

Changing a YARA rule changes the fingerprint, which invalidates every cached verdict automatically.

---

## Results

Evaluated on the full **CIC-Evasive-PDFMal2022** corpus — 10,012 files (5,549 malicious,
4,463 clean), under the severity-gated acceptance policy:

| Metric | Value |
|---|---|
| Recall | 95.48 % |
| Precision | 93.05 % |
| Accuracy | 93.54 % |
| F1 | 94.25 % |
| Specificity | 91.13 % |

Confusion matrix: TP 5,298 · FN 251 · TN 4,067 · FP 396.

> **On the two false-positive rates.** The pipeline *as implemented* refuses on any signature match
> regardless of the severity the matching rule declares, which on a corpus whose clean half was
> selected to resemble the malicious class yields a 96.0 % false-positive rate. Re-deriving the
> verdicts from the per-finding severities recorded during the run — refusing only high- and
> critical-severity findings — yields **8.87 %**, at a cost of 0.3 points of recall. That threshold
> is currently a re-analysis of the recorded results, not a code path; exposing it as a configurable
> minimum-severity acceptance level is the first planned change.

**Pixel-domain steganography.** On a 75-image sample of the Stego-Images-Dataset (15 images each of
JavaScript, HTML, PowerShell and Ethereum-address payloads, plus 15 clean controls), the LSB
clearing step neutralized **60 of 60** payload-carrying images and accepted all 15 controls.
PSNR never fell below 49.35 dB (mean 52.99 dB) — below the ~48 dB threshold of visual
imperceptibility.

---

## Requirements

| | |
|---|---|
| **.NET SDK** | 8.0 or later |
| **Node.js** | 18 or later (for the frontend) |
| **YARA** | `yara64.exe` (or `yara` on Linux/macOS) available on disk |
| **OS** | Developed and evaluated on Windows; the code is cross-platform apart from the YARA path |

NuGet packages restore automatically:

- `Magick.NET-Q8-AnyCPU` **14.15.0** — image decode / re-encode. Pinned to a patched release so the
  sanitization primitive is not itself a liability.
- `Swashbuckle.AspNetCore` 6.6.2 — Swagger UI for manual API testing during development.

---

## Setup

### 1. Install YARA

Download a YARA release and note the path to the executable. Then point `appsettings.json` at it:

```jsonc
"Yara": {
  "ExecutablePath": "C:/yara/yara64.exe",   // adjust for your machine
  "RulesFilePath":  "YaraRules/rules.yar",
  "TimeoutMs": 10000
}
```

### 2. Add the antivirus exclusion — required for correct measurement

When layer 5b inflates a PDF stream and surfaces a payload (for example the EICAR test string), it
writes that payload to a temporary file so YARA can read it. Real-time antivirus quarantines the
file before YARA opens it, YARA then fails — **and that failure looks exactly like a successful
rejection.** Measurements taken without this exclusion credit the pipeline with detections the
antivirus actually made.

All scan temporaries are routed into a single project-local folder for this reason:

```
backend/_scan_temp/
```

Exclude **only that folder** in Windows Defender (Settings → Virus & threat protection →
Exclusions → Add a folder). Leave real-time protection on everywhere else.

### 3. Restore and build

```bash
cd backend
dotnet restore
dotnet build

cd ../frontend
npm install
```

---

## Running

Two terminals:

```bash
# Terminal 1 — API on http://localhost:5170
cd backend
dotnet run --launch-profile http
```

```bash
# Terminal 2 — UI on http://localhost:5173
cd frontend
npm run dev
```

Open **http://localhost:5173**. The Vite dev server proxies `/api` to the backend, so the browser
only ever talks to one origin and CORS never comes into play in development.

Swagger UI for manual API calls: **http://localhost:5170/swagger**

---

## Configuration

All tunables live in `backend/appsettings.json` — no magic numbers are buried in code.

### `Upload`

| Key | Default | Meaning |
|---|---|---|
| `MaxFileSizeBytes` | 5242880 (5 MB) | Hard size ceiling |
| `StorageRoot` | `uploads` | Where accepted files are stored |
| `AllowedExtensions` | `.jpg .jpeg .png .webp .svg .pdf` | Layer 1 allow-list |
| `AllowedContentTypes` | matching MIME types | Layer 3 allow-list |

### `PdfDecode` — layer 5b

| Key | Default | Meaning |
|---|---|---|
| `MaxDecodeDepth` | 4 | How many times inflation may be re-applied to its own output |
| `MaxExpansionRatio` | 1500 | Expansion beyond this **refuses** the file (decompression-bomb indicator) |
| `MaxBytesPerStream` | 10 MB | Truncates and keeps scanning — not an attack indicator on its own |
| `MaxTotalBytes` | 50 MB | Ceiling across all streams of one PDF |

Only the expansion ratio produces a refusal. The byte caps bound resource use; reaching one
truncates the content and lets the scan continue, because a large legitimate stream is plausible.

### `ReEncoding` — layer 6

| Key | Default | Meaning |
|---|---|---|
| `MaxWidth` / `MaxHeight` | 10000 | Header-only checks, applied **before** any pixel is decoded |
| `MaxTotalPixels` | 40,000,000 | The real bomb cap — pixel count drives decode memory, not file size |
| `JpegQuality` | 90 | Visually near-lossless while still forcing full re-quantization |
| `StripMetadata` | `true` | Remove EXIF / XMP / IPTC / ICC / comments |
| `ClearLeastSignificantBit` | `true` | Zero bit 0 of every RGB channel (destroys pixel-domain LSB stego) |
| `MagickMemoryLimitMb` | 256 | Library-level ceiling, applied at startup as a backstop |

`StripMetadata` and `ClearLeastSignificantBit` are switches so the ablation study can measure
re-encoding with and without each.

### `Cache`

| Key | Default |
|---|---|
| `Enabled` | `true` |
| `MaxEntries` | 10000 |
| `TtlMinutes` | 60 |

Bounded by `SizeLimit` + per-entry size, so a flood of unique uploads cannot exhaust memory.

### `Demo`

`Demo:Enabled` is a **server-side** switch. It controls whether internal reasoning (rejection
reasons, per-layer evidence) leaves the process at all, and whether the comparison and corpus
endpoints exist. Turn it **off** for anything resembling a real deployment — rejection reasons are
always logged server-side, never returned to the client.

---

## API

Base path `/api`. Valid `category` values: `profile`, `id`.

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/upload` | Submit a file. Form fields: `file`, `category`. |
| `GET` | `/api/files` | List stored files |
| `GET` | `/api/files/{category}/{name}` | Fetch a stored file |
| `GET` | `/api/demo-status` | Whether demo mode is on |
| `POST` | `/api/compare` | Run one file through all six validators *(demo mode only)* |
| `GET` | `/api/corpus/status` | Corpus configuration and readiness *(demo mode only)* |
| `POST` | `/api/corpus/run?category=` | Run the full corpus, stream results to CSV *(demo mode only)* |

`POST /api/upload` returns `422 Unprocessable Entity` when a layer rejects the file. Accepted files
are stored under a **random** name — the submitted filename never reaches the filesystem, which
removes path traversal and overwrite of host files as a concern.

---

## Reproducing the evaluation

### Aggregate metrics

1. Set `Demo:CorpusRoot` to the corpus directory and `Demo:Enabled` to `true`.
2. `POST /api/corpus/run?category=profile`

Scanners run **sequentially** so their timings stay meaningful; a full corpus takes minutes. The CSV
is flushed as it goes, so an interrupted run still leaves usable rows.

Columns:

```
file, relative_path, sha256, size_bytes, truth, category, scanner, accepted,
content_rewritten, is_scanner_error, is_test_only, is_neutralized,
stopped_at_layer, reason_code, top_severity, layers_run, from_cache,
elapsed_ms, stored_size, reason
```

Two columns carry most of the analytical weight:

- **`top_severity`** — the highest severity among the findings for that file, taken from the rule
  that produced each one. This is what makes the severity-gated re-derivation reproducible from the
  results file alone.
- **`reason_code`** — `UNCODED` means the file passed all nine layers without any layer reaching a
  stopping condition, as opposed to being lost to a scanner error or a truncated inspection. This is
  how a genuine false negative is distinguished from a measurement failure.

### Adversarial comparison

`POST /api/compare` runs a single file through six validators under identical conditions: the four
DVWA reference levels re-implemented in C# from their documented logic, a baseline validator, and
the full layered pipeline. Adversarial fixtures were generated with
[Mitra](https://github.com/corkami/mitra).

The layers implement `IScanLayer`; the six comparators implement a separate interface,
`IFileScanner`. That separation is what lets the harness hand identical bytes to the pipeline and to
a flat reference validator while keeping the pipeline's internal composition invisible to it.

---

## Project structure

```
backend/
├── Scanning/                     the pipeline
│   ├── IScanLayer.cs             the one interface every layer implements
│   ├── ScanResult.cs             Accepted | Rejected | Sanitized + ScanEvidence
│   ├── FileScanContext.cs        stream, filename, declared + detected type, trace
│   ├── SecureUploadScanner.cs    the orchestrator (fail-fast, stream-swap, timing)
│   ├── CachedScanLayer.cs        three-part cache key
│   ├── ExtensionWhitelistLayer.cs
│   ├── MagicBytesLayer.cs
│   ├── HeaderContentMatchingLayer.cs
│   ├── DoubleExtensionLayer.cs
│   ├── SignatureScanningLayer.cs
│   ├── PdfFlateDecodeLayer.cs
│   ├── EmbeddedLinkLayer.cs
│   ├── ImageReEncodingLayer.cs
│   ├── SvgSanitizationLayer.cs
│   ├── YaraRunner.cs             external-process wrapper
│   └── ScanTempDirectory.cs      routes temporaries into _scan_temp
├── Services/                     evaluation harness
│   ├── IFileScanner.cs           scanner-level interface (comparison only)
│   ├── StaticAnalysisScanner.cs  the pipeline, as one comparator
│   ├── BasicValidationScanner.cs baseline
│   ├── DvwaScanners.cs           four DVWA reference levels
│   ├── ComparisonOrchestrator.cs
│   └── CorpusRunner.cs           corpus run → CSV
├── Controllers/                  Upload, Comparison, Corpus
├── Middleware/                   SecurityHeadersMiddleware
├── Models/                       strongly-typed options + response shapes
├── YaraRules/rules.yar           24 rules
└── appsettings.json

frontend/
└── src/
    ├── App.jsx
    ├── api.js
    └── components/
        ├── UploadCard.jsx        submit a file
        ├── PipelineRail.jsx      per-layer trace, live
        └── ComparePanel.jsx      six validators side by side
```

---

## Design notes

**Evidence, not assertions.** A rejection reason states the *conclusion*; `ScanEvidence` states the
*observations* it rests on — rule name, matched string, byte offset, nesting depth, severity, and an
external reference (CVE / CWE / ATT&CK). Without it a layer can only assert "this file is bad"; with
it, a verdict can be checked rather than trusted.

**Rejections are policy outcomes, not verdicts of malice.** A static filter cannot prove a payload
is malicious — that needs dynamic execution or semantic analysis, both out of scope for an upload
gate. What the pipeline *can* establish is one of three things: a known-bad indicator, a dangerous
capability, or a structural anomaly. Keeping that distinction is what makes the reported
false-positive rate meaningful.

**Fail-closed is not fail-fast.** *Fail-fast* is the performance property: the first rejection stops
the pipeline. *Fail-closed* is the security property: when a layer cannot reach a judgement — layer 3
finding that layer 2 never ran, for instance — it refuses. Exhausting the bounded inflation depth of
layer 5b is explicitly **not** treated as a refusal, because a legitimately deep filter chain exists.

**Format is pinned, never guessed.** Layer 6 decodes with the format detected by layer 2, so the
decoder is never permitted to infer a type from content it has already been lied to about.

**Neutralization is unconditional.** Every accepted raster image is rebuilt from its pixels, clean or
not. Rewriting only *suspicious* files would reintroduce the question "what is suspicious?" — the
detection problem that neutralization exists to sidestep. It works precisely because it does not
depend on recognizing the payload.

**Why `& 0xFE` and not posterization.** The LSB step originally used a posterize operator, which
*rounds* each channel to the nearest of a reduced set of levels — and rounding can leave bit 0 set on
bright pixels. It failed to neutralize one image in testing while succeeding on the rest by
coincidence. A bitwise-AND with `0xFE` clears bit 0 on every channel of every pixel without
exception. A neutralization guarantee has to be deterministic.

**YARA runs out-of-process.** An in-process binding would be faster, but it would hand
attacker-controlled bytes to native code inside the web server. A crash on a malformed file would
take the server down with it — turning a scan failure into a denial of service. The separate process
contains the crash, and the 10-second timeout turns a hang into a controlled failure.

---

## Limitations

- **The severity threshold is not implemented.** It is specified as a policy and re-derived from
  recorded severities; the shipped pipeline refuses on any signature match.
- **Transform-domain steganography is not addressed.** Clearing a spatial-domain least-significant
  bit does nothing to data hidden in the quantized DCT coefficients of a JPEG. The LSB result is
  scoped to the **lossless raster pixel domain**.
- **Encrypted PDFs cannot be scanned**, and the pipeline fails closed on them. They dominate the
  residual false positives under the gated policy.
- **Signature-and-structure has a known ceiling.** The 251 missed files carry indicators outside the
  current rule set and are not exposed by inflation. This is the expected failure mode of an
  approach with no learned component: it catches what its rules and structural checks describe.
- **No ablation study yet.** The switches exist (`StripMetadata`, `ClearLeastSignificantBit`); the
  per-layer contribution study is future work.

---

## Safety notice

The evaluation corpora contain **live malware**. Run corpus evaluation only inside an isolated
environment. Do not enable `Demo` mode on a network-reachable host. Accepted uploads are stored under
random names, but the storage directory should still be treated as untrusted and must never be served
from a web-executable path.

---

## References

- Issakhani, M. et al. *PDF Malware Detection Based on Stacking Learning* (CIC-Evasive-PDFMal2022), ICISSP 2022
- Cassavia, N., Caviglione, L., Guarascio, M., Manco, G., Zuppelli, M. — Stego-Images-Dataset, JOWUA 13(3), 2022
- Neef, S. & Oudeh, M. *FUEL: A Framework for Evaluating File-Upload Vulnerabilities*, DIMVA 2024
- Koch, S. et al. *On the Abuse and Detection of Polyglot Files*, WWW 2025
- Albertini, A. — [Mitra](https://github.com/corkami/mitra) and the Corkami file-format studies
- MITRE — CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-79, CWE-409
- OWASP — File Upload Cheat Sheet; ASVS V7 (logging rejection reasons server-side only)
