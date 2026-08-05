# Secure Upload Portal — Phase 1 Testbed

The web application for the project **"Design and Implementation of an XSS Filter
for Web Systems."** This is the Phase 1 deliverable: a working site with two file
upload entry points (a profile photo field and an ID document field), a React
front-end, and an ASP.NET Core Web API back-end.

The back-end runs every upload through a single `IFileScanner`. Right now that is
a deliberately **weak baseline validator** (extension + size + client-declared
content-type only). In Phase 3 you replace it with your static-analysis filter
without touching the rest of the app.

---

## Prerequisites

- **.NET SDK 8.0+** — <https://dotnet.microsoft.com/download> (`dotnet --version`)
- **Node.js 18+** and npm — <https://nodejs.org> (`node --version`)

---

## Project structure

```
webapp/
├── backend/                 ASP.NET Core Web API (.NET 8)
│   ├── Program.cs           app setup, CORS, DI — the filter is registered here
│   ├── Controllers/
│   │   └── UploadController.cs     POST /api/upload, GET /api/files[...]
│   ├── Services/
│   │   ├── IFileScanner.cs         the inspection seam (Phase 3 plugs in here)
│   │   └── BasicValidationScanner.cs   the weak Phase 1 baseline
│   ├── Models/              request/response + options types
│   ├── appsettings.json     upload limits & allow-lists
│   └── uploads/             stored files (created at runtime, git-ignored)
└── frontend/                React + Vite
    ├── vite.config.js       dev server + /api proxy to the backend
    └── src/
        ├── App.jsx          the two upload cards + stored-files list
        ├── components/UploadCard.jsx
        └── api.js           fetch helpers
```

---

## Running it (two terminals)

### 1. Back-end

```bash
cd backend
dotnet restore
dotnet run --launch-profile http
```

This serves the API at **http://localhost:5170** (Swagger UI at
http://localhost:5170/swagger while in Development).

### 2. Front-end

```bash
cd frontend
npm.cmd run dev
```

Open **http://localhost:5173**. The Vite dev server proxies every `/api` request
to the back-end, so there are no CORS issues. (If you change the back-end port,
update the `target` in `frontend/vite.config.js`.)

---

## API summary

| Method | Route                          | Purpose                                  |
|--------|--------------------------------|------------------------------------------|
| POST   | `/api/upload`                  | Upload one file. Form fields: `file`, `category` (`profile` or `id`). |
| GET    | `/api/files`                   | List stored files.                       |
| GET    | `/api/files/{category}/{name}` | Serve a stored file.                     |

A successful upload returns `200` with `accepted: true`; a file the baseline
rejects returns `422` with `accepted: false` and the reason. The front-end shows
both, along with the individual checks the scanner ran.

---

## Why the baseline is intentionally weak

This Phase 1 build validates uploads using only the file extension, the size, and
the **client-supplied** `Content-Type` — the same checks DVWA's Medium/High
levels rely on, and the same ones real attackers bypass. The app also serves
stored files **inline**, which is what makes a stored-XSS demonstration (e.g. a
script-bearing SVG) possible. This is on purpose: it is the measurable "before"
state for the Phase 4 baseline testing.

What it deliberately does **not** do yet (this is the Phase 3 filter's job):

- verify a file's real type from its magic bytes / content,
- scan content for embedded scripts, `<?php`, `javascript:`, event handlers, etc.,
- sanitize or block script-bearing SVG/XML,
- serve files with `Content-Disposition: attachment` + a strict CSP.

## Adding the Phase 3 filter later

1. Create `Services/StaticAnalysisScanner.cs` implementing `IFileScanner`
   (add your magic-byte, content-scan, SVG, and heuristic layers).
2. In `Program.cs`, change the registration:
   ```csharp
   builder.Services.AddScoped<IFileScanner, StaticAnalysisScanner>();
   ```
   (or register a composite scanner that runs the baseline first, then yours).

Nothing in the controller or the front-end changes — that is the point of the seam.

> ⚠ Run all attack testing inside an isolated lab environment, never against a
> machine with a route to production systems or the public internet.
