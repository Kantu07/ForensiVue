# ForensiVue System Architecture

## 1. Overview

ForensiVue is a Python engine with a CLI and a local web dashboard. Vendor knowledge lives in plugins; everything else (hashing, custody, timeline, recovery, reporting) is vendor-independent.

## 2. Component diagram

```mermaid
flowchart TD
    UI[Web Dashboard<br/>FastAPI + HTML/JS] --> API[FastAPI endpoints]
    CLI[CLI<br/>acquire / timeline / report / serve] --> CORE
    API --> CORE

    subgraph CORE[Core Engine]
        ACQ[Acquisition<br/>read-only, MD5+SHA-256]
        DID[Device ID<br/>YAML signatures]
        REG[Plugin Registry]
        REC[Recovery<br/>index + carving]
        TL[Timeline<br/>UTC normalization]
        RPT[Reporting<br/>PDF + HTML]
    end

    DID --> REG
    REG --> P1[Hikvision-style parser]
    REG --> P2[Dahua-style parser]
    REG --> P3[Uniview-style parser]
    REG --> P4[Generic fallback]

    ACQ --> AUD[(Hash-chained audit log)]
    DID --> AUD
    REG --> AUD
    REC --> AUD
    TL --> AUD
    RPT --> AUD
    ACQ --> IMG[(Evidence image .dd - read only)]
    REC --> OUT[(recovered/ clips + hashes)]
    RPT --> REP[(reports/ PDF + HTML)]
```

## 3. Data flow

```mermaid
sequenceDiagram
    participant E as Examiner
    participant T as ForensiVue
    participant A as Audit Log
    E->>T: Select image, enter case + examiner
    T->>A: ACQUISITION_START
    T->>T: Hash image (MD5, SHA-256), verify
    T->>T: Identify vendor (signatures)
    T->>A: IDENTIFY_DEVICE_COMPLETE
    T->>T: Parse index via plugin
    T->>T: Index recovery + signature carving
    T->>T: ffprobe validation + hashing of clips
    T->>T: Normalize timestamps, build timeline
    T->>T: Generate PDF/HTML report
    T->>A: REPORT_GENERATED
    E->>T: Verify Integrity
    T->>A: Recompute chain
    T-->>E: Chain Verified / Tamper detected
```

## 4. Plugin interface

`BaseVendorParser` defines: `identify()`, `parse_filesystem()`, `list_recordings()`, `extract_video()`, `extract_metadata()`. Plugins in `forensivue/fs_parsers/` are auto-discovered by the registry. See `PLUGIN_TEMPLATE.md`.

Data models: `Recording`, `Channel`, `EvidenceItem`.

## 5. Chain of custody

Each audit entry stores timestamp, action, details and `previous_hash`. The entry hash covers the previous hash, so editing or deleting any entry breaks every later link. `verify_chain()` recomputes the chain and reports the first broken entry.

## 6. Design rules

1. Read-only evidence access.
2. Every action logged.
3. Hashes at acquisition and for every extracted item.
4. UTC timestamps with raw values retained.
5. Never fabricate results.
6. Offline operation (no external CDNs or network calls).

## 7. Technology

Python 3.11+, FastAPI/Uvicorn, SQLite-free JSONL audit log, FFmpeg/ffprobe, ReportLab, pytest.

## 8. Not implemented

AI analytics (motion, object, face detection) and real-vendor file-system parsers. The plugin and recovery layers are designed so these can be added.
