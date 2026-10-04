# ForensiVue User Manual

> All bundled test images are **synthetic**. The dashboard shows a SYNTHETIC DATA warning banner.

## 1. Installation

1. Install Python 3.11+ and FFmpeg (ensure `ffmpeg -version` works in a terminal).
2. In the project folder:
   ```
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r requirements.txt
   ```
   Also install the phase requirement files if present (`requirements_phase3.txt`, `phase4`, `phase9`, `phase10`).
3. Generate test images: `python -m forensivue.testing.generate_suite`
4. Run tests: `pytest -v`

## 2. Starting the dashboard

```
python -m forensivue.cli serve
```
Wait for `Uvicorn running on http://127.0.0.1:8000`, then open **http://127.0.0.1:8000** in a browser. Keep the terminal open; press **Ctrl+C** in it to stop. Use a second terminal for other commands.

## 3. Dashboard workflow

| Step | What to do | What you see |
|---|---|---|
| 1. Case Info | Enter Case ID and Examiner Name; click **Initialize Workspace** | Case saved for reports |
| 2. Acquire | Choose a source image; click **Read Image Properties** | MD5 and SHA-256 of the image |
| 3. Identify & Parse | Click **Execute Parser** | Vendor, confidence bar, list of recordings with status |
| 4. Recover | Click **Initiate Carving & Index Recovery** | Recovered artifacts: method, confidence, SHA-256, path |
| 5. Timeline | Click **Construct Timeline** | Channel bars scaled to start/end times |
| 6. Report | Generate the report | PDF/HTML saved under `reports/<case>/` with a download link |
| 7. Custody Log | Click **Verify Integrity** | Green "Chain Verified" shield, or a red alert if tampering is detected |

Suggested test images: `normal.dd` (simple), `deleted.dd` (recovery), `fragmented.dd` (carving), `damaged.dd` (corruption), `multi_channel.dd` (timeline), `mixed.dd` (Dahua-style).

## 4. Command line

```
python -m forensivue.cli acquire --source <image or device> --case <ID> --examiner "<name>"
python -m forensivue.cli timeline --source <image> --table
python -m forensivue.cli report --source <image> --case <ID> --examiner "<name>" --out reports\<ID>
python -m forensivue.cli serve [--host 127.0.0.1] [--port 8000]
```

## 5. Reading the results

- **Confidence:** a signature-match score, not proof. Treat low scores or "unknown" as unrecognized.
- **Active / deleted:** deleted entries are index entries marked free that still point to data.
- **Recovery method:** `index` follows the index table; `carve` scans for H.264 start codes.
- **Carved clips** may have unknown times and can include spurious outputs. Verify before relying on them.
- **Damaged:** the clip recovered with corruption; it is never reported as intact.

## 6. Custody log and tamper detection

All actions are logged to `audit.jsonl`, each entry linked to the previous one by hash. **Verify Integrity** recomputes the chain. If any earlier entry was edited or removed, verification fails and the shield turns red.

## 7. Files the tool creates

| Path | Contents |
|---|---|
| `generated/` | Synthetic images and ground-truth JSON files |
| `recovered/<image>/` | Recovered clips |
| `reports/<case>/` | PDF and HTML reports |
| `audit.jsonl` | Hash-chained audit log |
| `custody.csv`, `custody.pdf` | Custody exports |

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Browser says "refused to connect" | The server is not running; start it and use 127.0.0.1:8000 |
| Server stops by itself | Something was typed or pasted into its window; restart and leave it alone |
| `ffmpeg` not recognized | Install FFmpeg and add it to PATH |
| `No module named ...` | Activate the venv and reinstall requirements |
| Image list is empty | Run `python -m forensivue.testing.generate_suite` |
| Verify Integrity shows red unexpectedly | `audit.jsonl` was edited; keep a copy for review, then start a fresh log |

## 9. Adding a vendor

See `PLUGIN_TEMPLATE.md`: add a parser class in `forensivue/fs_parsers/` and signature entries in the YAML file. Mark signatures as confirmed or placeholder.
