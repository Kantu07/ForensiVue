# Standard Operating Procedures

These SOPs are structured with reference to the principles of ISO/IEC 27037 (identification, collection, acquisition and preservation of digital evidence) and general SWGDE guidance on digital and multimedia evidence. They are a **working draft for this prototype**; they have not been audited for compliance with either standard. Adapt them to your laboratory's accreditation requirements.

Scope reminder: the tool is validated only on synthetic images (see `VALIDATION_REPORT.md`).

---

## SOP-1: Evidence Acquisition

**Purpose:** Create a verified, read-only forensic image of DVR/NVR storage.

**Before you start**
1. Record case ID, examiner, date/time, location and device details (make, model, serial, label, condition).
2. Photograph the device and storage media where possible.
3. Note the DVR clock versus real time (see SOP-2, step 4) before powering down if the device is live.

**Procedure**
1. Remove the disk from the DVR where permissible; do not power on the original recorder with the evidence disk unless required and documented.
2. Connect the disk through a **hardware write-blocker**. Record the write-blocker make and model.
3. Run acquisition: `python -m forensivue.cli acquire --source <device or image> --case <ID> --examiner "<name>"`.
4. Confirm the tool reports MD5 and SHA-256 and the re-verification result.
5. Record the hashes on the evidence form independently of the tool.
6. Store the original in sealed, labeled packaging; work only on the image.
7. Check the audit log shows acquisition start, hashing and verification entries.

**Failure handling:** If verification fails, repeat acquisition and document the failure. Bad sectors must be logged in the error map, never silently skipped.

**Records:** acquisition JSON, hashes, write-blocker details, audit log.

---

## SOP-2: Analysis and Recovery

**Purpose:** Identify the device structure, list recordings, recover deleted footage and build a timeline.

**Procedure**
1. Open the dashboard (`python -m forensivue.cli serve`) or use the CLI. Enter case ID and examiner.
2. **Identify:** run device identification. Review the vendor and confidence. Treat low confidence or "unknown" as unrecognized; do not force a match.
3. **Parse:** review listed recordings, with status (active or deleted) and normalized UTC times.
4. **Timestamp check:** compare the DVR's displayed time (recorded at seizure) with real time. Record any offset. Apply a manual offset only if justified; it is logged in the audit trail.
5. **Recover:** run index recovery and carving. Review each artifact's method, confidence, SHA-256 and path.
6. Treat carved clips as **leads until validated**. Recovered clips flagged damaged or partial must not be described as intact.
7. **Timeline:** build the unified timeline and review correlation between channels.
8. Export or play recovered clips only from the recovered output folder, never from the evidence image.

**Quality checks**
- Re-run the same image and confirm identical hashes and results (reproducibility).
- Run `pytest` after any tool update and record the result.

**Interpretation cautions:** spurious carved clips can occur; interleaved multi-channel data may not be separated by carving; synthetic validation does not demonstrate performance on real devices.

---

## SOP-3: Reporting and Verification

**Purpose:** Produce a defensible report and verify record integrity.

**Procedure**
1. In the Report step (or via `forensivue report`), generate the PDF and HTML report.
2. Check the report contains: case info, examiner, tool version, source and hashes, device identification, recordings and recovered items, timeline, custody verification result, limitations.
3. Verify that the hashes in the report match the hashes you recorded in SOP-1.
4. Run **Verify Integrity** on the custody log; record the result. If it reports tampering, stop, preserve the log and escalate.
5. Review the limitations section; add case-specific limitations (device quirks, clock offset, damaged sectors).
6. Examiner reviews and signs the report. Second-person review is recommended.
7. Archive: image (with hashes), recovered items, reports, audit log, acquisition record.

**Records retention:** per your organization's policy.

---

## Appendix: Evidence log fields

Case ID, item ID, description, make/model/serial, acquired by, date/time, write-blocker, image path, MD5, SHA-256, verification result, storage location, transfers (who, when, why).
