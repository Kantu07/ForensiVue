# Comparative Analysis of DVR/NVR OEMs

**Read this first.** Most DVR/NVR vendors do not publish their file-system or container formats. The table below is compiled from general industry knowledge and public forensic discussion. Every claim carries a status:

- **Reported**: widely reported in public forensic or industry sources, but **not verified by this project** against real devices.
- **Likely**: plausible from market structure, **unconfirmed**.
- **Unknown**: no reliable information available to the authors.

Nothing here was validated on physical hardware. Before citing any item in an official report, verify it against the specific model and firmware under examination.

## 1. Summary table

| OEM | Origin / market | Storage and file system | Typical codecs | Timestamp handling | OEM relationships |
|---|---|---|---|---|---|
| **Hikvision** | China, global | Proprietary file system (commonly called HIKVISION / HIKBTREE in forensic literature), data in proprietary blocks. *Reported* | H.264, H.265 (H.264+/H.265+). *Reported* | Device-local time, often stored as epoch values in index. *Likely*; verify per firmware | Own platform; its firmware is widely rebranded by other vendors. *Reported* |
| **Dahua** | China, global | Proprietary file system (DHFS family) and .dav-style container discussed publicly. *Reported* | H.264, H.265. *Reported* | Device-local time; DST and timezone settings can shift stored times. *Likely* | Own platform; widely OEM'd to rebrands. *Reported* |
| **CP Plus** | India (Aditya Infotech), major Indian market share | Often Dahua-derived firmware on many models. *Reported*; model-dependent | H.264, H.265. *Likely* | As Dahua if rebranded. *Likely* | Frequently described as Dahua-based on many lines. *Reported*; not universal |
| **Honeywell Security** | US brand; hardware sourced from multiple suppliers | Varies by product line; some lines resemble Hikvision- or Dahua-based platforms. *Likely*; **verify per model** | H.264, H.265. *Likely* | Unknown | Mixed OEM sourcing. *Likely* |
| **TP-Link (VIGI / Tapo NVRs)** | China, consumer and SMB | Proprietary or Linux-based storage; format details not well documented. *Unknown* | H.264, H.265. *Likely* | Unknown | Unknown |
| **Uniview (UNV)** | China, global | Proprietary storage and container. *Reported* as distinct from Hikvision and Dahua | H.264, H.265, with Ultra codecs on some lines. *Likely* | Unknown | Own platform; some rebranding. *Likely* |
| **Godrej** | India (Godrej Security Solutions) | Unknown; Indian-market brands commonly use OEM hardware. *Unknown*; **verify per model** | H.264, H.265. *Likely* | Unknown | Likely OEM-sourced. *Unconfirmed* |
| **Matrix (Matrix Comsec)** | India, designs own security products | Proprietary. *Unknown* detail | H.264, H.265. *Likely* | Unknown | Own design. *Likely* |

## 2. Cross-vendor challenges

1. **Closed formats.** Index structures, block layouts and checksums are undocumented for most vendors; analysis relies on reverse engineering per model.
2. **Rebranding.** A "CP Plus" or "Honeywell" device may run Hikvision- or Dahua-derived firmware, so vendor label alone does not identify the file system. Identification must be evidence-based (signatures, structures), not label-based.
3. **Timestamps.** Local-time storage, missing timezone information, DST changes and clock drift make cross-camera and cross-vendor correlation unreliable without normalization and documented offsets.
4. **Overwriting.** DVRs record in circular fashion; deleted or overwritten footage recovery depends on index retention and fragmentation.
5. **Encryption.** Some firmware offers disk encryption or signed exports, which can block acquisition.
6. **Codec variants.** Smart codecs (H.264+/H.265+) and proprietary wrappers can break generic carving.

## 3. What ForensiVue assumes

- Hikvision-style and Dahua-style parsers target **synthetic layouts we designed**, not the real structures above.
- Uniview-style parser is likewise synthetic.
- Other vendors (TP-Link, Godrej, Matrix, Honeywell, CP Plus) are covered only by:
  - the YAML signature entries (**placeholders**), and
  - the **generic H.264 carving fallback**, which is vendor-agnostic.
- Supporting a real vendor requires: real sample disks, documented structures, a new plugin (see `PLUGIN_TEMPLATE.md`), and validation.

## 4. Suggested next steps for real-device support

1. Acquire a lab disk from each target model with known recorded content.
2. Document header, index and block structure with hex analysis.
3. Confirm timestamp epoch and timezone behavior with known recording times.
4. Implement a plugin, then validate recovery against ground truth.
5. Cite public research papers (verify before citing; this document does not provide verified references).
