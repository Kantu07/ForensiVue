# ForensiVue Rules

- **Python 3.11+**
- **Evidence Access**: All evidence access must be READ-ONLY. Never write to source images.
- **Audit Logger**: Every action must be logged through the hash-chained audit logger (chain of custody).
- **File Extraction**: MD5 and SHA-256 hashes computed on every extracted file at acquisition and verification.
- **Timestamps**: Stored as UTC ISO-8601 with the original raw value and detected timezone offset kept.
- **Accuracy**: Never fabricate results; report "unrecognized" when parsing fails.
- **Code Quality**: Include type hints, docstrings, and pytest tests for every module.
- **Synthetics Disclaimer**: The testing layouts used in `fs_parsers/` (like Hikvision, Dahua) are **SYNTHETIC assumptions** created for testing. They are NOT verified proprietary vendor formats, which remain closed-source.
