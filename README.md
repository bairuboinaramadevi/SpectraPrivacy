# PDF PII Processing Workflow

This project provides a robust, agent-based workflow for detecting, redacting, masking, anonymizing, encrypting, and highlighting Personally Identifiable Information (PII) in PDF documents.

## Features
- **Batch processing**: Handles all PDFs in a folder.
- **PII detection**: Uses Presidio Analyzer with spaCy for efficient PII detection.
- **Redaction, masking, anonymization, encryption, highlighting**: Each step produces a new PDF in a dedicated output folder.
- **Seamless, restartable workflow**: Designed for robust, repeatable runs.

## Setup
1. **Clone the repository** and navigate to the project folder.
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Prepare your PDFs**:
   - Place input PDFs in `NasscomData/StructuredDataPDF/RawData/`.

## Usage
Run the main workflow:
```bash
python execute.py
```

- Processed PDFs will be saved in:
  - `RedactedData/` (redacted)
  - `MaskedData/` (masked)
  - `AnonymizedData/` (anonymized)
  - `EncryptedData/` (encrypted)
  - `HighlightedData/` (highlighted)

## Requirements
See `requirements.txt` for all dependencies.

## Notes
- The workflow is fully automated and does not require manual intervention.
- Only the PDF/PII agent workflow is supported; all legacy database code has been removed.

## Troubleshooting
- Ensure all dependencies are installed.
- Input PDFs must be valid and readable.
- For spaCy/Presidio errors, ensure the `en_core_web_sm` model is available.

---
MIT License
