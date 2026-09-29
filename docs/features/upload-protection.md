# File Upload Protection

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF inspects file uploads for malicious content, preventing malware uploads and file-based attacks.

## Configuration

```yaml
rules:
  - id: UPLOAD-001
    name: File Upload Validation
    enabled: true
    severity: high
    action: block
    phase: access
    field: request.headers.content-type
    operator: contains
    value: "multipart/form-data"
    params:
      max_file_size: 10485760        # 10 MB
      allowed_types:
        - image/jpeg
        - image/png
        - image/gif
        - application/pdf
        - text/plain
      blocked_types:
        - application/x-msdownload
        - application/x-msdos-program
        - application/x-sh
        - application/x-sharedlib
      scan_content: true              # Content-based detection
      max_files: 5                    # Max files per request
```

## Inspection Features

### File Type Validation

Validates uploaded files against both declared Content-Type and magic bytes:

```yaml
params:
  allowed_types:
    - image/jpeg
    - image/png
  mismatch_action: block    # Block if declared type != actual type
```

### File Size Enforcement

```yaml
params:
  max_file_size: 5242880    # 5 MB per file
  max_total_size: 20971520   # 20 MB total per request
```

### Content Scanning

Scans file content for dangerous patterns:

- Embedded scripts in images (polyglot files)
- Executable headers (MZ, ELF)
- Shell script signatures
- Encoded payloads (base64, gzip)
- Suspicious metadata (EXIF, comments)

## Security Rules

### Block Dangerous File Types

```yaml
rules:
  - id: UPLOAD-002
    name: Block Executable Files
    enabled: true
    severity: critical
    action: block
    field: request.files.content_type
    operator: regex
    value: "application/(x-msdownload|x-msdos-program|x-sharedlib|x-executable)"
```

### Image Sanitization

```yaml
- id: UPLOAD-003
  name: Image Upload Validation
  enabled: true
  severity: high
  action: block
  field: request.files.content_type
  operator: prefix
  value: "image/"
  params:
    reencode: true            # Re-encode images to remove embedded content
    strip_metadata: true      # Remove EXIF data
    max_dimensions:
      width: 4096
      height: 4096
    min_dimensions:
      width: 32
      height: 32
```

## Common Attack Patterns

| Attack | Detection |
|--------|-----------|
| Polyglot files (JS in image) | Byte pattern analysis |
| File extension spoofing | MIME vs extension mismatch |
| ZIP bombs | Size ratio analysis |
| SVG with embedded scripts | XML parsing + script detection |
| Double extensions | Filename pattern check |
| Null byte injection | Filename validation |

## Best Practices

- Always validate both MIME type and magic bytes
- Set realistic file size limits per use case
- Use content scanning for image uploads
- Re-encode uploaded images to strip embedded content
- Store uploads outside the web root
- Scan with antivirus if available
- Log all upload attempts for auditing
