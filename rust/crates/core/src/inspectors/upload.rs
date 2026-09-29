//! File upload security: size limits, MIME/magic verification, executable and
//! archive detection, image polyglots.
//!
//! Port of `internal/engine/upload.go`. Signatures, rule IDs, scores and check
//! order are preserved exactly.
//!
//! ## Deviation (documented)
//!
//! Go used `mime/multipart` to iterate parts. This port includes a minimal
//! multipart reader sufficient for the fields the inspector reads (part
//! filename from Content-Disposition, the part's own Content-Type header, and
//! the first 512 bytes of content). It follows RFC 2046 framing
//! (`--boundary` delimiters, CRLF or LF), matching how `mime/multipart` splits
//! parts. See `rust/DEVIATIONS.md`.

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

static SCRIPT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:<script|<svg|onerror|onload|javascript:|<\?php|<\?xml)").unwrap()
});

fn mime_signatures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("image/jpeg", vec![0xFF, 0xD8, 0xFF]),
        ("image/png", vec![0x89, 0x50, 0x4E, 0x47]),
        ("image/gif", vec![0x47, 0x49, 0x46, 0x38]),
        ("image/webp", vec![0x52, 0x49, 0x46, 0x46]),
        ("image/tiff", vec![0x49, 0x49, 0x2A, 0x00]),
        ("image/bmp", vec![0x42, 0x4D]),
        ("application/pdf", vec![0x25, 0x50, 0x44, 0x46]),
        ("application/zip", vec![0x50, 0x4B, 0x03, 0x04]),
        ("application/gzip", vec![0x1F, 0x8B]),
        ("application/x-bzip2", vec![0x42, 0x5A]),
        ("application/x-xz", vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
        ("text/plain", vec![]),
        ("text/csv", vec![]),
        ("application/json", vec![]),
        ("application/xml", vec![]),
        ("application/octet-stream", vec![]),
    ]
}

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".so", ".dylib", ".bin", ".bat", ".cmd", ".com", ".msi", ".scr", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1", ".msh", ".sh",
    ".bash", ".zsh", ".ksh", ".csh",
];

const ARCHIVE_EXTENSIONS: &[&str] = &[
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tgz", ".tbz2", ".zst", ".lz", ".lzma",
    ".lzo",
];

const IMAGE_EXTENSIONS: &[&str] = &[
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".tif", ".svg", ".ico", ".heic",
    ".heif",
];

fn executable_magic() -> Vec<Vec<u8>> {
    vec![
        vec![0x7F, 0x45, 0x4C, 0x46],
        vec![0x4D, 0x5A],
        vec![0xCA, 0xFE, 0xBA, 0xBE],
        vec![0xCF, 0xFA, 0xED, 0xFE],
        vec![0xCE, 0xFA, 0xED, 0xFE],
        vec![0xFE, 0xED, 0xFA, 0xCE],
        vec![0xFE, 0xED, 0xFA, 0xCF],
        vec![0x23, 0x21],
    ]
}

fn archive_magic() -> Vec<Vec<u8>> {
    vec![
        vec![0x50, 0x4B, 0x03, 0x04],
        vec![0x1F, 0x8B],
        vec![0x42, 0x5A],
        vec![0xFD, 0x37, 0x7A, 0x58, 0x5A],
        vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
        vec![0x75, 0x73, 0x74, 0x61, 0x72],
    ]
}

pub struct FileUploadSecurity {
    pub dev_mode: bool,
    max_file_size: i64,
    per_endpoint_limits: Arc<RwLock<HashMap<String, i64>>>,
}

impl FileUploadSecurity {
    pub fn new(dev_mode: bool) -> Self {
        FileUploadSecurity {
            dev_mode,
            max_file_size: 10 * 1024 * 1024,
            per_endpoint_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn get_endpoint_limit(&self, path: &str) -> i64 {
        let limits = self.per_endpoint_limits.read();
        limits.get(path).copied().unwrap_or(self.max_file_size)
    }

    /// Port of `SetEndpointLimit`.
    pub fn set_endpoint_limit(&self, path: &str, limit: i64) {
        self.per_endpoint_limits
            .write()
            .insert(path.to_string(), limit);
    }

    fn inspect_part(
        &self,
        filename: &str,
        part_content_type: &str,
        magic: &[u8],
        body_size: usize,
    ) -> Option<Decision> {
        if filename.is_empty() {
            return None;
        }

        if let Some(dec) = self.verify_mime_type(filename, part_content_type, magic) {
            return Some(dec);
        }
        if let Some(dec) = self.detect_executable(filename, magic) {
            return Some(dec);
        }
        if let Some(dec) = self.detect_archive_bomb(filename, magic, body_size) {
            return Some(dec);
        }
        if let Some(dec) = self.detect_image_polyglot(filename, magic) {
            return Some(dec);
        }
        None
    }

    fn verify_mime_type(
        &self,
        filename: &str,
        declared_type: &str,
        magic: &[u8],
    ) -> Option<Decision> {
        if magic.is_empty() {
            return None;
        }

        for (_name, sig) in mime_signatures() {
            if !sig.is_empty() && magic.len() >= sig.len() && magic.starts_with(&sig) {
                return None;
            }
        }

        let lower = filename.to_lowercase();
        let image_ext = IMAGE_EXTENSIONS.iter().any(|ie| lower.ends_with(ie));

        if image_ext {
            let mut is_image = false;
            for (_name, sig) in mime_signatures() {
                if !sig.is_empty() && magic.len() >= sig.len() && magic.starts_with(&sig) {
                    is_image = true;
                    break;
                }
            }
            if !is_image {
                return Some(
                    Decision::new(Action::Block, 70.0)
                        .with_rule_id("UPL002")
                        .with_rule_name("MIME Type Mismatch")
                        .with_severity("high")
                        .with_evidence(format!(
                            "file {filename} declared as {declared_type} but magic bytes mismatch"
                        )),
                );
            }
        }

        None
    }

    fn detect_executable(&self, filename: &str, magic: &[u8]) -> Option<Decision> {
        let ext = file_ext_lower(filename);
        if EXECUTABLE_EXTENSIONS.iter().any(|e| *e == ext) {
            return Some(
                Decision::new(Action::Block, 80.0)
                    .with_rule_id("UPL003")
                    .with_rule_name("Executable Upload Blocked")
                    .with_severity("high")
                    .with_evidence(format!("executable file upload blocked: {filename}")),
            );
        }

        for sig in executable_magic() {
            if magic.len() >= sig.len() && magic.starts_with(&sig) {
                return Some(
                    Decision::new(Action::Block, 80.0)
                        .with_rule_id("UPL004")
                        .with_rule_name("Executable Magic Bytes")
                        .with_severity("high")
                        .with_evidence(format!("executable magic bytes detected in {filename}")),
                );
            }
        }

        None
    }

    fn detect_archive_bomb(
        &self,
        filename: &str,
        magic: &[u8],
        body_size: usize,
    ) -> Option<Decision> {
        let ext = file_ext_lower(filename);
        if ARCHIVE_EXTENSIONS.iter().any(|e| *e == ext) {
            return Some(
                Decision::new(Action::Monitor, 10.0)
                    .with_rule_id("UPL005")
                    .with_rule_name("Archive Upload")
                    .with_severity("low")
                    .with_evidence(format!("archive upload: {filename}")),
            );
        }

        for sig in archive_magic() {
            if magic.len() >= sig.len() && magic.starts_with(&sig) {
                if body_size > 50 * 1024 * 1024 && magic.len() < 512 {
                    return Some(
                        Decision::new(Action::Block, 75.0)
                            .with_rule_id("UPL006")
                            .with_rule_name("Archive Bomb Detected")
                            .with_severity("high")
                            .with_evidence(format!(
                                "potential archive bomb: body size {body_size} bytes with only 512 bytes inspected"
                            )),
                    );
                }
            }
        }

        None
    }

    fn detect_image_polyglot(&self, filename: &str, magic: &[u8]) -> Option<Decision> {
        let ext = file_ext_lower(filename);
        let is_image_ext = IMAGE_EXTENSIONS.iter().any(|e| *e == ext);
        if !is_image_ext || magic.len() < 4 {
            return None;
        }

        let text_part = String::from_utf8_lossy(magic);
        if SCRIPT_PATTERN.is_match(&text_part) {
            return Some(
                Decision::new(Action::Block, 90.0)
                    .with_rule_id("UPL007")
                    .with_rule_name("Image Polyglot Detected")
                    .with_severity("critical")
                    .with_evidence(format!("image polyglot with script content in {filename}")),
            );
        }

        None
    }

    fn extract_boundary(&self, content_type: &str) -> String {
        let lower = content_type.to_lowercase();
        let idx = match lower.find("boundary=") {
            Some(i) => i,
            None => return String::new(),
        };
        let mut boundary = &content_type[idx + 9..];
        if boundary.starts_with('"') {
            boundary = &boundary[1..];
        }
        if let Some(end) = boundary.find('"') {
            boundary = &boundary[..end];
        }
        boundary.to_string()
    }
}

impl Inspector for FileUploadSecurity {
    fn name(&self) -> &str {
        "file_upload"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        let content_type = ctx.headers.get("Content-Type").cloned().unwrap_or_default();
        if !content_type.starts_with("multipart/form-data") {
            return Ok(None);
        }

        let content_length_str = ctx
            .headers
            .get("Content-Length")
            .cloned()
            .unwrap_or_default();
        let content_length = content_length_str.parse::<i64>().unwrap_or(0);

        let limit = self.get_endpoint_limit(&ctx.path);
        if content_length > limit {
            return Ok(Some(
                Decision::new(Action::Block, 65.0)
                    .with_rule_id("UPL001")
                    .with_rule_name("File Size Exceeded")
                    .with_severity("high")
                    .with_evidence(format!(
                        "file size {content_length} exceeds limit {limit} for {}",
                        ctx.path
                    )),
            ));
        }

        if ctx.body.is_empty() {
            return Ok(None);
        }

        let boundary = self.extract_boundary(&content_type);
        if boundary.is_empty() {
            return Ok(None);
        }

        let body_size = ctx.body.len();
        for part in parse_multipart(&ctx.body, &boundary) {
            let dec = self.inspect_part(&part.filename, &part.content_type, &part.magic, body_size);
            if let Some(dec) = dec {
                return Ok(Some(dec));
            }
        }

        Ok(None)
    }
}

struct MultipartPart {
    filename: String,
    content_type: String,
    magic: Vec<u8>,
}

/// Minimal multipart reader. Splits on `--boundary` lines, reads each part's
/// headers, extracts Content-Disposition filename and the part Content-Type,
/// and returns the first 512 bytes of the part content (matching Go, which
/// read up to 512 bytes into a buffer).
fn parse_multipart(body: &[u8], boundary: &str) -> Vec<MultipartPart> {
    let delimiter = format!("--{boundary}");
    let delim = delimiter.as_bytes();
    let mut parts = Vec::new();

    // Find the first delimiter, then iterate segments between delimiters.
    let mut positions = Vec::new();
    let mut i = 0;
    while i + delim.len() <= body.len() {
        if &body[i..i + delim.len()] == delim {
            positions.push(i);
            i += delim.len();
        } else {
            i += 1;
        }
    }

    for w in 0..positions.len().saturating_sub(0) {
        let start = positions[w] + delim.len();
        // Stop at the closing delimiter "--boundary--".
        if body.get(start..start + 2) == Some(b"--") {
            break;
        }
        let end = positions.get(w + 1).copied().unwrap_or(body.len());
        // Skip the CRLF/LF after the delimiter.
        let mut s = start;
        if body.get(s..s + 2) == Some(b"\r\n") {
            s += 2;
        } else if body.get(s..s + 1) == Some(b"\n") {
            s += 1;
        }
        if s >= end {
            continue;
        }
        let segment = &body[s..end];
        if let Some(part) = parse_one_part(segment) {
            parts.push(part);
        }
    }

    parts
}

fn parse_one_part(segment: &[u8]) -> Option<MultipartPart> {
    // Headers end at the first blank line.
    let header_end = find_header_end(segment)?;
    let header_bytes = &segment[..header_end.0];
    let content_start = header_end.1;
    let header_str = String::from_utf8_lossy(header_bytes);

    let mut filename = String::new();
    let mut content_type = String::new();
    for line in header_str.split("\r\n").flat_map(|l| l.split('\n')) {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_lowercase();
            let value = value.trim();
            if name == "content-disposition" {
                if let Some(f) = extract_param(value, "filename") {
                    filename = f;
                }
            } else if name == "content-type" {
                content_type = value.to_string();
            }
        }
    }

    let magic = &segment[content_start..(content_start + 512).min(segment.len())];
    Some(MultipartPart {
        filename,
        content_type,
        magic: magic.to_vec(),
    })
}

/// Find the end of the header block: the index of the blank line, and the
/// offset where the content begins.
fn find_header_end(segment: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < segment.len() {
        if segment[i] == b'\r'
            && segment.get(i + 1) == Some(&b'\n')
            && segment.get(i + 2) == Some(&b'\r')
            && segment.get(i + 3) == Some(&b'\n')
        {
            return Some((i, i + 4));
        }
        if segment[i] == b'\n' && segment.get(i + 1) == Some(&b'\n') {
            return Some((i, i + 2));
        }
        i += 1;
    }
    None
}

/// Extract a `key="value"` or `key=value` parameter from a header value.
fn extract_param(value: &str, key: &str) -> Option<String> {
    let lower = value.to_lowercase();
    let idx = lower.find(&format!("{key}="))?;
    let rest = &value[idx + key.len() + 1..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"').unwrap_or(stripped.len());
        Some(stripped[..end].to_string())
    } else {
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

fn file_ext_lower(filename: &str) -> String {
    match filename.rfind('.') {
        Some(idx) => filename[idx..].to_lowercase(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn multipart_body(boundary: &str, filename: &str, part_ct: &str, content: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        b.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
                .as_bytes(),
        );
        b.extend_from_slice(format!("Content-Type: {part_ct}\r\n\r\n").as_bytes());
        b.extend_from_slice(content);
        b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        b
    }

    #[test]
    fn exe_extension_blocked() {
        // ".exe" IS in the executable extension list; ".php" is deliberately
        // NOT (Go's list omits it), so use .exe for the extension rule.
        let u = FileUploadSecurity::new(false);
        let body = multipart_body("B", "run.exe", "application/octet-stream", b"MZhello");
        let mut r = HttpRequest::new("POST", "/upload");
        r.header
            .add("Content-Type", "multipart/form-data; boundary=B");
        r.body = body;
        let mut ctx = RequestContext::new(r);
        let dec = u.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "UPL003");
    }

    #[test]
    fn php_extension_is_not_treated_as_executable() {
        // Faithful: Go's executableExtensions list does not include ".php", so
        // this must not produce UPL003.
        let u = FileUploadSecurity::new(false);
        let body = multipart_body("B", "shell.php", "text/plain", b"hello");
        let mut r = HttpRequest::new("POST", "/upload");
        r.header
            .add("Content-Type", "multipart/form-data; boundary=B");
        r.body = body;
        let mut ctx = RequestContext::new(r);
        let dec = u.inspect(&mut ctx).unwrap();
        if let Some(dec) = dec {
            assert_ne!(dec.rule_id, "UPL003");
        }
    }

    #[test]
    fn elf_magic_in_image_blocked_as_executable() {
        let u = FileUploadSecurity::new(false);
        let body = multipart_body(
            "B",
            "photo.png",
            "image/png",
            &[0x7F, 0x45, 0x4C, 0x46, 0x02],
        );
        let mut r = HttpRequest::new("POST", "/upload");
        r.header
            .add("Content-Type", "multipart/form-data; boundary=B");
        r.body = body;
        let mut ctx = RequestContext::new(r);
        let dec = u.inspect(&mut ctx).unwrap().unwrap();
        // verify_mime_type runs first: png magic mismatch -> UPL002
        assert!(dec.rule_id == "UPL002" || dec.rule_id == "UPL004");
    }

    #[test]
    fn benign_png_upload_allowed() {
        let u = FileUploadSecurity::new(false);
        let body = multipart_body(
            "B",
            "photo.png",
            "image/png",
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0],
        );
        let mut r = HttpRequest::new("POST", "/upload");
        r.header
            .add("Content-Type", "multipart/form-data; boundary=B");
        r.body = body;
        let mut ctx = RequestContext::new(r);
        assert!(u.inspect(&mut ctx).unwrap().is_none());
    }

    #[test]
    fn size_limit_blocked() {
        let u = FileUploadSecurity::new(false);
        u.set_endpoint_limit("/upload", 10);
        let mut r = HttpRequest::new("POST", "/upload");
        r.header
            .add("Content-Type", "multipart/form-data; boundary=B");
        r.header.add("Content-Length", "1000");
        r.body = multipart_body("B", "a.txt", "text/plain", b"x");
        let mut ctx = RequestContext::new(r);
        let dec = u.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "UPL001");
    }

    #[test]
    fn polyglot_svg_blocked() {
        let u = FileUploadSecurity::new(false);
        let content = b"\x89PNG\r\n\x1a\n<script>alert(1)</script>";
        let body = multipart_body("B", "img.png", "image/png", content);
        let mut r = HttpRequest::new("POST", "/upload");
        r.header
            .add("Content-Type", "multipart/form-data; boundary=B");
        r.body = body;
        let mut ctx = RequestContext::new(r);
        let dec = u.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "UPL007");
    }
}
