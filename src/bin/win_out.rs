//! Encrypto Windows GUI - Output (Monitor Clipboard and Decrypt)
//!
//! This program monitors the clipboard for encrypted data (base64-encoded)
//! and automatically decrypts it to the desktop.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("此程序仅支持 Windows 平台。");
    std::process::exit(1);
}

#[cfg(windows)]
use std::io::Cursor;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use encrypto::crypto;

/// Magic bytes that identify our encrypted format after base64 decode.
/// The RSA-encrypted header starts with specific patterns.
#[cfg(windows)]
const POLL_INTERVAL_MS: u64 = 500;

#[cfg(windows)]
fn main() {
    // Create stop flag for clean shutdown
    let running = Arc::new(AtomicBool::new(true));

    // Show startup notification
    show_notification("Encrypto 监控已启动", "正在监控剪切板...\n\n检测到加密数据时将自动解密到桌面。");

    // Track last clipboard content to detect changes
    let mut last_clipboard_hash: u64 = 0;

    // Main monitoring loop
    while running.load(Ordering::Relaxed) {
        // Check clipboard
        if let Ok(text) = get_clipboard_text() {
            let hash = simple_hash(&text);

            // Only process if clipboard content changed
            if hash != last_clipboard_hash {
                last_clipboard_hash = hash;

                // Try to decrypt
                if let Some(result) = try_decrypt_clipboard(&text) {
                    match result {
                        Ok(output_path) => {
                            show_notification(
                                "解密成功",
                                &format!("文件已保存到:\n{}", output_path.display()),
                            );
                        }
                        Err(e) => {
                            // Only show error if it looked like encrypted data
                            if text.len() > 1000 && is_likely_base64(&text) {
                                show_notification("解密失败", &format!("错误: {}", e));
                            }
                            // Otherwise silently ignore - it's probably not our data
                        }
                    }
                }
            }
        }

        // Sleep before next check
        std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }
}

/// Try to decrypt clipboard content if it looks like encrypted data.
/// Returns None if the data doesn't look like our encrypted format.
/// Returns Some(Ok(path)) if decryption succeeded.
/// Returns Some(Err(e)) if it looked like our data but decryption failed.
#[cfg(windows)]
fn try_decrypt_clipboard(text: &str) -> Option<Result<PathBuf, Box<dyn std::error::Error>>> {
    // Quick checks to filter out obviously non-encrypted data
    let trimmed = text.trim();

    // Must be base64-like (reasonable length and characters)
    if trimmed.len() < 500 || !is_likely_base64(trimmed) {
        return None;
    }

    // Check base64 padding - valid base64 length should be divisible by 4
    let clean_len = trimmed.chars().filter(|c| !c.is_whitespace()).count();
    if clean_len % 4 != 0 {
        // Data might be truncated, skip silently
        return None;
    }

    // Try to base64 decode
    let decoded = match base64_decode(trimmed) {
        Ok(data) => data,
        Err(_) => return None,
    };

    // Check minimum size for our format (need at least 2 RSA blocks + IV + tag)
    // RSA 4096 = 512 bytes, so minimum is ~1100 bytes
    if decoded.len() < 1100 {
        return None;
    }

    // Validate data looks like our encrypted format before attempting decrypt
    // This helps avoid false positive error messages
    if !looks_like_encrypted_data(&decoded) {
        return None;
    }

    // Try to decrypt
    Some(decrypt_to_desktop(&decoded))
}

/// Check if decoded data looks like our encrypted format.
/// We can't fully validate without decryption, but we can do basic size checks.
#[cfg(windows)]
fn looks_like_encrypted_data(data: &[u8]) -> bool {
    // RSA 4096 = 512 bytes per block
    // Minimum structure: header_block(512) + key_block(512) + iv(12) + ciphertext(1+) + tag(16)
    // = 1053 bytes minimum
    if data.len() < 1053 {
        return false;
    }

    // The data should be large enough to contain the claimed ciphertext
    // We can't verify this without decrypting the header, but we can check
    // that the total size is reasonable (not truncated mid-block)
    
    // For RSA 4096, encrypted blocks are 512 bytes each
    // First two blocks are header and key = 1024 bytes
    // Remaining should be: IV (12) + ciphertext (variable) + tag (16)
    let payload_size = data.len().saturating_sub(1024);
    
    // Minimum payload: IV(12) + at least 1 byte ciphertext + tag(16) = 29 bytes
    if payload_size < 29 {
        return false;
    }

    true
}

/// Check if a string looks like base64 data.
#[cfg(windows)]
fn is_likely_base64(s: &str) -> bool {
    // Must be mostly alphanumeric, +, /, or =
    let valid_chars = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    let total_chars = s.chars().filter(|c| !c.is_whitespace()).count();

    if total_chars == 0 {
        return false;
    }

    // At least 95% valid base64 characters
    (valid_chars * 100 / total_chars) >= 95
}

/// Decrypt data and extract to desktop.
#[cfg(windows)]
fn decrypt_to_desktop(encrypted_data: &[u8]) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Validate minimum size before attempting decryption
    // RSA 4096 = 512 bytes, minimum = 2 blocks + iv + tag = 1024 + 12 + 16 = 1052
    if encrypted_data.len() < 1052 {
        return Err("数据太短，可能被截断".into());
    }

    // Decrypt to memory
    let mut input = Cursor::new(encrypted_data);
    let mut tar_data = Vec::new();
    
    // Wrap the decrypt call to provide better error messages
    match crypto::decrypt_hybrid(&mut input, &mut tar_data) {
        Ok(()) => {}
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("fill whole buffer") || err_str.contains("UnexpectedEof") {
                return Err("数据不完整，可能超过剪切板大小限制或被截断".into());
            }
            return Err(format!("解密失败: {}", e).into());
        }
    }

    // Get desktop path
    let desktop = get_desktop_path()?;

    // Analyze tar archive to get the root name
    let archive_name = get_tar_root_name(&tar_data)?;

    // Create unique output directory
    let output_dir = ensure_unique_path(desktop.join(&archive_name));

    // Create output directory
    std::fs::create_dir_all(&output_dir)?;

    // Extract tar archive
    extract_tar_to_dir(&tar_data, &output_dir)?;

    Ok(output_dir)
}

/// Get the root name from a tar archive.
#[cfg(windows)]
fn get_tar_root_name(tar_data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut archive = tar::Archive::new(Cursor::new(tar_data));

    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?;

        // Get the first component as the archive name
        if let Some(first) = path.components().next() {
            let name = first.as_os_str().to_string_lossy().to_string();
            if !name.is_empty() {
                return Ok(name);
            }
        }
    }

    // Fallback name with timestamp
    Ok(format!(
        "decrypted_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ))
}

/// Extract tar archive to directory.
#[cfg(windows)]
fn extract_tar_to_dir(tar_data: &[u8], output_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // First pass: determine structure
    let mut first_archive = tar::Archive::new(Cursor::new(tar_data));
    let mut archive_root: Option<String> = None;
    let mut root_is_dir = false;
    let mut entry_count = 0;

    for entry in first_archive.entries()? {
        let entry = entry?;
        let path = entry.path()?;
        entry_count += 1;

        let first_component: String = path
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .unwrap_or_default();

        if archive_root.is_none() {
            archive_root = Some(first_component.clone());
            root_is_dir = entry.header().entry_type().is_dir();
        } else if let Some(ref root) = archive_root {
            if !first_component.starts_with(root.as_str()) && first_component != *root {
                archive_root = None;
                break;
            }
        }
    }

    let strip_root = if let Some(root) = archive_root {
        if root_is_dir && entry_count > 1 {
            Some(root)
        } else {
            None
        }
    } else {
        None
    };

    // Second pass: extract
    let mut archive = tar::Archive::new(Cursor::new(tar_data));

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let path_str = path.to_string_lossy();

        // Validate path safety
        if !is_safe_relative_path(&path_str) {
            continue;
        }

        // Determine output path
        let relative_path = if let Some(ref root) = strip_root {
            if path_str == *root || path_str == format!("{}/", root) {
                continue;
            }
            let stripped = path_str
                .strip_prefix(root)
                .and_then(|s| s.strip_prefix('/'))
                .unwrap_or(&path_str);
            PathBuf::from(stripped)
        } else {
            path.to_path_buf()
        };

        if relative_path.as_os_str().is_empty() {
            continue;
        }

        let full_path = output_dir.join(&relative_path);

        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        entry.unpack(&full_path)?;
    }

    Ok(())
}

/// Check if a path is safe.
#[cfg(windows)]
fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }

    if path.starts_with('/') || path.starts_with('\\') {
        return false;
    }

    for component in path.split('/') {
        if component.is_empty() {
            continue;
        }
        if component.contains('\\') {
            return false;
        }
        if component == "." || component == ".." {
            return false;
        }
    }

    true
}

/// Get the desktop path.
#[cfg(windows)]
fn get_desktop_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Try USERPROFILE environment variable
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let desktop = PathBuf::from(profile).join("Desktop");
        if desktop.exists() {
            return Ok(desktop);
        }
    }

    // Try OneDrive desktop
    if let Ok(onedrive) = std::env::var("OneDrive") {
        let desktop = PathBuf::from(onedrive).join("Desktop");
        if desktop.exists() {
            return Ok(desktop);
        }
    }

    // Fallback to current directory
    Ok(std::env::current_dir()?)
}

/// Ensure a path is unique by adding suffix if needed.
#[cfg(windows)]
fn ensure_unique_path(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }

    let base_str = path.to_string_lossy().to_string();

    for i in 1..100000 {
        let candidate = PathBuf::from(format!("{}_{}", base_str, i));
        if !candidate.exists() {
            return candidate;
        }
    }

    path
}

/// Simple hash function for detecting clipboard changes.
#[cfg(windows)]
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

/// Base64 decode.
#[cfg(windows)]
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    const DECODE_TABLE: [i8; 256] = {
        let mut table = [-1i8; 256];
        let mut i = 0u8;
        while i < 26 {
            table[(b'A' + i) as usize] = i as i8;
            table[(b'a' + i) as usize] = (i + 26) as i8;
            i += 1;
        }
        let mut i = 0u8;
        while i < 10 {
            table[(b'0' + i) as usize] = (i + 52) as i8;
            i += 1;
        }
        table[b'+' as usize] = 62;
        table[b'/' as usize] = 63;
        table
    };

    // Filter whitespace and padding
    let chars: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace() && b != b'=')
        .collect();

    if chars.is_empty() {
        return Ok(Vec::new());
    }

    let mut result = Vec::with_capacity(chars.len() * 3 / 4);

    for chunk in chars.chunks(4) {
        let mut buf = [0u8; 4];
        let len = chunk.len();

        for (i, &byte) in chunk.iter().enumerate() {
            let val = DECODE_TABLE[byte as usize];
            if val < 0 {
                return Err("Invalid base64 character");
            }
            buf[i] = val as u8;
        }

        // Decode based on length
        if len >= 2 {
            result.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if len >= 3 {
            result.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if len >= 4 {
            result.push((buf[2] << 6) | buf[3]);
        }
    }

    Ok(result)
}

/// Get text from clipboard using Windows API.
#[cfg(windows)]
fn get_clipboard_text() -> Result<String, Box<dyn std::error::Error>> {
    use std::ptr;

    const CF_UNICODETEXT: u32 = 13;

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(hwnd: *mut std::ffi::c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn GetClipboardData(format: u32) -> *mut std::ffi::c_void;
        fn IsClipboardFormatAvailable(format: u32) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalLock(mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        fn GlobalUnlock(mem: *mut std::ffi::c_void) -> i32;
    }

    unsafe {
        // Check if text format is available
        if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
            return Err("剪切板中没有文本".into());
        }

        if OpenClipboard(ptr::null_mut()) == 0 {
            return Err("无法打开剪切板".into());
        }

        let result = (|| {
            let handle = GetClipboardData(CF_UNICODETEXT);
            if handle.is_null() {
                return Err("无法获取剪切板数据".into());
            }

            let ptr = GlobalLock(handle);
            if ptr.is_null() {
                return Err("无法锁定剪切板内存".into());
            }

            // Find string length
            let wstr = ptr as *const u16;
            let mut len = 0;
            while *wstr.add(len) != 0 {
                len += 1;
            }

            // Convert from UTF-16
            let slice = std::slice::from_raw_parts(wstr, len);
            let text = String::from_utf16_lossy(slice);

            GlobalUnlock(handle);

            Ok(text)
        })();

        CloseClipboard();
        result
    }
}

/// Show a Windows notification (toast or message box).
#[cfg(windows)]
fn show_notification(title: &str, message: &str) {
    use std::ptr;

    const MB_OK: u32 = 0x00000000;
    const MB_ICONINFORMATION: u32 = 0x00000040;
    const MB_SYSTEMMODAL: u32 = 0x00001000;

    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(
            hwnd: *mut std::ffi::c_void,
            text: *const u16,
            caption: *const u16,
            typ: u32,
        ) -> i32;
    }

    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            message_wide.as_ptr(),
            title_wide.as_ptr(),
            MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL,
        );
    }
}
