//! Encrypto Windows GUI - Input (Encrypt to Clipboard)
//!
//! Drag and drop files or directories onto this program to encrypt them
//! and copy the base64-encoded result to the clipboard.

#![windows_subsystem = "windows"]

use std::env;
use std::io::Cursor;
use std::path::Path;

use encrypto::{crypto, CompressionAlgorithm};

fn main() {
    // Get dropped file/directory from command line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        show_message(
            "使用方法",
            "请将文件或文件夹拖放到此程序上进行加密。\n\n加密结果将复制到剪切板。",
            false,
        );
        return;
    }

    let input_path = Path::new(&args[1]);

    if !input_path.exists() {
        show_message("错误", &format!("路径不存在: {}", input_path.display()), true);
        return;
    }

    match encrypt_to_clipboard(input_path) {
        Ok(size) => {
            let name = input_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "数据".to_string());
            
            // Warn if data is large (> 500KB base64 may have issues)
            let warning = if size > 500 * 1024 {
                format!(
                    "\n\n⚠️ 警告: 数据较大 ({:.1} MB)，某些程序可能无法处理如此大的剪切板内容。",
                    size as f64 / 1024.0 / 1024.0
                )
            } else {
                String::new()
            };
            
            show_message(
                "加密成功",
                &format!(
                    "已加密: {}\n\nBase64 大小: {} 字节 ({:.1} KB){}\n\n数据已复制到剪切板。",
                    name, size, size as f64 / 1024.0, warning
                ),
                false,
            );
        }
        Err(e) => {
            show_message("加密失败", &format!("错误: {}", e), true);
        }
    }
}

/// Encrypt a file or directory and copy the base64-encoded result to clipboard.
fn encrypt_to_clipboard(input_path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    // Get compression algorithm from environment (default to lz4)
    let compression = CompressionAlgorithm::from_env().unwrap_or(CompressionAlgorithm::Lz4);

    // Create tar archive of input
    let mut tar_data = Vec::new();
    {
        let mut tar_builder = tar::Builder::new(&mut tar_data);

        let metadata = std::fs::metadata(input_path)?;
        let file_name = input_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "data".to_string());

        if metadata.is_file() {
            tar_builder.append_path_with_name(input_path, &file_name)?;
        } else if metadata.is_dir() {
            tar_builder.append_dir_all(&file_name, input_path)?;
        } else {
            return Err("不支持的文件类型".into());
        }

        tar_builder.finish()?;
    }

    // Encrypt
    let mut input = Cursor::new(tar_data);
    let mut encrypted = Cursor::new(Vec::new());
    crypto::encrypt_hybrid(&mut input, &mut encrypted, compression)?;

    // Base64 encode
    let encrypted_bytes = encrypted.into_inner();
    let base64_data = base64_encode(&encrypted_bytes);
    let size = base64_data.len();

    // Copy to clipboard
    set_clipboard_text(&base64_data)?;

    Ok(size)
}

/// Base64 encode bytes.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Set text to clipboard using Windows API.
fn set_clipboard_text(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::ptr;

    // Windows API constants and types
    const CF_UNICODETEXT: u32 = 13;
    const GMEM_MOVEABLE: u32 = 0x0002;

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(hwnd: *mut std::ffi::c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn SetClipboardData(format: u32, mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(flags: u32, bytes: usize) -> *mut std::ffi::c_void;
        fn GlobalLock(mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        fn GlobalUnlock(mem: *mut std::ffi::c_void) -> i32;
    }

    // Convert to UTF-16
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let size = wide.len() * 2;

    unsafe {
        if OpenClipboard(ptr::null_mut()) == 0 {
            return Err("无法打开剪切板".into());
        }

        // Empty clipboard
        EmptyClipboard();

        // Allocate global memory
        let mem = GlobalAlloc(GMEM_MOVEABLE, size);
        if mem.is_null() {
            CloseClipboard();
            return Err("无法分配内存".into());
        }

        // Copy data
        let locked = GlobalLock(mem);
        if locked.is_null() {
            CloseClipboard();
            return Err("无法锁定内存".into());
        }

        ptr::copy_nonoverlapping(wide.as_ptr(), locked as *mut u16, wide.len());
        GlobalUnlock(mem);

        // Set clipboard data
        if SetClipboardData(CF_UNICODETEXT, mem).is_null() {
            CloseClipboard();
            return Err("无法设置剪切板数据".into());
        }

        CloseClipboard();
    }

    Ok(())
}

/// Show a Windows message box.
fn show_message(title: &str, message: &str, is_error: bool) {
    use std::ptr;

    const MB_OK: u32 = 0x00000000;
    const MB_ICONERROR: u32 = 0x00000010;
    const MB_ICONINFORMATION: u32 = 0x00000040;

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

    let icon = if is_error {
        MB_ICONERROR
    } else {
        MB_ICONINFORMATION
    };

    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            message_wide.as_ptr(),
            title_wide.as_ptr(),
            MB_OK | icon,
        );
    }
}
