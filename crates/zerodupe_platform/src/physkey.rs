use serde::{Deserialize, Serialize};

/// Opaque physical file identity key.
///
/// The cache and other consumers treat this as an opaque blob identified by a discriminant byte.
/// They never interpret the bytes — they only compare for equality and hash.
///
/// # Layout
///
/// | discriminant | OS      | bytes content                     |
/// |-------------|---------|----------------------------------|
/// | 0           | Unix    | 8 bytes device (BE) + 8 bytes inode (BE) |
/// | 1           | Windows | 4 bytes volume_serial (LE) + 8 bytes file_index (LE) |
/// | 2           | Fallback| canonical path bytes (UTF-8)     |
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PhysicalFileKey {
    /// 0 = Unix, 1 = Windows, 2 = Fallback (canonical path).
    pub discriminant: u8,
    /// Opaque identity bytes. Interpretation depends on discriminant.
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

impl PhysicalFileKey {
    /// Create from Unix device + inode numbers.
    pub fn from_unix(device: u64, inode: u64) -> Self {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&device.to_be_bytes());
        bytes.extend_from_slice(&inode.to_be_bytes());
        Self {
            discriminant: 0,
            bytes,
        }
    }

    /// Create from Windows volume serial + file index.
    pub fn from_windows(volume_serial: u32, file_index: u64) -> Self {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&volume_serial.to_le_bytes());
        bytes.extend_from_slice(&file_index.to_le_bytes());
        Self {
            discriminant: 1,
            bytes,
        }
    }

    /// Create a fallback key from a canonical path.
    pub fn from_fallback(path: &camino::Utf8Path) -> Self {
        let path_str = path.as_str();
        Self {
            discriminant: 2,
            bytes: path_str.as_bytes().to_vec(),
        }
    }

    /// Create a fallback key from a `std::path::Path` (lossy).
    pub fn from_fallback_std(path: &std::path::Path) -> Self {
        let lossy = path.to_string_lossy();
        Self {
            discriminant: 2,
            bytes: lossy.as_bytes().to_vec(),
        }
    }

    /// True if this key is a fallback (no real filesystem identity available).
    pub fn is_fallback(&self) -> bool {
        self.discriminant == 2
    }

    /// Obtain a Windows physical key from a file path using the stable Windows API.
    ///
    /// Uses `GetFileInformationByHandle` via FFI to retrieve the volume serial
    /// number and file index without depending on unstable std features
    /// (`windows_by_handle`). This is the stable-channel replacement for
    /// `MetadataExt::file_index()` and `MetadataExt::volume_serial_number()`.
    #[cfg(windows)]
    pub fn from_path_windows(path: &camino::Utf8Path) -> Option<Self> {
        use std::os::windows::io::AsRawHandle;

        #[repr(C)]
        #[allow(non_snake_case)]
        struct BY_HANDLE_FILE_INFORMATION {
            dwFileAttributes: u32,
            ftCreationTime: u64,
            ftLastAccessTime: u64,
            ftLastWriteTime: u64,
            dwVolumeSerialNumber: u32,
            nFileSizeHigh: u32,
            nFileSizeLow: u32,
            nNumberOfLinks: u32,
            nFileIndexHigh: u32,
            nFileIndexLow: u32,
        }

        unsafe extern "system" {
            fn GetFileInformationByHandle(
                hFile: *mut std::ffi::c_void,
                lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
            ) -> i32;
        }

        let file = std::fs::File::open(path.as_std_path()).ok()?;
        let handle = file.as_raw_handle();

        // SAFETY: BY_HANDLE_FILE_INFORMATION is a C repr struct with only integer fields;
        // zero-initialization is valid for all fields.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: handle is a valid file handle from File::open; info is a valid
        // pointer to a properly-sized BY_HANDLE_FILE_INFORMATION struct.
        let result = unsafe { GetFileInformationByHandle(handle, &mut info) };

        if result == 0 {
            return None;
        }

        let file_index = (info.nFileIndexHigh as u64) << 32 | (info.nFileIndexLow as u64);
        let volume_serial = info.dwVolumeSerialNumber;

        if file_index == 0 && volume_serial == 0 {
            None
        } else {
            Some(Self::from_windows(volume_serial, file_index))
        }
    }

    /// Stub for non-Windows platforms — always returns `None`.
    #[cfg(not(windows))]
    pub fn from_path_windows(_path: &camino::Utf8Path) -> Option<Self> {
        None
    }
}

/// Serde helper for byte arrays as sequences (not base64 strings).
mod serde_bytes {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&super::hex::encode(bytes.as_slice()))
        } else {
            serializer.serialize_bytes(bytes.as_slice())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;
        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a hex string or byte sequence")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                super::hex::decode(v).map_err(E::custom)
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(v)
            }
        }
        deserializer.deserialize_any(BytesVisitor)
    }
}

/// Simple hex encoding (no external crate dependency).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize]);
            s.push(HEX_CHARS[(b & 0x0F) as usize]);
        }
        s
    }

    pub fn decode(hex_str: &str) -> Result<Vec<u8>, String> {
        if !hex_str.len().is_multiple_of(2) {
            return Err("hex string has odd length".into());
        }
        let mut bytes = Vec::with_capacity(hex_str.len() / 2);
        let chars: Vec<u8> = hex_str.bytes().collect();
        for chunk in chars.chunks(2) {
            let hi = hex_val(chunk[0])?;
            let lo = hex_val(chunk[1])?;
            bytes.push((hi << 4) | lo);
        }
        Ok(bytes)
    }

    const HEX_CHARS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    fn hex_val(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(format!("invalid hex byte: {b}")),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn roundtrip() {
            let data = vec![0x00, 0xFF, 0xAB, 0x12, 0x34];
            let encoded = encode(&data);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(data, decoded);
        }

        #[test]
        fn empty() {
            assert_eq!(encode(&[]), "");
            assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_key_roundtrip_json() {
        let key = PhysicalFileKey::from_unix(2049, 12345);
        let json = serde_json::to_string(&key).expect("serialize");
        let deser: PhysicalFileKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, deser);
        assert_eq!(key.discriminant, 0);
    }

    #[test]
    fn windows_key_roundtrip_json() {
        let key = PhysicalFileKey::from_windows(0x1234_5678, 0xAAAA_BBBB_CCCC_DDDD);
        let json = serde_json::to_string(&key).expect("serialize");
        let deser: PhysicalFileKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, deser);
        assert_eq!(key.discriminant, 1);
    }

    #[test]
    fn fallback_key_roundtrip_json() {
        let path = camino::Utf8Path::new("/tmp/test.txt");
        let key = PhysicalFileKey::from_fallback(path);
        let json = serde_json::to_string(&key).expect("serialize");
        let deser: PhysicalFileKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, deser);
        assert_eq!(key.discriminant, 2);
    }

    #[test]
    fn different_unix_keys_not_equal() {
        let a = PhysicalFileKey::from_unix(1, 100);
        let b = PhysicalFileKey::from_unix(1, 200);
        assert_ne!(a, b);
    }

    #[test]
    fn windows_vs_unix_not_equal() {
        let a = PhysicalFileKey::from_unix(1, 100);
        let b = PhysicalFileKey::from_windows(1, 100);
        assert_ne!(a, b);
    }
}
