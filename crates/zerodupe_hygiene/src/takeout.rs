use std::io;
use std::path::Path;

use exif::{Field, In, Rational, Reader, Tag, Value, experimental::Writer};

/// Metadata extracted from a Google Takeout JSON sidecar.
#[derive(Debug, Clone, Default)]
pub struct TakeoutMetadata {
    pub timestamp_secs: Option<i64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub title: Option<String>,
}

/// Parse a Google Takeout `.jpg.json` (or similar) sidecar file.
pub fn parse_takeout_json(json_path: &Path) -> io::Result<TakeoutMetadata> {
    let content = std::fs::read_to_string(json_path)?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(TakeoutMetadata {
        timestamp_secs: json["photoTakenTime"]["timestamp"]
            .as_str()
            .and_then(|s| s.parse::<i64>().ok()),
        latitude: json["geoData"]["latitude"]
            .as_f64()
            .or_else(|| json["geoDataExif"]["latitude"].as_f64()),
        longitude: json["geoData"]["longitude"]
            .as_f64()
            .or_else(|| json["geoDataExif"]["longitude"].as_f64()),
        title: json["title"].as_str().map(|s| s.to_string()),
    })
}

/// Merge Takeout metadata into an image file.
///
/// Sets the file modification time to `photoTakenTime` (if present)
/// and writes GPS coordinates to EXIF (if present).
pub fn merge_takeout_metadata(image_path: &Path, metadata: &TakeoutMetadata) -> io::Result<()> {
    if let Some(ts) = metadata.timestamp_secs {
        let ft = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(ts as u64);
        if let Ok(f) = std::fs::File::open(image_path) {
            let _ = f.set_modified(ft);
        }
    }

    if let (Some(lat), Some(lon)) = (metadata.latitude, metadata.longitude) {
        let _ = write_gps_to_exif(image_path, lat, lon);
    }

    Ok(())
}

fn write_gps_to_exif(path: &Path, lat: f64, lon: f64) -> io::Result<()> {
    let jpeg_data = std::fs::read(path)?;

    if !jpeg_data.starts_with(&[0xFF, 0xD8]) {
        return Ok(());
    }

    let exif_result =
        Reader::new().read_from_container(&mut io::BufReader::new(io::Cursor::new(&jpeg_data)));

    let existing_fields: Vec<Field> = match &exif_result {
        Ok(exif) => exif.fields().cloned().collect(),
        Err(_) => Vec::new(),
    };

    let mut writer = Writer::new();
    for field in &existing_fields {
        if is_gps_tag(field.tag) {
            continue;
        }
        writer.push_field(field);
    }

    let gps_lat_ref = if lat >= 0.0 { b"N" } else { b"S" };
    let gps_lon_ref = if lon >= 0.0 { b"E" } else { b"W" };
    let lat_abs = lat.abs();
    let lon_abs = lon.abs();

    fn to_dms(deg: f64) -> Vec<Rational> {
        let d = deg.trunc();
        let m = ((deg - d) * 60.0).trunc();
        let s = (deg - d - m / 60.0) * 3600.0;
        let s_num = (s * 1000.0).round() as u32;
        vec![
            Rational {
                num: d as u32,
                denom: 1,
            },
            Rational {
                num: m as u32,
                denom: 1,
            },
            Rational {
                num: s_num,
                denom: 1000,
            },
        ]
    }

    let fields_to_add = [
        Field {
            tag: Tag::GPSLatitudeRef,
            ifd_num: In::PRIMARY,
            value: Value::Ascii(vec![gps_lat_ref.to_vec()]),
        },
        Field {
            tag: Tag::GPSLongitudeRef,
            ifd_num: In::PRIMARY,
            value: Value::Ascii(vec![gps_lon_ref.to_vec()]),
        },
        Field {
            tag: Tag::GPSLatitude,
            ifd_num: In::PRIMARY,
            value: Value::Rational(to_dms(lat_abs)),
        },
        Field {
            tag: Tag::GPSLongitude,
            ifd_num: In::PRIMARY,
            value: Value::Rational(to_dms(lon_abs)),
        },
    ];
    for f in &fields_to_add {
        writer.push_field(f);
    }

    let mut exif_buf = io::Cursor::new(Vec::new());
    writer
        .write(&mut exif_buf, false)
        .map_err(|e| io::Error::other(format!("EXIF write: {e}")))?;
    let new_exif_tiff = exif_buf.into_inner();

    let new_jpeg = patch_jpeg_exif(&jpeg_data, &new_exif_tiff)?;
    std::fs::write(path, &new_jpeg)?;

    Ok(())
}

fn is_gps_tag(tag: Tag) -> bool {
    tag == Tag::GPSLatitudeRef
        || tag == Tag::GPSLatitude
        || tag == Tag::GPSLongitudeRef
        || tag == Tag::GPSLongitude
        || tag == Tag::GPSAltitudeRef
        || tag == Tag::GPSAltitude
        || tag == Tag::GPSTimeStamp
        || tag == Tag::GPSSatellites
        || tag == Tag::GPSStatus
        || tag == Tag::GPSMeasureMode
        || tag == Tag::GPSDOP
        || tag == Tag::GPSSpeedRef
        || tag == Tag::GPSSpeed
        || tag == Tag::GPSTrackRef
        || tag == Tag::GPSTrack
        || tag == Tag::GPSImgDirectionRef
        || tag == Tag::GPSImgDirection
        || tag == Tag::GPSMapDatum
        || tag == Tag::GPSDestLatitudeRef
        || tag == Tag::GPSDestLatitude
        || tag == Tag::GPSDestLongitudeRef
        || tag == Tag::GPSDestLongitude
        || tag == Tag::GPSDestBearingRef
        || tag == Tag::GPSDestBearing
        || tag == Tag::GPSDestDistanceRef
        || tag == Tag::GPSDestDistance
        || tag == Tag::GPSProcessingMethod
        || tag == Tag::GPSAreaInformation
        || tag == Tag::GPSDateStamp
        || tag == Tag::GPSDifferential
        || tag == Tag::GPSHPositioningError
}

fn patch_jpeg_exif(jpeg_data: &[u8], new_exif_tiff: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = Vec::with_capacity(jpeg_data.len() + new_exif_tiff.len() + 64);
    let mut i = 0;

    while i + 1 < jpeg_data.len() {
        if jpeg_data[i] == 0xFF && jpeg_data[i + 1] == 0xE1 && i + 4 < jpeg_data.len() {
            let seg_len = ((jpeg_data[i + 2] as usize) << 8) | (jpeg_data[i + 3] as usize);
            if seg_len >= 8
                && i + 2 + seg_len <= jpeg_data.len()
                && &jpeg_data[i + 4..i + 10] == b"Exif\0\0"
            {
                i += 2 + seg_len;
                continue;
            }
        }

        if i == 2 && jpeg_data.starts_with(&[0xFF, 0xD8]) {
            let total_seg_len = 2 + 6 + new_exif_tiff.len();
            result.push(0xFF);
            result.push(0xE1);
            result.push(((total_seg_len >> 8) & 0xFF) as u8);
            result.push((total_seg_len & 0xFF) as u8);
            result.extend_from_slice(b"Exif\0\0");
            result.extend_from_slice(new_exif_tiff);
        }

        result.push(jpeg_data[i]);
        i += 1;
    }

    if let Some(&last) = jpeg_data.last()
        && result.last() != Some(&last)
    {
        result.push(last);
    }

    Ok(result)
}

/// Check if a Google Takeout JSON sidecar exists for the given image path.
pub fn takeout_json_for_image(image_path: &Path) -> Option<std::path::PathBuf> {
    let json_path = format!("{}.json", image_path.display());
    let p = Path::new(&json_path);
    if p.exists() {
        Some(p.to_path_buf())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exif::Value as ExifValue;

    #[test]
    fn write_gps_exif_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("test.jpg");

        let img = image::RgbImage::from_pixel(1, 1, image::Rgb([255u8, 0u8, 0u8]));
        img.save(&img_path).unwrap();

        let meta = TakeoutMetadata {
            timestamp_secs: Some(1700000000),
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
            title: Some("test".into()),
        };
        merge_takeout_metadata(&img_path, &meta).unwrap();

        let file = std::fs::File::open(&img_path).unwrap();
        let mut reader = io::BufReader::new(file);
        let exif = Reader::new().read_from_container(&mut reader).unwrap();

        let lat_ref = exif
            .get_field(Tag::GPSLatitudeRef, In::PRIMARY)
            .expect("GPSLatitudeRef not found");
        if let ExifValue::Ascii(ref v) = lat_ref.value {
            assert_eq!(v.first().map(|x| &x[..]), Some(&b"N"[..]));
        } else {
            panic!("GPSLatitudeRef is not Ascii");
        }

        let lon_ref = exif
            .get_field(Tag::GPSLongitudeRef, In::PRIMARY)
            .expect("GPSLongitudeRef not found");
        if let ExifValue::Ascii(ref v) = lon_ref.value {
            assert_eq!(v.first().map(|x| &x[..]), Some(&b"W"[..]));
        } else {
            panic!("GPSLongitudeRef is not Ascii");
        }

        let lat_field = exif
            .get_field(Tag::GPSLatitude, In::PRIMARY)
            .expect("GPSLatitude not found");
        if let ExifValue::Rational(ref v) = lat_field.value {
            assert_eq!(v.len(), 3);
            let deg = v[0].to_f64();
            assert!(
                (deg - 40.0).abs() < 1.0,
                "Expected latitude degrees ~40, got {deg}"
            );
        } else {
            panic!("GPSLatitude is not Rational");
        }

        let lon_field = exif
            .get_field(Tag::GPSLongitude, In::PRIMARY)
            .expect("GPSLongitude not found");
        if let ExifValue::Rational(ref v) = lon_field.value {
            assert_eq!(v.len(), 3);
            let deg = v[0].to_f64();
            assert!(
                (deg - 74.0).abs() < 1.0,
                "Expected longitude degrees ~74, got {deg}"
            );
        } else {
            panic!("GPSLongitude is not Rational");
        }
    }

    #[test]
    fn write_gps_southern_eastern() {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("test2.jpg");

        let img = image::RgbImage::from_pixel(1, 1, image::Rgb([0u8, 255u8, 0u8]));
        img.save(&img_path).unwrap();

        write_gps_to_exif(&img_path, -33.8688, 151.2093).unwrap();

        let file = std::fs::File::open(&img_path).unwrap();
        let mut reader = io::BufReader::new(file);
        let exif = Reader::new().read_from_container(&mut reader).unwrap();

        let lat_ref = exif
            .get_field(Tag::GPSLatitudeRef, In::PRIMARY)
            .expect("GPSLatitudeRef not found");
        if let ExifValue::Ascii(ref v) = lat_ref.value {
            assert_eq!(v.first().map(|x| &x[..]), Some(&b"S"[..]));
        } else {
            panic!("Expected Ascii for latitude ref");
        }

        let lon_ref = exif
            .get_field(Tag::GPSLongitudeRef, In::PRIMARY)
            .expect("GPSLongitudeRef not found");
        if let ExifValue::Ascii(ref v) = lon_ref.value {
            assert_eq!(v.first().map(|x| &x[..]), Some(&b"E"[..]));
        } else {
            panic!("Expected Ascii for longitude ref");
        }
    }

    #[test]
    fn write_gps_non_jpeg_is_silent() {
        let dir = tempfile::tempdir().unwrap();
        let txt_path = dir.path().join("not_an_image.txt");
        std::fs::write(&txt_path, b"hello world").unwrap();

        let result = write_gps_to_exif(&txt_path, 40.0, -74.0);
        assert!(result.is_ok());
    }
}
