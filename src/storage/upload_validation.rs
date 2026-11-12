//! Cheap rejection of recognizable file headers on client chunk uploads.
//!
//! This is a heuristic, not proof of self-encryption: headerless plaintext and
//! deliberately disguised files can pass. `file-format` classifies a bounded
//! prefix with all deep readers disabled. Admission accepts only vetted types,
//! corroborating short signatures to reduce accidental ciphertext matches.
//! There is no decoding, decompression, entropy calculation, or payload scan.

use file_format::FileFormat;

// Includes tar's magic/version field at offset 257. The PE check reads just
// four additional bytes at the bounds-checked offset from the DOS header.
const SNIFF_PREFIX_LEN: usize = 265;

/// Safe to return to clients, including through the browser error boundary.
pub const FILE_HEADER_REJECTION: &str =
    "chunk has a recognizable file header; self-encrypt files before uploading";

/// Whether a chunk begins with a known file header.
///
/// Short magic values such as `BM`, `ID3`, and JPEG's three-byte prefix also
/// need corroborating header bytes to reduce accidental ciphertext matches.
pub(super) fn has_file_header(content: &[u8]) -> bool {
    let header = &content[..content.len().min(64)];
    if has_html_header(header)
        || has_xml_header(header)
        || has_pe_header(content)
        || header.starts_with(b"BM") && header.get(6..10) == Some(b"\x00\x00\x00\x00")
    {
        return true;
    }

    // These variants have sufficiently distinctive signatures in file-format.
    // Keep this list explicit: recognizing a type is not itself evidence that
    // its signature is safe to reject in uniformly distributed ciphertext.
    match FileFormat::from_bytes(&content[..content.len().min(SNIFF_PREFIX_LEN)]) {
        FileFormat::PortableNetworkGraphics
        | FileFormat::GraphicsInterchangeFormat
        | FileFormat::Webp
        | FileFormat::AudioInterchangeFileFormat
        | FileFormat::AudioVideoInterleave
        | FileFormat::WaveformAudio
        | FileFormat::Av1ImageFileFormat
        | FileFormat::Av1ImageFileFormatSequence
        | FileFormat::HighEfficiencyImageCoding
        | FileFormat::HighEfficiencyImageCodingSequence
        | FileFormat::HighEfficiencyImageFileFormat
        | FileFormat::HighEfficiencyImageFileFormatSequence
        | FileFormat::Mpeg4Part14
        | FileFormat::AppleItunesAudio
        | FileFormat::AppleItunesAudiobook
        | FileFormat::AppleItunesProtectedAudio
        | FileFormat::AppleItunesVideo
        | FileFormat::ThirdGenerationPartnershipProject
        | FileFormat::ThirdGenerationPartnershipProject2
        | FileFormat::CompoundFileBinary
        | FileFormat::RoshalArchive
        | FileFormat::SevenZip
        | FileFormat::Xz
        | FileFormat::Sqlite3
        | FileFormat::TapeArchive
        | FileFormat::WindowsBitmap
        | FileFormat::AdvancedSystemsFormat
        | FileFormat::Jpeg2000Part1
        | FileFormat::Jpeg2000Part2
        | FileFormat::Jpeg2000Part3
        | FileFormat::Jpeg2000Part6
        | FileFormat::JpegNetworkGraphics
        | FileFormat::MultipleImageNetworkGraphics
        | FileFormat::CanonRaw2
        | FileFormat::NikonElectronicFile => true,
        FileFormat::JointPhotographicExpertsGroup => has_jpeg_header(header),
        FileFormat::TagImageFileFormat => {
            header.starts_with(b"II\x2a\x00\x08\x00\x00\x00")
                || header.starts_with(b"MM\x00\x2a\x00\x00\x00\x08")
        }
        FileFormat::FreeLosslessAudioCodec => {
            matches!(
                header.get(4..8),
                Some(b"\x00\x00\x00\x22" | b"\x80\x00\x00\x22")
            )
        }
        FileFormat::MusicalInstrumentDigitalInterface => {
            header.get(4..8) == Some(b"\x00\x00\x00\x06")
        }
        FileFormat::OggMultiplexedMedia
        | FileFormat::OggOpus
        | FileFormat::OggSpeex
        | FileFormat::OggTheora
        | FileFormat::OggVorbis
        | FileFormat::OggFlac
        | FileFormat::OggMedia => header.get(4) == Some(&0),
        FileFormat::PortableDocumentFormat => {
            header.starts_with(b"%PDF-1.") || header.starts_with(b"%PDF-2.")
        }
        FileFormat::Zip => has_zip_header(header),
        FileFormat::Gzip => has_gzip_header(header),
        FileFormat::AppleQuicktime => header.get(4..12) == Some(b"ftypqt  "),
        FileFormat::ExtensibleBinaryMetaLanguage => {
            header.windows(7).any(|bytes| bytes == b"\x42\x82\x84webm")
                || header
                    .windows(11)
                    .any(|bytes| bytes == b"\x42\x82\x88matroska")
        }
        FileFormat::Id3v2 => {
            header.len() >= 10
                && header[4] == 0
                && header[6..10].iter().all(|byte| byte & 0x80 == 0)
        }
        // Unknown, ambiguous, and newly added crate variants pass until vetted.
        _ => false,
    }
}

fn has_jpeg_header(header: &[u8]) -> bool {
    header.starts_with(b"\xff\xd8\xff\xdb\x00\x43")
        || header.starts_with(b"\xff\xd8\xff\xdb\x00\x84")
        || header.starts_with(b"\xff\xd8\xff\xe0") && header.get(6..11) == Some(b"JFIF\x00")
        || header.starts_with(b"\xff\xd8\xff\xe1") && header.get(6..12) == Some(b"Exif\x00\x00")
}

fn has_zip_header(header: &[u8]) -> bool {
    header.starts_with(b"PK\x03\x04")
        && matches!(
            header.get(4..6),
            Some(b"\x0a\x00" | b"\x14\x00" | b"\x2d\x00")
        )
        || header.starts_with(b"PK\x05\x06") && header.get(4..8) == Some(b"\x00\x00\x00\x00")
}

/// Match document openers, allowing a UTF-8 BOM, whitespace, and mixed case.
fn has_html_header(header: &[u8]) -> bool {
    let header = header.strip_prefix(b"\xef\xbb\xbf").unwrap_or(header);
    let header = header.trim_ascii_start();
    // Avoid short tags such as <p> or <a>: they match random ciphertext too often.
    [b"<!doctype html".as_slice(), b"<html", b"<head", b"<body"]
        .iter()
        .any(|opener| {
            header
                .get(..opener.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(opener))
                && header
                    .get(opener.len())
                    .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'>')
        })
}

/// Recognize an XML declaration with its required whitespace delimiter.
fn has_xml_header(header: &[u8]) -> bool {
    let header = header.strip_prefix(b"\xef\xbb\xbf").unwrap_or(header);
    let header = header.trim_ascii_start();
    header.starts_with(b"<?xml")
        && header
            .get(5)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

/// Recognize Windows PE images (EXE/DLL) using both DOS and PE signatures.
fn has_pe_header(content: &[u8]) -> bool {
    if !content.starts_with(b"MZ") {
        return false;
    }
    let Some(offset_bytes) = content.get(0x3c..0x40) else {
        return false;
    };
    let offset = u32::from_le_bytes([
        offset_bytes[0],
        offset_bytes[1],
        offset_bytes[2],
        offset_bytes[3],
    ]);
    let Ok(offset) = usize::try_from(offset) else {
        return false;
    };
    // The signature must follow the DOS header and fit in the offered chunk.
    if offset < 0x40 {
        return false;
    }
    let Some(end) = offset.checked_add(4) else {
        return false;
    };
    content.get(offset..end) == Some(b"PE\x00\x00")
}

/// Check gzip's fixed header fields without interpreting optional fields.
fn has_gzip_header(header: &[u8]) -> bool {
    header.len() >= 10
        && header.starts_with(b"\x1f\x8b\x08") // gzip magic and DEFLATE method
        && header[3] & 0xe0 == 0 // Reserved flag bits
        && matches!(header[8], 0 | 2 | 4) // Known DEFLATE extra flags
        && matches!(header[9], 0..=13 | 255) // Defined OS identifiers or unknown
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::has_file_header;

    #[test]
    fn recognizes_common_file_headers() {
        let headers: &[&[u8]] = &[
            b"\x89PNG\r\n\x1a\n",
            b"GIF87a",
            b"GIF89a",
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
            b"\xff\xd8\xff\xe1\x00\x20Exif\x00\x00",
            b"\xff\xd8\xff\xdb\x00\x43",
            b"II\x2a\x00\x08\x00\x00\x00",
            b"MM\x00\x2a\x00\x00\x00\x08",
            b"BM\x36\x00\x00\x00\x00\x00\x00\x00",
            b"RIFF\x20\x00\x00\x00WEBPVP8 ",
            b"RIFF\x20\x00\x00\x00WAVEfmt ",
            b"RIFF\x20\x00\x00\x00AVI ",
            b"FORM\x20\x00\x00\x00AIFF",
            b"FORM\x20\x00\x00\x00AIFC",
            b"ID3\x04\x00\x00\x00\x00\x01\x00",
            b"OggS\x00",
            b"fLaC\x00\x00\x00\x22",
            b"MThd\x00\x00\x00\x06",
            b"\x00\x00\x00\x18ftypisom",
            b"\x00\x00\x00\x18ftypM4A ",
            b"\x00\x00\x00\x18ftypavif",
            b"\x00\x00\x00\x18ftypheic",
            b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\x82\x84webm",
            b"\x1a\x45\xdf\xa3\xa3\x42\x86\x81\x01\x42\x82\x88matroska",
            b"%PDF-1.7",
            b"%PDF-2.0",
            b"PK\x03\x04\x14\x00",
            b"PK\x05\x06\x00\x00\x00\x00",
            b"Rar!\x1a\x07\x00",
            b"Rar!\x1a\x07\x01\x00",
            b"7z\xbc\xaf\x27\x1c",
            b"\xfd7zXZ\x00",
            b"SQLite format 3\x00",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c", // ASF
            b"\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a\x00\x00\x00\x14ftypjp2 ",
            b"\x00\x00\x00\x18ftypiso6",
            b"\x00\x00\x00\x18ftypM4B ",
        ];
        for header in headers {
            assert!(has_file_header(header), "missed {header:?}");
            let mut chunk = header.to_vec();
            chunk.resize(1024 * 1024, 0xa5);
            assert!(has_file_header(&chunk), "missed padded {header:?}");
        }
    }

    #[test]
    fn permits_short_ambiguous_and_headerless_content() {
        for content in [
            &b""[..],
            b"B",
            b"BM",
            b"ID3",
            b"\xff\xd8\xff",
            b"RIFF",
            b"ftyp",
            b"hello world",
            b"{\"some\":\"json\"}",
            b"\x00\x00\x00\x18ftyp????",
            b"BM12345678",
            b"ID3\xff\x00\x00\x00\x00\x00\x00",
            b"ID3\x04\x00\x00\x80\x00\x00\x00",
        ] {
            assert!(!has_file_header(content), "rejected {content:?}");
        }
        for len in 0..=64 {
            assert!(!has_file_header(&vec![0xa5; len]));
        }
        // Signatures inside ciphertext are not file headers.
        let mut content = vec![0xa5; 1024];
        content.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        assert!(!has_file_header(&content));
        let mut content = b"\x1a\x45\xdf\xa3".to_vec();
        content.resize(64, 0xa5);
        content.extend_from_slice(b"\x42\x82\x84webm");
        assert!(!has_file_header(&content));
    }

    #[test]
    fn crate_classification_alone_does_not_reject_ambiguous_signatures() {
        for bytes in [
            b"MZ".as_slice(),
            b"\x1f\x8b",
            b"\xff\xd8\xff",
            b"PK\x03\x04",
            b"\xff\n",   // JPEG XL codestream has only two magic bytes
            b"%!",       // PostScript
            b"\x30\x82", // DER certificate
            b"\xff\xf1", // AAC
            b"\x00\x02", // COFF
        ] {
            assert_ne!(
                file_format::FileFormat::from_bytes(bytes),
                file_format::FileFormat::ArbitraryBinaryData,
                "fixture must be recognized by the crate: {bytes:?}"
            );
            assert!(!has_file_header(bytes), "ambiguous match: {bytes:?}");
            let mut chunk = bytes.to_vec();
            chunk.resize(1024, 0xa5);
            assert!(
                !has_file_header(&chunk),
                "padded ambiguous match: {bytes:?}"
            );
        }
    }

    #[test]
    fn recognizes_html_document_openers_without_matching_short_tags() {
        for html in [
            &b"<!DOCTYPE html>\n<html>"[..],
            b"<!doctype HTML PUBLIC \"example\">",
            b"<html>",
            b"<HtMl lang=\"en\">",
            b" \t\r\n<head><title>Example</title>",
            b"\xef\xbb\xbf\n<body class=\"example\">",
        ] {
            assert!(has_file_header(html), "missed {html:?}");
        }
        for content in [
            &b"<htmlish>"[..],
            b"<header>",
            b"<bodyguard>",
            b"<!doctype htmlish>",
            b"<html",
            b"<p>",
            b"<a href=\"example\">",
            b"text before <html>",
            b"<!-- just a comment -->",
        ] {
            assert!(!has_file_header(content), "rejected {content:?}");
        }
        let mut beyond_limit = vec![b' '; 64];
        beyond_limit.extend_from_slice(b"<html>");
        assert!(!has_file_header(&beyond_limit));
    }

    #[test]
    fn recognizes_gzip_with_optional_fields_and_varied_compression() {
        use std::io::Write;

        for compression in [
            flate2::Compression::none(),
            flate2::Compression::fast(),
            flate2::Compression::default(),
            flate2::Compression::best(),
        ] {
            let mut encoder = flate2::GzBuilder::new()
                .mtime(1_700_000_000)
                .filename("example.tar")
                .comment("test archive")
                .extra(vec![1, 2, 3, 4])
                .write(Vec::new(), compression);
            encoder
                .write_all(b"example file contents")
                .expect("compress");
            let compressed = encoder.finish().expect("finish gzip");
            assert!(has_file_header(&compressed));
        }
        let gzip = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff";
        assert!(has_file_header(gzip));
        for len in 0..gzip.len() {
            assert!(!has_file_header(&gzip[..len]));
        }
        for (index, invalid) in [(2, 7), (3, 0x20), (8, 0xff), (9, 0xfe)] {
            let mut header = *gzip;
            header[index] = invalid;
            assert!(!has_file_header(&header));
        }
    }

    #[test]
    fn recognizes_tar_magic_only_at_its_fixed_offset() {
        for header in [tar::Header::new_ustar(), tar::Header::new_gnu()] {
            let bytes = header.as_bytes();
            assert!(has_file_header(bytes));
            assert!(has_file_header(&bytes[..265]));
            assert!(!has_file_header(&bytes[..264]));
            assert!(!has_file_header(&bytes[1..]));
            let mut damaged = *bytes;
            damaged[263] ^= 0x01; // Unsupported magic/version pair
            assert!(!has_file_header(&damaged));
        }
        assert!(!has_file_header(tar::Header::new_old().as_bytes()));
        assert!(!has_file_header(b"ustar\x0000"));
    }

    #[test]
    fn requires_complete_sqlite_and_xz_signatures_at_the_start() {
        for signature in [b"SQLite format 3\x00".as_slice(), b"\xfd7zXZ\x00"] {
            for len in 0..signature.len() {
                assert!(!has_file_header(&signature[..len]));
            }
            let mut embedded = vec![0xa5; 8];
            embedded.extend_from_slice(signature);
            assert!(!has_file_header(&embedded));
            let mut damaged = signature.to_vec();
            let last = damaged.last_mut().expect("signature terminator");
            *last = 1;
            assert!(!has_file_header(&damaged));
        }
    }

    #[test]
    fn recognizes_xml_declarations_with_bom_and_whitespace() {
        for xml in [
            b"<?xml version=\"1.0\"?><root/>".as_slice(),
            b"<?xml\tversion='1.1'?><root/>",
            b"\xef\xbb\xbf<?xml version='1.0'?>",
            b"\n \t<?xml\r\nversion='1.0'?>",
        ] {
            assert!(has_file_header(xml), "missed {xml:?}");
        }
        for content in [
            b"<?xml".as_slice(),
            b"<?xml?>",
            b"<?xml-stylesheet href='x'?>",
            b"<?xmlish ?>",
            b"<?XML version='1.0'?>",
            b"<root/>",
            b"text before <?xml version='1.0'?>",
        ] {
            assert!(!has_file_header(content), "rejected {content:?}");
        }
        let mut beyond_limit = vec![b' '; 64];
        beyond_limit.extend_from_slice(b"<?xml version='1.0'?>");
        assert!(!has_file_header(&beyond_limit));
    }

    #[test]
    fn recognizes_exe_and_dll_with_pe_signatures_beyond_the_prefix() {
        for (offset, characteristics) in [(0x80_u32, 0x0002_u16), (0x1000, 0x2002)] {
            let offset_usize = usize::try_from(offset).expect("PE offset");
            let mut image = vec![0; offset_usize + 24];
            image[..2].copy_from_slice(b"MZ");
            image[0x3c..0x40].copy_from_slice(&offset.to_le_bytes());
            image[offset_usize..offset_usize + 4].copy_from_slice(b"PE\x00\x00");
            image[offset_usize + 22..offset_usize + 24]
                .copy_from_slice(&characteristics.to_le_bytes());
            assert!(has_file_header(&image));
            assert!(!has_file_header(&image[..offset_usize + 3]));
            image[offset_usize + 2] = 1;
            assert!(!has_file_header(&image));
        }
    }

    #[test]
    fn permits_mz_without_a_valid_pe_signature() {
        assert!(!has_file_header(b"MZ"));
        assert!(!has_file_header(&[b'M', b'Z', 0, 0]));
        for offset in [0_u32, 2, 0x3c, 0x40, 0x80, u32::MAX] {
            let mut content = vec![0; 0x80];
            content[..2].copy_from_slice(b"MZ");
            content[0x3c..0x40].copy_from_slice(&offset.to_le_bytes());
            assert!(!has_file_header(&content));
        }
        // A PE marker at a different offset from the DOS pointer is insufficient.
        let mut content = vec![0; 256];
        content[..2].copy_from_slice(b"MZ");
        content[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        content[0xc0..0xc4].copy_from_slice(b"PE\x00\x00");
        assert!(!has_file_header(&content));
    }
}
