//! Mark-of-the-Web propagation (spec 9: "인터넷에서 받은 아카이브를 풀면
//! 출력 파일에 MotW를 전파").
//!
//! Windows records where a downloaded file came from in its
//! `Zone.Identifier` alternate data stream. When the archive carries one
//! with a zone of Internet (3) or Restricted (4), every file extracted from
//! it gets a `Zone.Identifier` too, so SmartScreen, Office Protected View
//! and the "this file came from another computer" warnings still apply to
//! the extracted files. This is what Explorer's own ZIP extraction does.

use std::path::Path;

/// Zone at or above which marks are propagated (3: Internet).
const MIN_ZONE: u32 = 3;

/// The `Zone.Identifier` to write on files extracted from `archive`, or
/// None when the archive has no mark (or a local / intranet / trusted one).
pub(crate) fn mark_for(archive: &Path) -> Option<String> {
    if !cfg!(windows) {
        return None;
    }
    let mut ads = std::path::absolute(archive).ok()?.into_os_string();
    ads.push(":Zone.Identifier");
    let text = std::fs::read(&ads).ok()?;
    let text = String::from_utf8_lossy(&text);
    let zone = zone_id(&text)?;
    if zone < MIN_ZONE {
        return None;
    }
    let src = std::path::absolute(archive).ok()?;
    Some(format!(
        "[ZoneTransfer]\r\nZoneId={zone}\r\nReferrerUrl={}\r\n",
        src.display()
    ))
}

/// `ZoneId=` of a `Zone.Identifier` stream.
fn zone_id(text: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim().eq_ignore_ascii_case("ZoneId"))
            .then(|| v.trim().parse().ok())
            .flatten()
    })
}

/// Write `mark` as the `Zone.Identifier` of `file` (best effort: FAT and
/// some network drives have no alternate streams).
pub(crate) fn apply(file: &Path, mark: &str) {
    let mut ads = file.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    let _ = std::fs::write(ads, mark);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zone_id() {
        assert_eq!(zone_id("[ZoneTransfer]\r\nZoneId=3\r\n"), Some(3));
        assert_eq!(
            zone_id("[ZoneTransfer]\nReferrerUrl=x\nZoneId = 4\n"),
            Some(4)
        );
        assert_eq!(zone_id("[ZoneTransfer]\n"), None);
    }
}
