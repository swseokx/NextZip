//! Front-end support shared by `nextzip.exe`, the shell extension, `nz.exe`
//! and the archive facade:
//!
//! * [`prefs`]: user preferences (`%LOCALAPPDATA%\NextZip\settings.txt`):
//!   UI language and malware scanning.
//! * [`i18n`]: UI translations. Korean is the source language; other
//!   languages come from gettext PO catalogs in `i18n/` (spec 8 "접근성·다국어":
//!   Korean and English built in, more by the community).

pub mod i18n;
pub mod prefs;

pub use i18n::{Lang, tr, trf};
