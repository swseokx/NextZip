#![no_main]

// Disk images and structured storage: ISO 9660/Joliet/Rock Ridge, VHD, VHDX, VMDK, QCOW2, MSI/CFB.
use nz_formats::Format as F;

libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_formats::fuzzing::run_selected(&[F::Iso, F::Vhd, F::Vhdx, F::Vmdk, F::Qcow2, F::Msi], data));
