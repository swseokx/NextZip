#![no_main]

// unarc-rs legacy readers: ARJ, ACE, ARC, ZOO, LHA, HA, UC2, SQ, SQZ, HYP, JAR, CAB, Amiga LZX/DMS/ADF/HDF, C64, Atari, Lynx, Pack-Ice, FAT.
use nz_formats::Format as F;

libfuzzer_sys::fuzz_target!(|data: &[u8]| nz_formats::fuzzing::run_selected(&[F::Arj, F::Ace, F::Arc, F::Zoo, F::Lha, F::Ha, F::Uc2, F::Sq, F::Sqz, F::Hyp, F::Jar32, F::Cab, F::AmigaLzx, F::Dms, F::Adf, F::Hdf, F::D64, F::T64, F::Lynx, F::Atr, F::PackIce, F::Ice, F::Fat], data));
