# 서드파티 버그 기록 (외부 미보고)

NextZip 1.0 포맷 작업(M3, 2026-11-22) 중 발견한 서드파티 구성 요소의 버그·동작 차이.
사용자 결정에 따라 **외부(업스트림)에는 보고하지 않고 이 문서에만 기록**한다.
버전이 바뀌면 재현 입력으로 다시 확인하고, 고쳐졌으면 우리 쪽 우회를 걷어낸다.

| # | 대상 | 버전 | 증상 | 재현 입력 | 우리 쪽 조치 | 상태 |
|---|---|---|---|---|---|---|
| 1 | lzxd | 0.2.7 | LZX E8 변환이 호출 대상 0을 음수로 취급해 출력이 틀림 | `crates/nz-formats/tests/data/la_cab_lzx_e8.cab` | `third_party/lzxd` 패치 사본 | 우회 중 |
| 2 | unarc-rs HA (ASC/HSC) | 0.8.1 | 손상 입력에서 끝나지 않음 (M5 확인: ASC가 기록된 크기를 넘어 출력을 끝없이 만듦) | `crates/nz-archive/tests/data/fuzz_ha_hang.ha` | `third_party/unarc-rs` 패치(출력 상한), 워커 예산, 부모 무응답 감시 | 패치 |
| 3 | unarc-rs HA (HSC) | 0.8.1 | 덧셈 오버플로 패닉(디버그). 릴리스는 래핑 후 출력이 끝없이 늘어 수십 GB 메모리 사용 | `crates/nz-archive/tests/data/fuzz_ha_overflow.ha` | `third_party/unarc-rs` 패치(출력 상한·문맥 체인 순환 차단), 패닉 가드, 워커 예산 | 패치 |
| 4 | unarc-rs ARC (Squeeze) | 0.8.1 | 노드 테이블이 잘리면 인덱스 범위 초과 패닉 (릴리스 빌드에서도 발생) | 테스트 안에서 생성: `crates/nz-formats/tests/fixtures.rs` `arc_squeeze_short_node_table_is_an_error` | 패닉 가드 | 우회 중 |
| 5 | unarc-rs ACE (LZ77) | 0.8.1 | 블록 기호 수 0에서 뺄셈 오버플로 (디버그 빌드만 패닉, 릴리스는 래핑) | 저장된 입력 없음 (아래 참고) | 패닉 가드, 릴리스는 CRC 검사로 검출 | 우회 중 |
| 6 | 일부 ZIP 해제 프로그램 | - | ZIP 안의 XZ 멤버(메서드 95)가 CRC64 체크면 풀다가 실패 | NextZip ZIPX를 XZ + CRC64로 만들면 재현 | ZIPX XZ는 CRC32 체크로 작성 | 우회 중 |
| 7 | 7-Zip | 26.06 | UTF 플래그 없는 CAB 이름을 OEM 코드페이지로만 해석해 이름이 깨짐 (버그라기보다 동작 차이) | unarc-rs 테스트 데이터 `tests/cab/multi.cab`의 `caf\xE9.txt` | 해당 없음 (NextZip은 코드페이지 감지로 `café.txt`) | 기록만 |

## 상세

### 1. lzxd 0.2.7 — E8 변환

- **위치**: `src/lib.rs` E8 후처리(패치 사본 273행 부근). 절대 대상 주소 판정에 `is_positive()`를 씀.
- **문제**: `is_positive()`는 0을 거짓으로 보므로, 대상이 정확히 0인 E8 호출이 변환되지 않음. 올바른 조건은 `>= 0`.
- **재현**: libarchive 3.8.11 `test_read_format_cab_lzx_e8.cab`(우리 픽스처 `la_cab_lzx_e8.cab`).
  - 패치 전에는 CRC가 불일치함.
  - 7-Zip과 libarchive는 정상.
- **조치**: `third_party/lzxd`(코드 1줄 수정), 워크스페이스 `[patch.crates-io]`. 자세한 내용은 `third_party/README.md`.

### 2. unarc-rs 0.8.1 HA — 무한 루프

- **위치**: `src/ha/hsc.rs`. 연결 리스트 순회(`while blk != NULL_PTR` 등)가 손상된 테이블에서 순환하는 것으로 추정.
- **재현**: `fuzz_ha_hang.ha`(퍼저 `fmt_detect`, 3,885바이트). 디버그 빌드 기준 120초 이상 끝나지 않음. 7-Zip은 HA를 지원하지 않음.
- **조치**:
  - `crates/nz-archive/src/isolated.rs`: 워커가 300초 동안 프레임을 보내지 않으면 종료하고 오류 처리.
  - 대기 중에도 취소가 바로 먹음.
  - 테스트: `crates/nz-archive/tests/hang.rs` `hung_decoder_is_killed`(제한 5초로 확인).
- **퍼징**: `nz_formats::fuzzing`에서 HA는 건너뜀.

### 3. unarc-rs 0.8.1 HA — 덧셈 오버플로

- **위치**: `src/ha/hsc.rs:827` `update_context_stats`의 `ctx_rescale_factor[idx] += 1`(u8).
- **재현**: `fuzz_ha_overflow.ha`(퍼저 `fmt_detect`).
- **조치**: `nz_formats::guard`의 `catch_unwind`가 "damaged archive (decoder fault: …)" 오류로 바꿈. 테스트: `tests/hang.rs` `decoder_panic_is_an_error`.
- **참고**: Windows의 libFuzzer는 패닉 되감기 자체를 크래시로 잡으므로, 퍼징에서는 가드까지 가지 못함.

### 4. unarc-rs 0.8.1 ARC — Squeeze 인덱스 범위 초과

- **위치**: `src/arc/unsqueeze.rs:24`. 노드 수를 읽은 뒤 `get_i16!`이 버퍼 길이를 확인하지 않음.
- **재현**: 노드 수 2, 뒤에 1바이트만 있는 squeezed(메서드 4) 멤버. 테스트가 직접 만듦.
  - 퍼저 `fmt_legacy`(`-O` 빌드)가 135,311회째 발견.
  - Windows libFuzzer가 아티팩트를 남기지 못해 입력을 다시 만들었음.
- **조치**: 패닉 가드. 테스트: `crates/nz-formats/tests/fixtures.rs` `arc_squeeze_short_node_table_is_an_error`.

### 5. unarc-rs 0.8.1 ACE — LZ77 기호 수 뺄셈 오버플로

- **위치**: `src/ace/lz77.rs:150` `read_main_symbol`. `read_trees` 뒤 새 블록의 기호 수가 0이면 `symbols_remaining -= 1`이 언더플로.
- **재현**: 퍼저 `fmt_legacy`(오버플로 검사 켠 빌드) 약 12,800회째. 입력은 저장되지 않음.
- **영향**: 릴리스 빌드는 래핑되어 패닉 없이 진행하고, 결과는 CRC 검사에서 걸림.
- **조치**: 패닉 가드(디버그 빌드), 릴리스는 CRC.

### 6. 일부 ZIP 해제 프로그램 — ZIP 안 XZ의 CRC64 체크

- **증상**: ZIP 메서드 95(XZ) 멤버의 XZ 스트림 체크 타입이 CRC64(0x04)이면 일부 해제 프로그램이 풀다가 실패.
  - 7-Zip과 WinZip은 정상.
  - CRC32(0x01)면 모두 정상.
- **재현**: `nz-create` ZIPX에서 `zipx.rs`의 XZ 인코더 체크를 `Check::Crc64`로 바꿔 만든 뒤 외부 해제 프로그램으로 풂.
- **조치**: ZIPX XZ는 7-Zip처럼 CRC32 체크로 작성. 코드 주석은 `crates/nz-create/src/zipx.rs`.

### 7. 7-Zip 26.06 — CAB 레거시 이름

- **증상**: UTF 플래그가 없는 CAB 이름 바이트 `63 61 66 E9 2E 74 78 74`(cp1252 `café.txt`)를 7-Zip이 시스템 OEM 코드페이지(이 PC는 cp949)로 읽음.
  - `E9 2E`가 2바이트 문자로 묶여 `caf?txt`가 되고, 점이 사라짐.
- **판단**: 레거시 이름의 코드페이지가 모호해서 생기는 동작 차이. 엄밀한 버그는 아님.
- **NextZip 동작**: 코드페이지 감지로 `café.txt`.

### M5 추가 (2026-11-22): HA 디코더 패치

- release 빌드(오버플로 검사 꺼짐)에서 #3 입력은 패닉 대신 출력을 끝없이 메모리에 쌓았다(격리 프로세스에서는 초당 약 35MB, `nz-formats` 프로세스 내 테스트는 68GB까지 커짐). #2 입력도 같은 원인(ASC 출력 무한)이었다.
- `third_party/unarc-rs`(0.8.1 사본)에서 `decompress_hsc`/`decompress_asc`가 헤더에 기록된 원본 크기를 넘으면 "corrupted entry" 오류를 내고, HSC 기호 하나에 문맥 차수보다 많은 escape가 필요하면(순환 체인) 멈추게 했다.
- 별도 방어선: `nz-decode.exe`의 멤버별 시간·메모리 예산(`isolated::watchdog`, 종료 코드 0x4E5A).
- 테스트: `crates/nz-archive/tests/hang.rs`, `tests/runaway.rs`(debug·release 모두 1초 안에 실패), `crates/nz-formats/tests/fixtures.rs` `truncated_and_flipped_fixtures_do_not_panic`(release).
