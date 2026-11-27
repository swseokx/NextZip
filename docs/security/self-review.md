# 보안 자체 점검표 (스펙 9장)

점검일: 2026-11-22 (M5). 점검자: 개발 세션 자체 점검(외부 검토 아님).
위협 모델은 [threat-model.md](threat-model.md)를 보세요.

표기: ✅ 확인·통과 / 🔧 M5에서 고침 / ⚠️ 공백(사용자 결정 필요) / ➖ 범위 밖

## 1. 경로 조작

| 점검 항목 | 결과 | 근거 |
|---|---|---|
| `../`, `..\` 가 들어간 이름 | ✅ 압축 파일 전체 거부 | `safepath::sanitize`, `walk::safe_relative`; `tests/security.rs` |
| 절대 경로 `/x`, `C:\x`, `C:x`, `\\server\x`, `\\?\` | ✅ 전체 거부 | `traversal_absolute_drive_and_stream_names_are_rejected` |
| 끝에 공백·점이 붙은 `.. `, `...` (Windows가 `..`로 바꿈) | 🔧 nz-core에서 `..`로 취급해 거부 | `dot_dot_with_trailing_space_or_dot_is_rejected`. M5 전에도 tar 경로는 다른 이유로 실패해 실제 탈출은 없었음(방어 보강) |
| `:` (대체 데이터 스트림), NUL | 🔧 nz-core에서 거부 | 같은 테스트 |
| 예약어 CON, NUL, COM1, `nul.txt`, 끝의 점·공백 | 🔧 nz-core에서도 `_CON`, `_nul.txt`, 점·공백 제거 | `reserved_names_are_renamed`. M5 전에는 nz-core 경로에서 실패했음 |
| 이름을 바꿨을 때 사용자에게 알림 (스펙 "이름 변경 후 알림") | 🔧 "Windows에서 쓸 수 없는 이름이라 바꾼 항목 N개 (예: CON → _CON)" 알림. GUI·CLI 모든 형식(tar 계열은 nz-core의 이름 훅) | `safepath::rename_notice`, `renamed_names_are_reported`, `tar_renamed_names_are_reported` |

## 2. 링크

| 점검 항목 | 결과 | 근거 |
|---|---|---|
| 격리 디코더 경로(RAR, 레거시 형식) | ✅ 링크를 만들지 않음 | `extract_isolated`의 `jobs.retain(... link.is_none())` |
| tar 계열: 대상 밖을 가리키는 심볼릭 링크 | ✅ 만들지 않고 경고 | `resolve_inside` |
| tar 계열: 먼저 푼 링크(`p -> sub`)를 거쳐 `p/../..` 식으로 탈출 | 🔧 **실제 취약점이었음.** 링크를 거치는 경로는 거부 | `links_cannot_escape_the_output_folder`. nz-core 수정 전 코드로 되돌려 재현 확인 |
| 하드 링크 대상 | ✅ 압축 안 경로만, 정리 후 출력 폴더 기준 | `make_link` |
| 기본값 "링크를 일반 파일로 풀기" | 🔧 링크는 대상 경로를 담은 텍스트 파일로 풂. 실제 링크는 설정·`-symlinks`(기본 꺼짐) | 6절 D1, `links_become_text_files_by_default` |

## 3. 압축 폭탄

| 점검 항목 | 결과 | 근거 |
|---|---|---|
| 선언 크기 합계 상한 (ZIP, ALZ, EGG, 7z) | 🔧 ZIP 외 형식에도 적용. 상한 = 압축 파일 × 4096 + 1 GiB, 최대 64 GiB | `check_total`, `declared_total_over_ratio_limit_is_rejected` |
| 겹치는 로컬 헤더·데이터 (overlapping zip bomb) | 🔧 해제 전에 거부 | `check_zip_layout`, `overlapping_zip_members_are_rejected` |
| 데이터가 파일 밖을 가리킴 | 🔧 거부 | `zip_member_outside_the_file_is_rejected` |
| 격리 경로의 실제 출력량 | ✅ 항목·합계 모두 같은 상한으로 중단, 잘린 파일은 지움 | `isolated::extract` |
| 디코더 무한 출력·무한 루프 | 🔧 unarc-rs HA 패치 + 자식 감시(시간·메모리) + 부모 300초 | `tests/runaway.rs`, `tests/hang.rs` |
| 파일 수 상한 (스펙 "파일 수 상한") | 🔧 압축 파일 바이트 수 + 10,000개. 넘으면 쓰기 전에 멈춤 | 6절 D3, `tar_entry_and_size_limits` |
| tar.gz/xz/bz2/zst (nz-core 스트리밍) 출력량 상한 | 🔧 격리 경로와 같은 상한(압축 파일 × 4096 + 1 GiB, 최대 64 GiB)을 항목 헤더 크기로 쓰기 전에 검사 | `nz_core::ExtractOptions`, `tar_output_over_the_limit_is_rejected` |

## 4. 샌드박스·메모리

| 점검 항목 | 결과 | 근거 |
|---|---|---|
| nz-decode: 낮은 무결성, 권한 제거, 실패 시 실행 거부 | ✅ | `nz_sandbox::lockdown`, `isolation` 테스트(파일 쓰기·프로세스 생성 실패 확인) |
| nz-decode: 잡 오브젝트 메모리 3 GiB, 자식 프로세스 금지, 부모 종료 시 함께 종료 | ✅ | `CHILD_MEMORY`, `Contained` |
| nz-decode: 시간·메모리 감시 | 🔧 30초 + MiB당 1초, 커밋 256 MiB + 2×크기 + 압축 크기 | `isolated::watchdog` |
| 릴리스 빌드에서도 손상된 HA 입력이 빨리 실패 | 🔧 1초 안 | `damaged_ha_fails_fast_in_debug_and_release` |
| 디코더 패닉이 오류가 됨 (디버그·릴리스) | 🔧 | `decoder_panic_is_an_error` |
| 주 프로세스의 C 코덱 (libdeflate, zstd, liblzma, bzip2, lz4) | ➖ 사용자 결정으로 유지(속도). 퍼징 타깃 `core_tar`·`core_7z`·`codecs`로 보강, LZMA 사전 할당을 출력 크기로 제한 | 6절 D4 |
| 주 프로세스 메모리: ZIP·ALZ·EGG 항목을 통째로 메모리에 풂 (항목당 최대 4 GiB) | 🔧 동시에 메모리에 푸는 항목 크기 합계를 2 GiB로 제한(넘으면 기다림, 2 GiB보다 큰 항목은 혼자 실행) | `MemBudget`, `memory_budget_waits_and_lets_one_big_member_run` |
| AMSI 검사기 프로세스 | ➖ 중간 무결성(데이터만 받음, 파서 없음). AMSI 공급자가 낮은 무결성에서 동작하는지 미확인이라 샌드박스하지 않음 | — |

## 5. 그 밖의 스펙 9장 항목

| 점검 항목 | 결과 | 근거 |
|---|---|---|
| AMSI 연동(별도 프로세스), 해제 전 검사 옵션 | 🔧 기본 켜짐, 설정·`-noscan`으로 끔. 감지 항목은 쓰지 않고 경고 창 | `nz-archive/src/scan.rs`, `tests/malware.rs`(EICAR) |
| Mark-of-the-Web 전파 | 🔧 **없었음.** 인터넷(3)·제한(4) 영역 표시를 푼 파일 모두에 전파 | `nz-archive/src/motw.rs`, `tests/motw.rs` |
| 암호 사용 후 메모리 제로화 | 🔧 키·키스트림·요청 버퍼·`Options` 암호를 사용 후 지움(`zeroize`). nz-formats 내부 사본과 GUI 세션 암호는 남음 | 6절 D7 |
| 암호 관리자 DPAPI | ➖ 암호 관리자 기능 없음 | — |
| 업데이트 서명 검증 | ➖ 업데이트 기능 없음 | — |
| ZipCrypto 생성 시 경고 | ✅ ZipCrypto 생성 기능 자체가 없음 | — |
| 텔레메트리 없음 | ✅ 네트워크 코드 없음 | — |

## 6. 사용자 결정이 필요한 공백

| # | 내용 | 선택지 |
|---|---|---|
| D1 | ~~tar 계열 심볼릭 링크를 실제 링크로 만듦~~ → 사용자 결정 (a): 기본은 대상 경로 텍스트 파일, 실제 링크는 옵션(기본 꺼짐) | — |
| D2 | ~~tar.* 스트리밍 해제에 출력량 상한 없음~~ → M5에서 해결 (nz-core `extract_with`) | — |
| D3 | ~~파일 수 상한 없음~~ → 사용자 결정: 압축 파일 크기 비례(바이트 수 + 1만 개). 근거 측정은 `bench/results/M5-2026-11-22.md` 1.8 | — |
| D4 | 주 프로세스에서 도는 C 코덱 → 사용자 결정 (a): 그대로 두고 퍼징 보완(타깃 3개 추가) | — |
| D5 | ~~항목 통째 메모리 해제~~ → 동시 합계 2 GiB 상한으로 완화 (항목 하나가 최대 4 GiB까지 메모리를 쓰는 것은 그대로) | — |
| D6 | ~~이름 변경 알림 없음~~ → M5에서 해결 (모든 형식, GUI·CLI) | — |
| D7 | ~~암호 제로화 없음~~ → `zeroize` 1.9(MIT OR Apache-2.0) 도입 | — |

## 7. 알려진 한계

- nz-core 경로(7z 기본 코더, tar 계열)의 AMSI 검사와 MotW는 해제가 끝난 뒤 "새로 생기거나 바뀐 파일"을 찾아 처리합니다.
  같은 이름·같은 크기·같은 수정 시각의 파일을 덮어쓴 경우는 바뀐 것으로 보지 않습니다(같은 압축 파일을 같은 폴더에 다시 푼 경우).
  또 검사 전 잠시 디스크에 평문이 있으므로 Defender 실시간 보호가 먼저 잡을 수 있습니다(이때도 감지로 보고).
- 격리 경로에서 64 MiB를 넘는 항목은 검사가 끝날 때까지 `이름.nzpart`로 디스크에 둡니다.
- AMSI 공급자가 없거나(서드파티 백신이 AMSI를 지원하지 않는 경우) 정책으로 꺼져 있으면 검사 없이 풀고 알림만 띄웁니다.
- 300초 부모 무응답 한도 자체를 건드리는 회귀 입력은 이제 없습니다. `tests/hang.rs`의 HA 입력이 패치 뒤 1초 안에 실패하기 때문입니다. 그 한도를 직접 시험하려면 테스트 전용 "멈춘 디코더" 백엔드가 필요합니다(후속 작업).
