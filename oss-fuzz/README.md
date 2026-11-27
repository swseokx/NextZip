# OSS-Fuzz 등록 준비물

스펙 10.1 "cargo-fuzz + OSS-Fuzz 등록"을 위한 파일입니다. 저장소 공개(2026-11-28) 후 제출 준비를 마쳤습니다.
제출(google/oss-fuzz 저장소에 `projects/nextzip/` 풀 리퀘스트)은 외부로 내보내는 일이라
프로젝트 책임자가 직접 결정하고 진행합니다.

| 파일 | 내용 |
|---|---|
| `project.yaml` | 언어 rust, AddressSanitizer + libFuzzer. 연락처·저장소·홈페이지는 TODO |
| `Dockerfile` | `base-builder-rust` 이미지 + nightly 고정(`nightly-2026-11-19`), 저장소 clone(주소는 TODO). zip·cmake는 기본 이미지에 있어 apt 설치 없음 |
| `build.sh` | `cargo fuzz build -O --fuzz-dir fuzz`로 `cargo fuzz list`의 모든 타깃(현재 16개)을 빌드해 `$OUT`에 복사, 시드 코퍼스 zip, `max_len` 1 MiB |
| `.gitattributes` | 이 폴더 파일을 LF로 유지(`core.autocrlf=true`여도 `build.sh`가 CRLF가 되지 않게) |

## 제출 전에 채울 것

1. 공개 git 저장소 주소: `Dockerfile`의 `git clone` 줄과 `project.yaml`의 `main_repo`.
2. `primary_contact`: 크래시 보고를 받을 메일 주소(OSS-Fuzz는 Google 계정과 연결된 주소를 요구).
3. `homepage`.
4. OSS-Fuzz는 오픈소스이면서 사용자가 많은 프로젝트만 받습니다. 1.0 공개 뒤 신청하는 것이 현실적입니다.

## 로컬 확인 결과 (2026-11-23, Docker 29.9.3)

OSS-Fuzz 저장소를 받아 `projects/nextzip/`에 세 파일을 넣고, `Dockerfile`의 `git clone` 줄만
`RUN mkdir -p $SRC/nextzip`로 바꿔(소스는 로컬 체크아웃을 마운트) 확인했습니다.

| 단계 | 결과 |
|---|---|
| `build_image nextzip` | 통과 |
| `build_fuzzers nextzip <체크아웃>` (address) | 통과, 16개 타깃 모두 빌드 |
| `check_build nextzip` | 통과(16/16) |
| `run_fuzzer nextzip archive` 60초 | 크래시 없음, 약 5.1만 회, cov 1808 |
| `run_fuzzer nextzip nz_recovery` 60초 | 크래시 없음, 약 107만 회, cov 188 |

이때 고친 것:

1. 기본 이미지의 nightly(`nightly-2025-09-05` = rustc 1.91)가 MSRV 1.95보다 낮아
   `Dockerfile`에서 `nightly-2026-11-19`를 설치하고 `RUSTUP_TOOLCHAIN`으로 고정.
   OSS-Fuzz가 기본 nightly를 올리면 이 줄은 지워도 됩니다.
2. `apt-get install zip cmake pkg-config` 제거: 둘 다 기본 이미지에 있고, cmake 의존성(libicu66)
   다운로드가 미러 해시 불일치로 계속 실패했습니다.
3. `build.sh`의 타깃 목록이 하드코딩(14개)이라 `nz_read`, `nz_recovery`가 빠져 있어
   `cargo fuzz list`로 바꿈.
4. `nz-rar`가 Windows 전용 API(`encode_wide`, UTF-16 `wchar_t`)를 써서 Linux에서 컴파일되지 않아
   `wchar_t` 변환을 `cfg(windows)`/`cfg(not(windows))`로 나눔(Windows 동작은 그대로).

### Windows에서 돌릴 때 주의

`infra/helper.py`는 Windows에서 `build_fuzzers`/`check_build`/`run_fuzzer`가 실패합니다
(`docker run -i -t`가 TTY 없이 실패하고, 소스 마운트 경로가 `\src\nextzip`이 됨).
`build_image`는 되므로, 나머지는 helper가 출력하는 `docker run` 명령을 `-t` 없이,
마운트 대상은 `/src/nextzip`으로 직접 실행했습니다. Linux/WSL에서는 README 원래 명령 그대로 됩니다:

```
python infra/helper.py build_image nextzip
python infra/helper.py build_fuzzers nextzip <path to nextzip checkout>
python infra/helper.py check_build nextzip
python infra/helper.py run_fuzzer nextzip archive
```

## 알아 둘 점

- 퍼즈 크레이트(`fuzz/`)는 별도 워크스페이스라 `[patch.crates-io]`를 따로 둡니다.
  M5에서 `unarc-rs` 패치(HA 디코더 출력 한도)를 여기에도 추가했습니다.
- 타깃이 임시 파일(`/tmp/nzfuzz-<pid>.*`)에 입력을 써서 읽습니다. OSS-Fuzz 실행 환경에서 문제없지만,
  나중에 메모리 입력 API로 바꾸면 더 빨라집니다.
- `fmt_legacy`는 HA를 아직 건너뜁니다(`nz_formats::fuzzing`). 무한 출력은 M5 패치로 고쳤지만,
  디버그 단언(overflow) 패닉이 남아 있는지는 퍼징으로 다시 확인해야 합니다.
