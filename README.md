# NextZip

**빠르고, 거의 모든 압축 파일을 열고, 손상에도 강한 Windows용 압축 프로그램.**
광고도 텔레메트리도 없습니다. 엔진부터 GUI까지 Rust로 새로 만들었습니다.

- **64가지 형식 풀기, 16가지 형식 + `.nz` 만들기** — ZIP·7Z·RAR·ALZ·EGG부터 디스크 이미지와 고전 아카이브까지
- **모든 코어를 끝까지 쓰는 병렬 엔진** — ZIP 압축 초당 약 500~800 MB, 64개를 넘는 논리 CPU(프로세서 그룹)도 활용
- **스레드 수와 상관없이 같은 결과** — 1스레드로 만들든 수십 스레드로 만들든 아카이브는 바이트까지 같습니다
- **`.nz` 네이티브 포맷** — 복구 기록, 중복 제거 백업, 스냅샷, 파일 이름까지 숨기는 AEAD 암호화
- **받은 압축 파일을 안전하게** — 격리된 저권한 디코더, AMSI 악성코드 검사, Mark-of-the-Web 유지, 압축 폭탄 차단

## 지원 형식

### 풀기 (64종)

| 분류 | 형식 |
|---|---|
| 주요 아카이브 | ZIP (Deflate, Deflate64, BZip2, LZMA, PPMd, XZ, Zstd, AES, ZipCrypto, ZIP64, 분할), ZIPX, 7Z (LZMA/LZMA2, PPMd, BZip2, Deflate, Zstd, BCJ/ARM64/Delta 필터, AES), RAR 4 / RAR 5 (분할 포함), ALZ, EGG |
| TAR 계열 | TAR, TAR.GZ, TAR.XZ, TAR.BZ2, TAR.LZ4, TAR.ZST (그 밖의 스트림 압축 안의 TAR 포함) |
| 단일 스트림 | GZ, BZ2, XZ, LZMA, LZIP, ZST, LZ4, BR(Brotli), Z |
| 패키지·설치 파일 | CPIO (bin LE/BE, odc, newc, crc), AR, DEB, RPM, ASAR, XAR, MSI, CAB (MSZIP, LZX) |
| 디스크 이미지 | ISO 9660 + Joliet, VHD (고정/동적), VHDX, VMDK (sparse/stream-optimized), QCOW2 |
| 인코딩 | UUE, XXE |
| 고전 아카이브 | ACE, ARC/PAK, ARJ (분할 포함), ZOO, LHA/LZH, HA, UC2, SQ, SQZ, HYP, JAR(ARJ) |
| 레트로 이미지 | Amiga LZX, DMS, ADF, HDF, Pack-Ice, Commodore D64·T64·Lynx, Atari ATR, FAT 플로피 |
| 변형 | 자동 풀림(SFX) EXE (PE/ELF 스텁 + 7z·RAR·ZIP), 앞에 데이터가 붙은 ZIP, `.001` 분할 세트 |

옛 한국어·일본어·중국어 압축 파일의 이름은 **코드페이지 자동 판별**(CP949, Shift_JIS, GBK, Big5 등)로 바로잡고, 판별 근거를 보여 주며 직접 바꿀 수도 있습니다.

### 만들기 (16종 + 네이티브 `.nz`)

| 형식 | 특징 |
|---|---|
| **ZIP** | 블록 병렬 Deflate(libdeflate + 자체 컨테이너 인코더). 어디서나 열리는 표준 ZIP |
| **7Z** | 파일 유형별 코덱 라우팅(텍스트 → LZMA2, 실행 파일 → BCJ x86 + LZMA2, 이미 압축된 데이터 → zstd), 유형별 솔리드 블록 병렬 압축, 압축 헤더 |
| **TAR, TAR.GZ, TAR.XZ, TAR.BZ2, TAR.LZ4, TAR.ZST** | PAX 긴 이름·UTF-8, 심볼릭 링크, 청크 병렬 압축(gzip은 pigz 방식, bzip2는 pbzip2 방식), 64 MiB 독립 zstd 프레임으로 병렬 해제 |
| **ZIPX** | zstd, LZMA, PPMd, XZ, BZip2 메서드 |
| **ISO** | ISO 9660 Level 2 + Joliet, 4 GiB 넘는 파일은 multi-extent |
| **GZ, XZ, BZ2, ZST, LZ4** | 파일 하나 압축 |
| **EXE SFX** | x64·ARM64 자동 풀림 실행 파일 (표준 7z 페이로드, 7-Zip으로도 열림) |
| **NZ** | NextZip 네이티브 포맷 (아래) |

## 성능

아래 수치는 모두 Ryzen 5 9600X(물리 6코어, 논리 12), Windows 11, **Defender 실시간 보호 켜짐**, 기본 12스레드에서 `nz bench`로 잰 값입니다(워밍업 1회 + 7회 측정 중앙값, 프로세스 시작 비용 포함, 해제 결과는 원본과 바이트 단위로 검증).

- **텍스트 세트**: 소스·문서·데이터 파일 1,211개, 27.38 MiB
- **혼합 세트**: 텍스트 + 실행 파일 + JAR 등 1,444개, 100.25 MiB

### 압축

| 형식·레벨 | 텍스트: 압축률 / 시간 | 혼합: 압축률 / 시간 |
|---|---|---|
| ZIP `-l:5` (기본) | **50.98%** / 0.056 s (**약 510 MB/s**) | **68.87%** / 0.133 s (**약 790 MB/s**) |
| TAR.GZ `-l:5` | 49.79% / 0.105 s (약 260 MB/s) | 68.14% / 0.321 s (약 310 MB/s) |
| TAR.ZST `-l:5` | 48.35% / 0.209 s (약 130 MB/s) | 64.77% / 0.732 s (약 137 MB/s) |
| 7Z `-l:6` | **45.24%** / 0.85 s (약 32 MB/s) | **62.18%** / 2.41 s (약 40 MB/s) |
| 7Z `-l:9` | 44.93% / 2.5 s | 61.88% / 11.9 s |
| NZ `-l:5` (복구 기록 3% 포함) | 51.81% / 0.159 s (약 170 MB/s) | 69.31% / 0.368 s |

압축률은 "압축 파일 크기 ÷ 원본 크기"이며 작을수록 좋습니다. 7Z `-l:6`은 텍스트에서 LZMA2 단일 스트림 수준(45.4%)보다 작게 줄이면서 모든 코어를 씁니다.

### 해제

| 케이스 | 시간 | 처리량 |
|---|---:|---:|
| ZIP 혼합 세트 | 0.347 s | 약 300 MB/s |
| ZIP 혼합 세트, Defender 예외 폴더 (엔진 자체) | 0.19~0.20 s | 약 500 MB/s |
| 7Z 혼합 세트 | 0.43 s | 약 245 MB/s |
| 7Z 텍스트 세트 | 0.29 s | 약 95 MB/s |
| TAR.ZST 2.1 GB 단일 파일 | 1.01 s | **약 2.1 GB/s** |

파일 1,000개 이상을 푸는 작업은 계산보다 NTFS 파일 생성·쓰기와 실시간 검사가 대부분을 차지합니다. NextZip은 7z 폴더·zstd 프레임·청크 단위로 디코딩을 병렬화하고, 파일 쓰기를 별도 작업자에 넘겨 이 바닥에 최대한 붙습니다.

### 시작과 메모리

- GUI 콜드 스타트: 빈 화면 **약 96 ms**, 압축 파일 열기 **약 121 ms**
- 최대 메모리: 혼합 세트 7Z `-l:6`에서 commit 820 MiB. 메모리 예산(`NZ_MEM_MIB`, 기본은 남은 RAM의 절반, 256~880 MiB)이 작업 스케줄만 조절하고 결과 바이트는 바꾸지 않습니다.

측정 원자료와 분석은 [`bench/results/`](bench/results/)에 있습니다.

## 멀티스레딩

- **기본 스레드 수 = 시스템의 모든 논리 CPU.** Windows의 64-CPU 프로세서 그룹 경계를 넘어, 모든 그룹을 세어 작업자를 그룹 크기에 비례해 나누고 각 작업자를 해당 그룹에 고정합니다(`-t:N`으로 바꿀 수 있음).
- **결정적 출력.** 모든 작성기는 작업을 스레드 수가 아니라 입력 크기로만 나눕니다. 그래서 `-t:1`, `-t:3`, `-t:12`로 만든 아카이브가 바이트까지 같고, 테스트가 매번 이를 확인합니다.
- **큰 일부터.** 7z는 모든 LZMA2 세그먼트와 블록 작업을 예상 비용 순으로 정렬해(LPT 스케줄) 긴 작업이 늦게 시작해 꼬리를 남기지 않게 합니다.
- **기다리지 않는 파이프라인.** 파일 읽기, 압축, 순서대로 쓰기가 겹쳐서 돌고, 디렉터리 탐색도 병렬입니다.
- 1→12스레드 확장은 물리 6코어 장비에서 4.3~4.9배입니다.

## `.nz` 네이티브 포맷

공개 사양 [`docs/nz-format-v1.md`](docs/nz-format-v1.md)(v1.0, 안정)과 MIT 라이선스 참조 구현 `crates/nz-nzf`가 있습니다. 사양의 테스트 벡터는 테스트가 매번 다시 만들어 비교하므로 문서와 구현이 어긋나지 않습니다.

- **복구 기록**: 섹터 단위 Reed-Solomon(GF(2^16)). 기본 3%. 묶음마다 손상 섹터 수가 패리티 이하이면 완전히 복원합니다(`nz repair`).
- **중복 제거 백업**: FastCDC 내용 기반 청크 + BLAKE3. `nz backup`으로 같은 `.nz` 끝에 증분 스냅샷을 더하고, 바뀌지 않은 데이터는 다시 저장하지 않습니다. 중간에 멈춰도 직전 스냅샷은 유효합니다. `nz snapshots` / `nz restore`.
- **AEAD 암호화**: Argon2id 키 유도 + AES-256-GCM 또는 ChaCha20-Poly1305. 파일 이름이 들어 있는 인덱스까지 암호화합니다.
- **독립 블록**: LZ4·zstd·LZMA2·저장 블록을 따로 풀 수 있어 손상이 번지지 않습니다.

## 보안

받은 압축 파일은 누가 만들었는지 모른다는 전제로 설계했습니다.

- **격리 디코더**: RAR과 오래된·희귀한 형식은 별도 프로세스 `nz-decode.exe`에서 읽습니다. Low integrity, 권한 제거, 1-프로세스 Job, 메모리·시간 상한, 프로세스 완화 정책이 걸려 있어 파일을 쓰거나 다른 프로그램을 실행할 수 없습니다. 이름 정리·크기 제한·실제 쓰기는 부모 프로세스가 맡습니다.
- **AMSI 악성코드 검사**: 압축 파일 안의 내용을 디스크에 쓰기 **전에** Windows 보안(또는 AMSI 지원 백신)에 검사받고, 걸린 파일은 쓰지 않습니다.
- **Mark-of-the-Web 유지**: 인터넷에서 받은 압축 파일을 풀면 푼 파일에도 "인터넷에서 받음" 표시를 붙여 Windows·Office 경고가 그대로 동작합니다.
- **압축 폭탄 차단**: 풀린 크기(압축 파일의 4096배 + 1 GiB), 항목 수, 겹치는 ZIP 항목을 검사해 멈춥니다.
- **경로 탈출 차단**: `..`·절대 경로·드라이브 문자가 든 아카이브는 통째로 거부하고, 출력 폴더 밖을 가리키는 링크는 만들지 않습니다. Windows 예약어(`CON`, `NUL` 등)는 안전한 이름으로 바꿉니다.
- **메모리 안전성**: 엔진과 CLI는 `unsafe_code = forbid`. `unsafe`는 Win32·liblzma 경계(`nz-sys`, `nz-xz` 등)에만 있습니다. 리더마다 cargo-fuzz 타깃이 있고, 찾은 입력은 회귀 테스트로 남깁니다. 위협 모델과 자체 검토는 [`docs/security/`](docs/security/)에 있습니다.

## GUI와 탐색기 통합

- **네이티브 Win32 + Direct2D/DirectWrite** GUI. WinUI·웹뷰 없이 가볍고 빠르게 뜹니다. 라이트/다크 테마는 Windows 설정을 따릅니다.
- **탐색기 오른쪽 클릭 메뉴**: Windows 11 최상위 메뉴(`IExplorerCommand`)에 **여기에 풀기 / 폴더로 풀기 / 압축…**.
- 압축 프로필(초고속·균형·고압축·최대), 진행 창의 일시 정지·취소(쓰다 만 파일 정리), 암호 입력, 코드페이지 선택.
- 한국어 / English (Windows 표시 언어 자동 선택).
- 사용자 단위 설치 프로그램(관리자 권한 불필요). 제거하면 설치한 것만 깔끔하게 지웁니다.

사용 설명서: [`docs/user/README.md`](docs/user/README.md) · 명령줄 도구 `nz`: [`docs/user/cli.md`](docs/user/cli.md)

## 명령줄 도구 `nz`

```powershell
nz c archive.7z .\project            # 압축 (형식은 확장자로)
nz c -fmt:zip -l:9 out.zip .\docs    # 형식·레벨 지정
nz x -o:.\out archive.rar            # 풀기 (형식 자동 판별)
nz l archive.zip                     # 목록
nz t archive.nz                      # .nz 검사 (복구 기록 + 모든 블록)
nz backup daily.nz .\work            # .nz 증분 백업
nz bench .\data -cases:zip:5,7z:6    # 벤치마크
```

## 빌드

요구 사항: Rust **1.95 이상**(stable, `x86_64-pc-windows-msvc`), Visual Studio Build Tools(C/C++ — libdeflate, zstd, liblzma, UnRAR를 함께 빌드합니다).

```powershell
cargo build --release
```

```powershell
cargo test --workspace
```

결과물은 `target\release\`의 `nz.exe`(CLI), `nextzip.exe`(GUI), `nz-decode.exe`(격리 디코더), `nextzip_shell.dll`(탐색기 메뉴), `nz-sfx.exe`(SFX 스텁)입니다. x64·ARM64 SFX 스텁과 서명된 설치 파일은 `packaging\build-installer.ps1`이 함께 만듭니다.

## 저장소 구성

| 경로 | 내용 |
|---|---|
| `crates/nz-core` | 압축 엔진: ZIP·7Z·TAR 계열 쓰기·해제, 계획기, 병렬 스케줄러, 프로세서 그룹 스레드 풀 |
| `crates/nz-archive` | 읽기 전용 형식(ALZ, EGG, RAR 등)과 격리 실행 |
| `crates/nz-formats` | 고전·패키지·디스크 이미지 형식 리더 |
| `crates/nz-create` | ZIPX, ISO, 단일 스트림, EXE SFX 만들기 |
| `crates/nz-nzf` | `.nz` 포맷 참조 구현 (MIT) |
| `crates/nz-rar` | RAR 풀기 (UnRAR 라이브러리) |
| `crates/nz-sandbox`, `crates/nz-scan` | 격리 디코더 프로세스, AMSI 검사 |
| `crates/nz-gui`, `crates/nz-shell`, `crates/nz-front` | GUI, 탐색기 메뉴, 공용 프런트엔드·번역 |
| `crates/nz-cli` | `nz` 명령줄 도구, 왕복·호환성 테스트 |
| `crates/nz-sfx`, `crates/nz-setup` | 자동 풀림 스텁, 설치 프로그램 |
| `crates/nz-sys`, `crates/nz-xz` | Win32·liblzma FFI 경계 |
| `fuzz/`, `oss-fuzz/` | 퍼징 타깃 |
| `docs/` | `.nz` 사양, 보안 문서, 사용 설명서 |
| `bench/results/` | 벤치마크 원자료와 보고서 |

## 라이선스

NextZip 코드는 **MIT OR Apache-2.0**입니다. `.nz` 참조 구현 `nz-nzf`는 MIT입니다.

함께 포함·링크하는 서드파티 코드:

| 구성 요소 | 라이선스 | 비고 |
|---|---|---|
| **UnRAR** (`nz-rar`, `unrar_sys`) | UnRAR 라이선스 ([`crates/nz-rar/LICENSE-UNRAR.txt`](crates/nz-rar/LICENSE-UNRAR.txt)) | RAR **풀기 전용**. RAR 압축 알고리즘을 재현하는 데 쓸 수 없습니다 |
| unarc-rs, lzxd (패치 사본, [`third_party/`](third_party/README.md)) | MIT OR Apache-2.0 | 고전 아카이브·CAB 디코더 |
| sevenz-rust2, lzma-rust2 | Apache-2.0 | 7z 확장 코더 |
| libdeflate, zstd, liblzma, lz4 | MIT / BSD / 0BSD·퍼블릭 도메인 / BSD-2-Clause | 코덱 (정적 링크) |
| zlib-rs, libbz2-rs, brotli, ruzstd, ppmd-rust 등 | Zlib / bzip2 / BSD-3-Clause·MIT / MIT / CC0·MIT-0 | 순수 Rust 코덱 |
| 테스트 데이터: libarchive 샘플 | BSD-2-Clause | 각 크레이트 `tests/data`의 `NOTICE.md` |

GPL/LGPL 의존성은 없습니다. 패치한 크레이트의 변경 내용은 [`third_party/README.md`](third_party/README.md)에 있습니다.
