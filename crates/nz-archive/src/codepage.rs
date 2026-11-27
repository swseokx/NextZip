//! Statistical code page detection for legacy archive member names.
//!
//! ZIP names without the UTF-8 flag (bit 11) and without a 0x7075 Unicode
//! Path field are, per APPNOTE, CP437; in practice they are in whatever OEM or
//! ANSI code page the writing PC used (Korean tools: CP949, Japanese: Shift_JIS,
//! Chinese: GBK/Big5, Russian: CP866). [`detect`] decodes every non-ASCII name
//! with each candidate, rejects candidates that produce invalid sequences, and
//! scores the rest by how plausible the resulting characters are for the
//! language behind that code page (script ranges plus a small table of the
//! most frequent characters per language). The result keeps the per-candidate
//! scores so the UI can show why it chose a code page and let the user override.

use nz_front::{tr, trf};
use std::collections::HashSet;
use std::sync::OnceLock;

use encoding_rs::{BIG5, EUC_KR, Encoding, GBK, IBM866, SHIFT_JIS, WINDOWS_1252};

/// Code pages NextZip can decode legacy names with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Codepage {
    Utf8,
    /// Korean (Windows-949 / UHC, superset of EUC-KR).
    Cp949,
    /// Japanese (Windows-932).
    ShiftJis,
    /// Simplified Chinese (Windows-936).
    Gbk,
    /// Traditional Chinese (Windows-950).
    Big5,
    /// IBM PC / DOS US (APPNOTE default).
    Cp437,
    /// DOS Cyrillic.
    Cp866,
    /// Windows Western European.
    Cp1252,
}

impl Codepage {
    pub const ALL: [Codepage; 8] = [
        Codepage::Utf8,
        Codepage::Cp949,
        Codepage::ShiftJis,
        Codepage::Gbk,
        Codepage::Big5,
        Codepage::Cp437,
        Codepage::Cp866,
        Codepage::Cp1252,
    ];

    /// Windows code page number.
    pub fn number(self) -> u32 {
        match self {
            Codepage::Utf8 => 65001,
            Codepage::Cp949 => 949,
            Codepage::ShiftJis => 932,
            Codepage::Gbk => 936,
            Codepage::Big5 => 950,
            Codepage::Cp437 => 437,
            Codepage::Cp866 => 866,
            Codepage::Cp1252 => 1252,
        }
    }

    pub fn from_number(n: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.number() == n)
    }

    /// Parse `949`, `cp949`, `euc-kr`, `sjis`, `utf8`, ...
    pub fn parse(s: &str) -> Option<Self> {
        let l = s.trim().to_ascii_lowercase();
        let l = l.trim_start_matches("cp").trim_start_matches("windows-");
        if let Ok(n) = l.parse() {
            return Self::from_number(n);
        }
        Some(match l {
            "utf8" | "utf-8" => Codepage::Utf8,
            "euc-kr" | "euckr" | "uhc" | "ko" | "korean" => Codepage::Cp949,
            "sjis" | "shift_jis" | "shift-jis" | "ja" | "japanese" => Codepage::ShiftJis,
            "gbk" | "gb2312" | "zh-cn" | "zh-hans" => Codepage::Gbk,
            "big5" | "zh-tw" | "zh-hant" => Codepage::Big5,
            "oem" | "dos" | "ibm437" => Codepage::Cp437,
            "ibm866" | "ru" => Codepage::Cp866,
            "latin1" | "ansi" => Codepage::Cp1252,
            _ => return None,
        })
    }

    /// Short label for menus: `CP949 (한국어)`.
    pub fn label(self) -> &'static str {
        match self {
            Codepage::Utf8 => "UTF-8",
            Codepage::Cp949 => tr("CP949 (한국어)"),
            Codepage::ShiftJis => tr("Shift_JIS (일본어)"),
            Codepage::Gbk => tr("GBK (중국어 간체)"),
            Codepage::Big5 => tr("Big5 (중국어 번체)"),
            Codepage::Cp437 => tr("CP437 (DOS 영어)"),
            Codepage::Cp866 => tr("CP866 (DOS 러시아어)"),
            Codepage::Cp1252 => tr("CP1252 (서유럽)"),
        }
    }

    fn encoding(self) -> Option<&'static Encoding> {
        match self {
            Codepage::Cp949 => Some(EUC_KR), // encoding_rs EUC-KR is the full UHC table
            Codepage::ShiftJis => Some(SHIFT_JIS),
            Codepage::Gbk => Some(GBK), // decoder is GB18030, a superset of GBK
            Codepage::Big5 => Some(BIG5),
            Codepage::Cp866 => Some(IBM866),
            Codepage::Cp1252 => Some(WINDOWS_1252),
            Codepage::Utf8 | Codepage::Cp437 => None,
        }
    }

    /// Strict decode: `None` if `raw` is not valid in this code page.
    pub fn decode(self, raw: &[u8]) -> Option<String> {
        match self {
            Codepage::Utf8 => std::str::from_utf8(raw).ok().map(str::to_owned),
            Codepage::Cp437 => Some(raw.iter().map(|&b| cp437(b)).collect()),
            _ => self
                .encoding()
                .and_then(|e| e.decode_without_bom_handling_and_without_replacement(raw))
                .map(|c| c.into_owned()),
        }
    }

    /// Decode, replacing invalid sequences with U+FFFD.
    pub fn decode_lossy(self, raw: &[u8]) -> String {
        match self {
            Codepage::Utf8 => String::from_utf8_lossy(raw).into_owned(),
            Codepage::Cp437 => raw.iter().map(|&b| cp437(b)).collect(),
            _ => {
                let enc = self.encoding().expect("table code page");
                enc.decode_without_bom_handling(raw).0.into_owned()
            }
        }
    }

    fn lang(self) -> Lang {
        match self {
            Codepage::Utf8 => Lang::Any,
            Codepage::Cp949 => Lang::Ko,
            Codepage::ShiftJis => Lang::Ja,
            Codepage::Gbk => Lang::ZhHans,
            Codepage::Big5 => Lang::ZhHant,
            Codepage::Cp437 | Codepage::Cp1252 => Lang::Latin,
            Codepage::Cp866 => Lang::Cyrillic,
        }
    }
}

/// IBM PC code page 437.
pub fn cp437(b: u8) -> char {
    const HIGH: [char; 128] = [
        'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', //
        'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', //
        'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', //
        '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', //
        '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', //
        '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀', //
        'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', //
        '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
    ];
    if b < 0x80 {
        char::from(b)
    } else {
        HIGH[usize::from(b - 0x80)]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    Any,
    Ko,
    Ja,
    ZhHans,
    ZhHant,
    Latin,
    Cyrillic,
}

// Most frequent characters per language (general text and typical file and
// folder names). Hits on these tables are what separates, for example, Korean
// bytes read as CP949 (frequent syllables) from the same bytes read as GBK
// (valid but mostly uncommon hanzi).
const KO_FREQ: &str = "이다는의에고하가지기리서사자대도로를정수한일그시나인어으아보소부주전장제구상경우문성여면해회원들화생만니재공국동관계미연위무개진비실내거체결방과터스트드파레포프크즈바마라오요운영용학년월표본최종안새폴더음악료약견적것있없을와은게했었던된될할함합니까요며라서야네께님씨분명번호간식품점차량집방역발표업무팀장님과정초중고대학교회사선생님친구가족사랑행복여행사진동영상문서자료보고서기획안결과회의록계약서견적서발주서명세서영수증신청서이력서자기소개서포트폴리오백업설정프로그램게임음악노래앨범드라마영화애니만화강의수업시험과제숙제정리요약노트메모일기편지카드초대장청첩장설계도면도안디자인로고배경바탕화면아이콘글꼴폰트한글워드엑셀파워포인트출력인쇄스캔복사원본수정최종완료작업진행예정임시삭제보관이전신규추가변경검토승인반려제출접수처리확인결재요청답변문의안내공지알림소식뉴스기사블로그카페게시판댓글좋아요구독";
const ZH_HANS_FREQ: &str = "的一是不了人我在有他这中大来上国个到说们为子和你地出道也时年得就那要下以生会自着去之过家学对可她里后小么心多天而能好都然没日于起还发成事只作当想看文无开手十用主行方又如前所本见经头面公同三已老从动两长知民样现分将外但身些与高意进把法此实回二理美点月明其种声全工己话儿者向情部正名定女问力机给等几很业最间新什打便位因重被走电四第门相次东政海口使教西再平真听世气信北少关并内加化由却代军产入先山五太水万市眼体别处总才场师书比住员九笑性通目华报立马命张活难神数件安表原车白应路期叫死常提感金何更反合放做系计或司利受光王果亲界及今京务制解各任至清物台象记边共风战干接它许八特觉望直服毛林题建南度统色字请交爱让认算论百吃义科怎元社术结六功指思非流每青管夫连远资队跟带花快条院变联言权往展该领传近留红治决周保达办运武半候七必城父强步完革深区即求品士转量空甚众技轻程告江语英基派满式李息写呢识极令黄德收脸钱党倒未持取设始版双历越史商千片容研像找友孩站广改议形委早房音火际则首单据导影失拿网香似斯专石若兵弟谁校读志飞观争究包组造落视济喜离虽坐集编宝谈府拉黑且随格尽剑讲布杀微怕母调局根曾准团段终乐切级克精哪官示冷域足送图件夹载档案资料照视频备份软游戏歌曲课程作业考试笔记设计图标壁纸字体表格演示稿报告总结计划方案合同发票清单简历证书扫描复印原稿修改最终完成临时删除新建";
const ZH_HANT_FREQ: &str = "的一是不了人我在有他這中大來上國個到說們為子和你地出道也時年得就那要下以生會自著去之過家學對可她裡後小麼心多天而能好都然沒日於起還發成事只作當想看文無開手十用主行方又如前所本見經頭面公同三已老從動兩長知民樣現分將外但身些與高意進把法此實回二理美點月明其種聲全工己話兒者向情部正名定女問力機給等幾很業最間新什打便位因重被走電四第門相次東政海口使教西再平真聽世氣信北少關並內加化由卻代軍產入先山五太水萬市眼體別處總才場師書比住員九笑性通目華報立馬命張活難神數件安表原車白應路期叫死常提感金何更反合放做系計或司利受光王果親界及今京務制解各任至清物台象記邊共風戰幹接它許八特覺望直服毛林題建南度統色字請交愛讓認算論百吃義科怎元社術結六功指思非流每青管夫連遠資隊跟帶花快條院變聯言權往展該領傳近留紅治決週保達辦運武半候七必城父強步完革深區即求品士轉量空甚眾技輕程告江語英基派滿式李息寫呢識極令黃德收臉錢黨倒未持取設始版雙歷越史商千片容研像找友孩站廣改議形委早房音火際則首單據導影失拿網香似斯專石若兵弟誰校讀志飛觀爭究包組造落視濟喜離雖坐集編寶談府拉黑且隨格盡劍講布殺微怕母調局根曾準團段終樂切級克精哪官示冷域足送圖檔案資料照片影音備份軟體遊戲歌曲課程作業考試筆記設計圖示桌布字型表格簡報報告總結計畫方案合約發票清單履歷證書掃描複印原稿修改最終完成暫存刪除新增";
const JA_KANJI_FREQ: &str = "日一国人年大十二本中長出三時行見月後前生五間上東四今金九入学高円子外八六下来気小七山話女北午百書先名川千水半男西電校語土木聞食車何南万毎白天母火右読友左休父雨会社事者自分新用手方地合部作的同業定物発内理回目場実立言意化度家明全問体関動主開数機公表通法現代対最当力定成員取取資料写真動画音楽文書報告書企画議事録契約見積請求領収申請履歴設定保存削除変更追加修正完了作業予定確認承認提出受付処理資料画像映像曲歌集版第号章話編巻下上前後新旧原本最終仮案試験課題授業講義教科書";

fn table(lang: Lang) -> &'static HashSet<char> {
    static KO: OnceLock<HashSet<char>> = OnceLock::new();
    static ZS: OnceLock<HashSet<char>> = OnceLock::new();
    static ZT: OnceLock<HashSet<char>> = OnceLock::new();
    static JA: OnceLock<HashSet<char>> = OnceLock::new();
    static EMPTY: OnceLock<HashSet<char>> = OnceLock::new();
    let (cell, src) = match lang {
        Lang::Ko => (&KO, KO_FREQ),
        Lang::ZhHans => (&ZS, ZH_HANS_FREQ),
        Lang::ZhHant => (&ZT, ZH_HANT_FREQ),
        Lang::Ja => (&JA, JA_KANJI_FREQ),
        _ => (&EMPTY, ""),
    };
    cell.get_or_init(|| src.chars().collect())
}

fn is_hangul(c: char) -> bool {
    ('\u{AC00}'..='\u{D7A3}').contains(&c)
}
fn is_han(c: char) -> bool {
    ('\u{4E00}'..='\u{9FFF}').contains(&c) || ('\u{3400}'..='\u{4DBF}').contains(&c)
}
fn is_kana(c: char) -> bool {
    ('\u{3041}'..='\u{30FF}').contains(&c)
}

/// Plausibility of one non-ASCII character for a language (higher is better).
fn char_weight(c: char, lang: Lang) -> f32 {
    let freq = |l| table(l).contains(&c);
    match c {
        '\u{0}'..='\u{1F}' | '\u{7F}'..='\u{9F}' | '\u{E000}'..='\u{F8FF}' | '\u{FFFD}' => -3.0,
        _ if is_hangul(c) => match lang {
            Lang::Ko if freq(Lang::Ko) => 3.0,
            Lang::Ko => 1.2,
            Lang::Any if freq(Lang::Ko) => 3.0,
            _ => 1.0,
        },
        '\u{3131}'..='\u{318E}' => 0.5, // compatibility jamo
        '\u{3041}'..='\u{309F}' => match lang {
            Lang::Ja | Lang::Any => 3.0,
            _ => 0.5,
        },
        '\u{30A0}'..='\u{30FF}' => match lang {
            Lang::Ja | Lang::Any => 2.6,
            _ => 0.5,
        },
        '\u{FF61}'..='\u{FF9F}' => 0.2, // half-width katakana: classic mojibake
        _ if is_han(c) => {
            let l = if lang == Lang::Any {
                [Lang::ZhHans, Lang::ZhHant, Lang::Ja, Lang::Ko]
                    .into_iter()
                    .find(|&l| freq(l))
                    .unwrap_or(Lang::Any)
            } else {
                lang
            };
            match l {
                Lang::ZhHans | Lang::ZhHant | Lang::Ja if freq(l) => 2.6,
                Lang::ZhHans | Lang::ZhHant => 0.6,
                Lang::Ja => 0.8,
                Lang::Ko => 0.3, // hanja are rare in Korean names
                _ => 0.5,
            }
        }
        '\u{3000}'..='\u{303F}' | '\u{FF01}'..='\u{FF5E}' => 1.0,
        '\u{00C0}'..='\u{024F}' if c != '×' && c != '÷' => match lang {
            Lang::Latin | Lang::Any => 1.5,
            _ => 0.4,
        },
        '\u{0400}'..='\u{04FF}' => match lang {
            Lang::Cyrillic | Lang::Any => 2.0,
            _ => 0.3,
        },
        '\u{2500}'..='\u{259F}'
        | '\u{2200}'..='\u{22FF}'
        | '\u{2310}'
        | '\u{2320}'
        | '\u{2321}' => 0.05,
        '\u{0370}'..='\u{03FF}' => 0.2,
        _ => 0.3,
    }
}

/// Score for one candidate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Score {
    pub codepage: Codepage,
    /// Mean plausibility per non-ASCII character (higher is better).
    pub score: f32,
    /// Names that are not valid in this code page.
    pub invalid: usize,
}

/// Result of [`detect`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct Detection {
    pub codepage: Codepage,
    /// 0.0 (guess) to 1.0 (certain).
    pub confidence: f32,
    /// Names with non-ASCII bytes that were examined.
    pub names_checked: usize,
    /// Every candidate, best first.
    pub scores: Vec<Score>,
    /// Share of decoded non-ASCII characters per script for the winner
    /// (Hangul, Kana, Han, Latin, Cyrillic, other), for the UI.
    pub scripts: Vec<(&'static str, f32)>,
}

impl Detection {
    /// One-line Korean explanation, e.g.
    /// `CP949 (한국어) · 이름 37개 분석 · 한글 92% · 2위 GBK 점수의 3.1배`.
    pub fn summary_ko(&self) -> String {
        if self.names_checked == 0 {
            return trf(
                "{} · 모든 이름이 ASCII라 판별할 필요 없음",
                &[&self.codepage.label()],
            );
        }
        let mut s = trf(
            "{} · 이름 {}개 분석 · 신뢰도 {}%",
            &[
                &self.codepage.label(),
                &self.names_checked,
                &format!("{:.0}", self.confidence * 100.0),
            ],
        );
        if let Some((script, share)) = self.scripts.first() {
            s += &format!(" · {script} {:.0}%", share * 100.0);
        }
        if let (Some(a), Some(b)) = (self.scores.first(), self.scores.get(1)) {
            if b.invalid == 0 && b.score > 0.0 {
                s += &trf(
                    " · 2위 {} 점수의 {}배",
                    &[&b.codepage.label(), &format!("{:.1}", a.score / b.score)],
                );
            } else {
                s += tr(" · 다른 후보는 잘못된 바이트 열로 탈락");
            }
        }
        s
    }
}

/// Detect the code page of legacy `names`. `hint` is the system ANSI/OEM
/// code page (a small tie-break bonus); pass `None` on non-Windows systems.
pub fn detect<'a>(names: impl IntoIterator<Item = &'a [u8]>, hint: Option<Codepage>) -> Detection {
    let names: Vec<&[u8]> = names
        .into_iter()
        .filter(|n| n.iter().any(|&b| b >= 0x80))
        .take(4000)
        .collect();
    if names.is_empty() {
        let cp = hint.unwrap_or(Codepage::Cp437);
        return Detection {
            codepage: cp,
            confidence: 1.0,
            names_checked: 0,
            scores: vec![],
            scripts: vec![],
        };
    }
    let mut scores: Vec<Score> = Codepage::ALL
        .iter()
        .map(|&cp| score_candidate(cp, &names, hint))
        .collect();
    scores.sort_by(|a, b| {
        a.invalid.cmp(&b.invalid).then(
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    let best = scores[0].clone();
    let confidence = match scores.get(1) {
        Some(b) if b.invalid <= best.invalid && b.score > 0.0 && best.score > 0.0 => {
            let ratio = (best.score - b.score) / best.score;
            let n = names.len() as f32;
            (ratio * 2.0).clamp(0.0, 1.0) * (n / (n + 1.0))
        }
        _ if best.score > 0.0 => (names.len() as f32 / (names.len() as f32 + 0.5)).min(0.99),
        _ => 0.0,
    };
    let scripts = script_shares(best.codepage, &names);
    Detection {
        codepage: best.codepage,
        confidence,
        names_checked: names.len(),
        scores,
        scripts,
    }
}

fn score_candidate(cp: Codepage, names: &[&[u8]], hint: Option<Codepage>) -> Score {
    let lang = cp.lang();
    let mut invalid = 0usize;
    let mut total = 0.0f32;
    let mut chars = 0usize;
    for raw in names {
        let Some(s) = cp.decode(raw) else {
            invalid += 1;
            continue;
        };
        let mut name_total = 0.0f32;
        let mut name_chars = 0usize;
        let (mut letters, mut non_ascii_letters) = (0usize, 0usize);
        // Cyrillic letters glued to ASCII letters ("RВsumВ") are what Latin
        // accents look like through CP866; real Russian words do not mix.
        let mut mixed_word = false;
        let mut prev: Option<char> = None;
        for c in s.chars() {
            let cyr = |x: char| ('\u{0400}'..='\u{04FF}').contains(&x);
            if let Some(p) = prev
                && ((p.is_ascii_alphabetic() && cyr(c)) || (cyr(p) && c.is_ascii_alphabetic()))
            {
                mixed_word = true;
            }
            prev = Some(c);
            if c.is_alphabetic() {
                letters += 1;
            }
            if c.is_ascii() {
                continue;
            }
            if c.is_alphabetic() {
                non_ascii_letters += 1;
            }
            let mut w = char_weight(c, lang);
            // UHC extension syllables (lead or trail below 0xA1) are far
            // rarer than the 2,350 KS X 1001 syllables.
            if cp == Codepage::Cp949 && is_hangul(c) && !ks_x_1001_core(c) {
                w = w.min(0.2);
            }
            name_total += w;
            name_chars += 1;
        }
        // Accented Latin letters are sprinkled among ASCII; whole words of
        // them are what Cyrillic or CJK bytes look like through CP437/1252.
        if lang == Lang::Latin && letters > 0 && non_ascii_letters * 2 > letters {
            name_total *= 0.4;
        }
        if lang == Lang::Cyrillic && mixed_word {
            name_total *= 0.3;
        }
        total += name_total;
        chars += name_chars;
    }
    let mut score = if chars == 0 {
        0.0
    } else {
        total / chars as f32
    };
    if cp == Codepage::Utf8 && chars > 0 {
        score += 1.0; // random legacy bytes are almost never valid multi-byte UTF-8
    }
    if Some(cp) == hint {
        score += 0.15;
    }
    if invalid == names.len() {
        score = f32::MIN;
    }
    Score {
        codepage: cp,
        score,
        invalid,
    }
}

/// Whether `c` is in the EUC-KR core (KS X 1001) rather than the UHC
/// extension. Re-encodes the single character, which is cheap.
fn ks_x_1001_core(c: char) -> bool {
    let mut buf = [0u8; 4];
    let (bytes, _, _) = EUC_KR.encode(c.encode_utf8(&mut buf));
    bytes.len() == 2 && bytes[0] >= 0xA1 && bytes[1] >= 0xA1
}

fn script_shares(cp: Codepage, names: &[&[u8]]) -> Vec<(&'static str, f32)> {
    let mut counts = [0usize; 6];
    let labels: [&'static str; 6] = [
        tr("한글"),
        tr("가나"),
        tr("한자"),
        tr("라틴 문자"),
        tr("키릴 문자"),
        tr("기타 문자"),
    ];
    for raw in names {
        for c in cp.decode_lossy(raw).chars().filter(|c| !c.is_ascii()) {
            let k = if is_hangul(c) {
                0
            } else if is_kana(c) {
                1
            } else if is_han(c) {
                2
            } else if ('\u{00C0}'..='\u{024F}').contains(&c) {
                3
            } else if ('\u{0400}'..='\u{04FF}').contains(&c) {
                4
            } else {
                5
            };
            counts[k] += 1;
        }
    }
    let total: usize = counts.iter().sum::<usize>().max(1);
    let mut v: Vec<_> = labels
        .iter()
        .zip(counts)
        .filter(|(_, n)| *n > 0)
        .map(|(l, n)| (*l, n as f32 / total as f32))
        .collect();
    v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(cp: Codepage, s: &str) -> Vec<u8> {
        match cp {
            Codepage::Utf8 => s.as_bytes().to_vec(),
            Codepage::Cp437 => s
                .chars()
                .map(|c| (0u8..=255).find(|&b| cp437(b) == c).expect("cp437 char"))
                .collect(),
            _ => {
                let (b, _, bad) = cp.encoding().unwrap().encode(s);
                assert!(!bad, "{s} not encodable in {cp:?}");
                b.into_owned()
            }
        }
    }

    fn check(cp: Codepage, names: &[&str]) -> Detection {
        let raw: Vec<Vec<u8>> = names.iter().map(|n| enc(cp, n)).collect();
        let d = detect(raw.iter().map(Vec::as_slice), None);
        assert_eq!(d.codepage, cp, "{names:?}: {d:#?}");
        d
    }

    #[test]
    fn korean() {
        let d = check(
            Codepage::Cp949,
            &[
                "보고서/2026년 결산.xlsx",
                "사진/제주도 여행.jpg",
                "회의록.hwp",
            ],
        );
        assert!(d.confidence > 0.5, "{d:#?}");
        assert!(d.summary_ko().contains("한글"));
    }

    #[test]
    fn single_short_korean_name() {
        check(Codepage::Cp949, &["새 폴더/문서.txt"]);
        check(Codepage::Cp949, &["자료.zip"]);
    }

    #[test]
    fn japanese() {
        check(
            Codepage::ShiftJis,
            &["資料/会議の議事録.txt", "写真/たのしい旅行.jpg"],
        );
        check(Codepage::ShiftJis, &["テスト.txt"]);
    }

    #[test]
    fn chinese() {
        check(
            Codepage::Gbk,
            &["新建文件夹/工作报告.doc", "照片/我们的家.jpg"],
        );
        check(
            Codepage::Big5,
            &["新增資料夾/工作報告.doc", "照片/我們的家.jpg"],
        );
    }

    #[test]
    fn western_and_cyrillic() {
        check(Codepage::Cp437, &["Résumé.doc", "café/menü.txt"]);
        check(Codepage::Cp866, &["Документы/отчёт.txt", "Фото.jpg"]);
    }

    #[test]
    fn utf8_without_flag() {
        check(Codepage::Utf8, &["보고서.txt", "資料.txt"]);
    }

    #[test]
    fn ascii_only_uses_hint() {
        let d = detect([b"a.txt".as_slice()], Some(Codepage::Cp949));
        assert_eq!(d.codepage, Codepage::Cp949);
        assert_eq!(d.names_checked, 0);
    }

    #[test]
    fn parse_names() {
        assert_eq!(Codepage::parse("949"), Some(Codepage::Cp949));
        assert_eq!(Codepage::parse("cp932"), Some(Codepage::ShiftJis));
        assert_eq!(Codepage::parse("UTF-8"), Some(Codepage::Utf8));
        assert_eq!(Codepage::parse("euc-kr"), Some(Codepage::Cp949));
        assert_eq!(Codepage::parse("xyz"), None);
    }
}
