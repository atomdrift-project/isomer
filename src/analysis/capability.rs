//! The capability shape of one changed file: which platform-neutral families
//! of behavior it gained, read from its traits, symbols, and facts.
//!
//! A newly-added executable can be an implant even when every individual API
//! looks ordinary, so the families and their combinations are scored on the
//! file that gained them. The family vocabulary is matched by *word*, not by
//! substring: `sha` is a hash and `shared` is not, `serial` is a hardware id
//! and `serialize` is not, `listen` is a socket and `addEventListener` is not.
//! Long names that cannot occur inside another word (`getprocaddress`,
//! `urlsession`) are still found anywhere, which is how `NSURLSession` and
//! `CreateProcessW` keep reading as what they are.

use cleave::types::{FileDiffEntry, Scope};

use crate::member::MemberPath;
use crate::taxonomy::TraitId;

/// A platform-neutral family of capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Family {
    Communications,
    Process,
    RemoteAccess,
    Discovery,
    Crypto,
    Loading,
    Persistence,
    Concealment,
    CredentialAccess,
}

impl Family {
    const ALL: [Family; 9] = [
        Family::Communications,
        Family::Process,
        Family::RemoteAccess,
        Family::Discovery,
        Family::Crypto,
        Family::Loading,
        Family::Persistence,
        Family::Concealment,
        Family::CredentialAccess,
    ];

    fn bit(self) -> u16 {
        1 << self as u16
    }

    /// The cues that put text in this family.
    fn cues(self) -> &'static [Cue] {
        use Cue::{Stem, Within, Word};
        match self {
            Self::Communications => &[
                Within("communications/"),
                Stem("socket"),
                Stem("connect"),
                Word("listen"),
                Word("accept"),
                Stem("http"),
                Within("websocket"),
                Within("urlsession"),
                Within("urlrequest"),
                Stem("network"),
                Within("winhttp"),
                Within("internetopen"),
            ],
            Self::Process => &[
                Within("process/"),
                Stem("shell"),
                Within("powershell"),
                Stem("spawn"),
                Within("execve"),
                Within("createprocess"),
                Within("nstask"),
                Within("nspipe"),
                Within("mkfifo"),
                Within("/bin/sh"),
                Stem("fork"),
                Word("vfork"),
            ],
            Self::RemoteAccess => &[
                Stem("ssh"),
                Word("openssh"),
                Within("identityfile"),
                Within("stricthostkeychecking"),
                Within("forwarding"),
                Within("tunnelwithhostname"),
                Within("remote-access"),
            ],
            Self::Discovery => &[
                Within("discovery"),
                Within("hardware"),
                Within("iokit"),
                Within("sysctl"),
                Word("serial"),
                Within("serialnumber"),
                Within("machine-id"),
                Within("username"),
                Within("getcomputername"),
                Within("gethostname"),
                Within("registry"),
                Word("uname"),
            ],
            Self::Crypto => &[
                Within("crypto"),
                // `crypt` inside `encrypt`, `decrypt`, `bcrypt` is the point.
                Within("crypt"),
                Word("aes"),
                Within("hmac"),
                Within("pbkdf"),
                Word("sha"),
                Word("md5"),
                Within("pem-public-key"),
            ],
            Self::Loading => &[
                Within("dylib/load"),
                Within("dlopen"),
                Within("dlsym"),
                Within("loadlibrary"),
                Within("getprocaddress"),
                Within("ld_preload"),
            ],
            Self::Persistence => &[
                Within("persistence"),
                Within("launchd"),
                Within("systemd"),
                Word("cron"),
                Word("crond"),
                Word("crontab"),
                Within("runonce"),
                Within("startup"),
                Within("autostart"),
                Within("service-install"),
            ],
            Self::Concealment => &[
                Within("archive"),
                Within("encrypted-entry"),
                Within("encoded-payload"),
                Within("base64"),
                Within("entropy"),
                Within("packed"),
                Within("compression"),
            ],
            Self::CredentialAccess => &[
                Within("credential"),
                Within("password"),
                Within("browser"),
                Within("keychain"),
                Within("secret"),
                Word("token"),
                Word("tokens"),
            ],
        }
    }
}

/// The families a file has gained: a set over [`Family`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Families(u16);

impl Families {
    pub(super) fn insert(&mut self, family: Family) {
        self.0 |= family.bit();
    }

    pub(super) fn contains(self, family: Family) -> bool {
        self.0 & family.bit() != 0
    }

    pub(super) fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Put `text` — a trait namespace, a symbol, a library, a fact — in every
    /// family it names.
    pub(super) fn observe(&mut self, text: &str) {
        let text = Text::new(text);
        for family in Family::ALL {
            if family.cues().iter().any(|cue| text.matches(*cue)) {
                self.insert(family);
            }
        }
    }
}

/// How a cue word is found in text.
#[derive(Clone, Copy, Debug)]
pub(super) enum Cue {
    /// A whole word, optionally followed by digits: `sha` finds `sha256` and
    /// `SHA1_Update`, never `shared`.
    Word(&'static str),
    /// A word that starts with this: `connect` finds `connection` and
    /// `ConnectEx`, never `disconnect`.
    Stem(&'static str),
    /// Anywhere in the text, case-insensitively — for names and paths that
    /// cannot occur inside another word.
    Within(&'static str),
    /// Consecutive `/`-separated segments of a path: `fs/write` finds
    /// `micro-behaviors/fs/write/file`, never `zfs/writer`.
    Path(&'static str),
}

/// Text read for cues: lowercased whole, and split into words at punctuation,
/// camelCase, and acronym boundaries.
pub(super) struct Text {
    lower: String,
    words: Vec<String>,
}

impl Text {
    pub(super) fn new(text: &str) -> Self {
        Self {
            lower: text.to_ascii_lowercase(),
            words: words(text),
        }
    }

    pub(super) fn matches(&self, cue: Cue) -> bool {
        match cue {
            Cue::Word(word) => self.words.iter().any(|w| {
                w.strip_prefix(word)
                    .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
            }),
            Cue::Stem(stem) => self.words.iter().any(|w| w.starts_with(stem)),
            Cue::Within(needle) => self.lower.contains(needle),
            Cue::Path(path) => {
                let mut segments = self.lower.split('/');
                let wanted: Vec<&str> = path.split('/').collect();
                let segments: Vec<&str> = segments.by_ref().collect();
                segments
                    .windows(wanted.len())
                    .any(|w| w == wanted.as_slice())
            }
        }
    }
}

/// Lowercase words of `text`. Splits at anything not alphanumeric, at a
/// lower-to-upper step (`addEvent` → `add`, `event`), at the end of an
/// acronym (`XMLHttp` → `xml`, `http`), and at a digit-to-letter step
/// (`SHA256Init` → `sha256`, `init`); digits stay with the letters before them.
fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for run in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        let chars: Vec<char> = run.chars().collect();
        let mut word = String::new();
        for (i, &c) in chars.iter().enumerate() {
            let prev = i.checked_sub(1).map(|j| chars[j]);
            let next = chars.get(i + 1);
            let boundary = c.is_ascii_uppercase()
                && prev.is_some_and(|p| {
                    p.is_ascii_lowercase()
                        || p.is_ascii_digit()
                        || (p.is_ascii_uppercase() && next.is_some_and(char::is_ascii_lowercase))
                });
            if boundary && !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            word.push(c.to_ascii_lowercase());
        }
        if !word.is_empty() {
            out.push(word);
        }
    }
    out
}

/// What one added or changed file can do, as families plus the placement
/// facts that make a capability bundle suspicious.
#[derive(Debug, Default)]
pub(super) struct CapabilityShape {
    pub families: Families,
    pub executable: bool,
    pub resource_path: bool,
    pub archive_member: bool,
}

/// Directories that hold programs on the platforms isomer sees. Path shape is
/// the only executable evidence available when a member cannot be extracted, so
/// both the capability profile and the extraction fallback read the same list.
/// `/usr/bin/` and `/usr/local/bin/` need no entry — `/bin/` already covers them.
pub(super) const EXEC_PATH_MARKERS: [&str; 5] = [
    "/contents/macos/",
    "/bin/",
    "/sbin/",
    "/libexec/",
    "\\system32\\",
];

/// Build a compact, explainable profile from the diff scopes. It deliberately
/// consumes the facts already emitted by cleave instead of requiring a new
/// platform-specific trait for every API spelling.
pub(super) fn capability_shape(file: &FileDiffEntry) -> CapabilityShape {
    let lower_path = file.path.to_ascii_lowercase();
    let mut shape = CapabilityShape {
        executable: super::member_type(file).is_some_and(|t| t.is_binary())
            || EXEC_PATH_MARKERS.iter().any(|m| lower_path.contains(m)),
        resource_path: [
            "/resources/",
            "/plugins/",
            "/extensions/",
            "/vendor/",
            "/assets/",
        ]
        .iter()
        .any(|part| lower_path.contains(part)),
        archive_member: MemberPath::new(&file.path).is_member(),
        ..Default::default()
    };

    if let Some(traits) = file.scopes.traits.as_ref() {
        for id in traits
            .added
            .iter()
            .map(|t| &t.id)
            .chain(traits.changed.iter().map(|change| &change.new.id))
        {
            let id = TraitId::new(id);
            shape.families.observe(id.namespace());
            shape.executable |= trait_is_executable(id);
        }
    }

    if let Some(symbols) = file.scopes.symbols.as_ref() {
        for symbol in symbols
            .added
            .iter()
            .chain(symbols.changed.iter().map(|change| &change.new))
        {
            shape.families.observe(&symbol.symbol);
            if let Some(library) = &symbol.library {
                shape.families.observe(library);
            }
        }
    }

    // Sections plus symbols are a useful cross-platform executable marker for
    // extensionless ELF/Mach-O/PE files. Source files normally have neither.
    shape.executable |= file.scopes.view(Scope::Sections).has_changes
        && file.scopes.view(Scope::Symbols).has_changes;

    if let Some(metrics) = file.scopes.metrics.as_ref() {
        for path in metrics
            .added
            .iter()
            .map(|metric| &metric.path)
            .chain(metrics.changed.iter().map(|change| &change.new.path))
        {
            add_metric_signal(&mut shape, path);
        }
    }
    if let Some(kv) = file.scopes.kv.as_ref() {
        for fact in kv
            .added
            .iter()
            .chain(kv.changed.iter().map(|change| &change.new))
        {
            shape.families.observe(&fact.path);
            // A string fact is read as-is; only a structured value needs
            // serializing to be searched.
            match fact.value.as_str() {
                Some(text) => shape.families.observe(text),
                None => shape.families.observe(&fact.value.to_string()),
            }
        }
    }
    shape
}

fn add_metric_signal(shape: &mut CapabilityShape, path: &str) {
    let lower = path.to_ascii_lowercase();
    shape.executable |= lower.contains("sections.executable_count")
        || lower.starts_with("macho.")
        || lower.starts_with("elf.")
        || lower.starts_with("pe.");
    if lower.contains("overlay")
        || lower.contains("concealed")
        || lower.contains("high_entropy")
        || lower.contains("near_maximum_entropy")
        || lower.contains("packed")
    {
        shape.families.insert(Family::Concealment);
    }
}

fn trait_is_executable(id: TraitId<'_>) -> bool {
    id.is_under("metadata/lang/compiled")
        || id.is_under("metadata/binary")
        // Format names are taxonomy tokens, not arbitrary substrings:
        // `self` is not ELF and `scope-string` is not PE.
        || id
            .namespace()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|token| {
                token.eq_ignore_ascii_case("macho")
                    || token.eq_ignore_ascii_case("elf")
                    || token.eq_ignore_ascii_case("pe")
            })
}

/// The shape's score: a point per family, more for the combinations an
/// implant needs, and for an executable placed where payloads hide.
pub(super) fn capability_shape_score(
    shape: &CapabilityShape,
    package_context: bool,
    replacement: bool,
) -> u32 {
    use Family::{Communications, Crypto, Discovery, Loading, Process, RemoteAccess};
    let has = |family| shape.families.contains(family);
    let both = |a, b| u32::from(has(a) && has(b));

    let mut score = shape.families.len();
    score += 2 * both(Communications, Process);
    score += 2 * both(Communications, RemoteAccess);
    score += both(Discovery, Communications);
    score += both(Crypto, Communications);
    score += both(Process, RemoteAccess);
    score += both(Loading, Communications);
    if shape.executable {
        score += 2;
    }
    if shape.resource_path || shape.archive_member {
        score += 2;
    }
    if package_context {
        score += 2;
    }
    if replacement {
        // A root directory rename must not hide a binary replacement. The
        // normalized suffix is enough to pair `App-1.2.3/bin/x` with
        // `App/bin/x` without trusting archive-specific naming conventions.
        score += 1;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    fn families(text: &str) -> Families {
        let mut families = Families::default();
        families.observe(text);
        families
    }

    #[test]
    fn capability_families_are_platform_neutral() {
        let families = families("CreateProcess WinHttpOpen BCryptEncrypt GetComputerName");
        assert!(families.contains(Family::Process));
        assert!(families.contains(Family::Communications));
        assert!(families.contains(Family::Crypto));
        assert!(families.contains(Family::Discovery));
    }

    /// Short cue words are words, not fragments of longer ones.
    #[test]
    fn short_cues_do_not_match_inside_other_words() {
        assert!(!families("shared_memory").contains(Family::Crypto));
        assert!(families("SHA256_Update").contains(Family::Crypto));
        assert!(families("CC_SHA1").contains(Family::Crypto));
        assert!(!families("serializeJSON").contains(Family::Discovery));
        assert!(families("IOPlatformSerialNumber").contains(Family::Discovery));
        assert!(!families("addEventListener").contains(Family::Communications));
        assert!(families("listen").contains(Family::Communications));
        assert!(!families("tokenizeInput").contains(Family::CredentialAccess));
        assert!(families("access_token").contains(Family::CredentialAccess));
        assert!(!families("acronym").contains(Family::Persistence));
        assert!(families("crontab -e").contains(Family::Persistence));
        // Long, unambiguous names are still found inside identifiers.
        assert!(families("NSURLSession").contains(Family::Communications));
        assert!(families("XMLHttpRequest").contains(Family::Communications));
        assert!(families("EVP_EncryptInit").contains(Family::Crypto));
    }

    #[test]
    fn words_split_at_camel_case_acronyms_and_digits() {
        assert_eq!(words("XMLHttpRequest"), ["xml", "http", "request"]);
        assert_eq!(words("SHA256Init"), ["sha256", "init"]);
        assert_eq!(words("addEventListener"), ["add", "event", "listener"]);
        assert_eq!(words("fetch-exec_shell"), ["fetch", "exec", "shell"]);
    }

    #[test]
    fn path_cues_align_to_segments() {
        let ns = Text::new("micro-behaviors/fs/write/file");
        assert!(ns.matches(Cue::Path("fs/write")));
        assert!(ns.matches(Cue::Path("fs")));
        assert!(!Text::new("objectives/zfs/writer").matches(Cue::Path("fs/write")));
    }

    #[test]
    fn capability_bundle_requires_convergence_not_one_api() {
        let mut one_api = Families::default();
        one_api.insert(Family::Communications);
        let ordinary = CapabilityShape {
            families: one_api,
            executable: true,
            ..Default::default()
        };
        assert!(capability_shape_score(&ordinary, false, false) < 10);

        let mut bundle = Families::default();
        for family in [
            Family::Communications,
            Family::Process,
            Family::RemoteAccess,
            Family::Discovery,
            Family::Crypto,
            Family::Loading,
        ] {
            bundle.insert(family);
        }
        let suspicious = CapabilityShape {
            families: bundle,
            executable: true,
            resource_path: true,
            archive_member: true,
        };
        assert!(capability_shape_score(&suspicious, true, true) >= 10);
    }
}
