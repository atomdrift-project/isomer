//! cleave's grammar for a path inside an archive.
//!
//! A diff entry for an archive member is named `container!!member`, a nested
//! archive repeats the separator (`a.tgz!!inner.zip!!x.js`), and a comparison's
//! own root entry is `<root>`. The grammar is cleave's; every reading of it in
//! isomer goes through [`MemberPath`], rather than through `split_once("!!")`
//! here and `rsplit("!!")` there — two different ideas of which separator
//! delimits "the member" that once let a nested archive's `x.js` be read out
//! of the outer archive under the same name.

/// The separator cleave puts between an archive and a member inside it.
pub(crate) const SEPARATOR: &str = "!!";

/// The name cleave gives a comparison's own root entry.
pub(crate) const ROOT: &str = "<root>";

/// A diff path, read in cleave's archive grammar. Borrowed: these are read in
/// per-file and per-member loops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct MemberPath<'a>(&'a str);

impl<'a> MemberPath<'a> {
    pub(crate) fn new(path: &'a str) -> Self {
        Self(path)
    }

    /// The path as cleave spelled it.
    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }

    /// The comparison's own root entry.
    pub(crate) fn is_root(self) -> bool {
        self.0 == ROOT
    }

    /// Whether this names something inside an archive.
    pub(crate) fn is_member(self) -> bool {
        self.0.contains(SEPARATOR)
    }

    /// How many archive layers deep: 0 for a plain file, 2 for a member of an
    /// archive inside an archive.
    pub(crate) fn depth(self) -> usize {
        self.0.matches(SEPARATOR).count()
    }

    /// Whether this is a member of an archive that is itself inside the
    /// artifact: one layer further in than the artifact's own members.
    pub(crate) fn is_nested(self) -> bool {
        self.depth() > 1
    }

    /// The outermost container and everything inside it: `("a.tgz",
    /// "package/x.js")`, or `("a.tgz", "inner.zip!!x.js")` when nested.
    pub(crate) fn split(self) -> Option<(&'a str, &'a str)> {
        self.0.split_once(SEPARATOR)
    }

    /// The path inside the outermost container, when this is a member. The
    /// container's own name differs between a diff (`<root>`) and an analysis
    /// report (the archive's file name); this part does not, so it is the key
    /// the two are joined on.
    pub(crate) fn member(self) -> Option<&'a str> {
        self.split().map(|(_, member)| member)
    }

    /// The path as a reader sees it: the member, or a plain file as itself.
    /// Raw — a lookup key; neutralize it before printing.
    pub(crate) fn display(self) -> &'a str {
        self.member().unwrap_or(self.0)
    }

    /// The innermost layer: `x.js` in `a.tgz!!inner.zip!!x.js`.
    pub(crate) fn leaf(self) -> &'a str {
        self.0.rsplit(SEPARATOR).next().unwrap_or(self.0)
    }

    /// The innermost layer's file name: `x.js` for `a.tgz!!package/x.js`.
    pub(crate) fn file_name(self) -> &'a str {
        let leaf = self.leaf();
        leaf.rsplit('/').next().unwrap_or(leaf)
    }

    /// The archive this member sits in, and its name inside it:
    /// `(a.tgz!!inner.zip, x.js)`. `None` for a plain file.
    pub(crate) fn parent(self) -> Option<(MemberPath<'a>, &'a str)> {
        self.0
            .rsplit_once(SEPARATOR)
            .map(|(parent, leaf)| (MemberPath(parent), leaf))
    }

    /// Each layer, outermost first.
    pub(crate) fn layers(self) -> impl Iterator<Item = &'a str> {
        self.0.split(SEPARATOR)
    }

    /// Every path this one descends from: `a` and `a!!b` for `a!!b!!c`. Every
    /// position is tried, not just non-overlapping matches, so `a!!!b`
    /// descends from both `a` and `a!`, exactly as a prefix test would say.
    pub(crate) fn containers(self) -> impl Iterator<Item = &'a str> {
        let path = self.0;
        path.match_indices('!').filter_map(move |(i, _)| {
            path.get(i..)
                .filter(|rest| rest.starts_with(SEPARATOR))
                .and_then(|_| path.get(..i))
        })
    }
}

/// Join layers back into one path.
pub(crate) fn join<S: AsRef<str>>(layers: impl IntoIterator<Item = S>) -> String {
    let mut out = String::new();
    for (i, layer) in layers.into_iter().enumerate() {
        if i > 0 {
            out.push_str(SEPARATOR);
        }
        out.push_str(layer.as_ref());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nested_member_reads_one_way_everywhere() {
        let p = MemberPath::new("a.tgz!!inner.zip!!package/x.js");
        assert!(p.is_member());
        assert_eq!(p.depth(), 2);
        assert_eq!(p.split(), Some(("a.tgz", "inner.zip!!package/x.js")));
        assert_eq!(p.display(), "inner.zip!!package/x.js");
        assert_eq!(p.leaf(), "package/x.js");
        assert_eq!(p.file_name(), "x.js");
        let (parent, leaf) = p.parent().unwrap();
        assert_eq!(
            (parent, leaf),
            (MemberPath::new("a.tgz!!inner.zip"), "package/x.js")
        );
        assert_eq!(
            p.containers().collect::<Vec<_>>(),
            ["a.tgz", "a.tgz!!inner.zip"]
        );
        assert_eq!(join(p.layers()), "a.tgz!!inner.zip!!package/x.js");
    }

    #[test]
    fn a_plain_path_is_its_own_member() {
        let p = MemberPath::new("src/index.js");
        assert!(!p.is_member());
        assert_eq!(p.depth(), 0);
        assert_eq!(p.member(), None);
        assert_eq!(p.display(), "src/index.js");
        assert_eq!(p.file_name(), "index.js");
        assert!(MemberPath::new(ROOT).is_root());
        assert_eq!(p.containers().count(), 0);
    }

    #[test]
    fn overlapping_separators_name_every_container() {
        assert_eq!(
            MemberPath::new("a!!!b").containers().collect::<Vec<_>>(),
            ["a", "a!"]
        );
    }
}
