//! The taxonomy paths the shape detectors join on, named once.
//!
//! Two kinds, kept apart because they are matched differently: a capability
//! [`class`] is the root-stripped path [`crate::rubric::capability_class`]
//! groups traits by, and a [`trait_`] hierarchy is a full namespace a trait id
//! is tested against with [`crate::taxonomy::TraitId::is_under`].

/// Capability classes (`process/create`, not `micro-behaviors/process/create`).
pub(super) mod class {
    pub(in crate::analysis) const HTTP: &str = "communications/http";
    pub(in crate::analysis) const PROCESS_CREATE: &str = "process/create";
    pub(in crate::analysis) const INTERPRETER: &str = "process/interpreter";
    pub(in crate::analysis) const SYSCALL: &str = "os/syscall";
    pub(in crate::analysis) const SIGNAL: &str = "os/signal";
    pub(in crate::analysis) const FILE: &str = "fs/file";
    pub(in crate::analysis) const DELETE: &str = "fs/delete";
    /// Cryptographic implementation APIs (`provider/{cryptoapi,library}`).
    pub(in crate::analysis) const CRYPTO_PROVIDER: &str = "crypto/provider";
    pub(in crate::analysis) const CRYPTO_ASYMMETRIC: &str = "crypto/asymmetric";
    /// Key lifecycle and representation (*legacy: `asymmetric/key`*).
    pub(in crate::analysis) const CRYPTO_KEY: &str = "crypto/key";
}

/// Full trait hierarchies, for [`crate::taxonomy::TraitId::is_under`].
pub(super) mod trait_ {
    pub(in crate::analysis) const PROCESS_CREATE: &str = "micro-behaviors/process/create";
    pub(in crate::analysis) const INTERPRETER: &str = "micro-behaviors/process/interpreter";
    /// Language-module and script loading, a browser `<script src>` included.
    pub(in crate::analysis) const SCRIPT_LOAD: &str = "micro-behaviors/os/module/load";
    /// Hostnames and domain references in URLs.
    pub(in crate::analysis) const URL_HOST: &str = "micro-behaviors/communications/url/host";
    pub(in crate::analysis) const FS_WRITE: &str = "micro-behaviors/fs/write";
    pub(in crate::analysis) const CHAR_CODE: &str = "micro-behaviors/data/encode/char-code";
}
