//! Source lint for production dependencies on unstable local trait IDs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use proc_macro2::{Delimiter, TokenStream, TokenTree};
use regex::Regex;

#[derive(Clone, Debug)]
struct Token {
    value: String,
    line: usize,
    literal: bool,
}

/// One source-lint failure, with its original line and value.
#[derive(Debug)]
pub struct Violation {
    pub line: usize,
    pub reason: &'static str,
    pub value: String,
}

fn flatten(stream: TokenStream, output: &mut Vec<Token>) {
    for token in stream {
        let line = token.span().start().line;
        if let TokenTree::Group(group) = token {
            let delimiters = match group.delimiter() {
                Delimiter::Parenthesis => Some(("(", ")")),
                Delimiter::Brace => Some(("{", "}")),
                Delimiter::Bracket => Some(("[", "]")),
                Delimiter::None => None,
            };
            if let Some((open, _)) = delimiters {
                output.push(Token {
                    value: open.into(),
                    line,
                    literal: false,
                });
            }
            flatten(group.stream(), output);
            if let Some((_, close)) = delimiters {
                output.push(Token {
                    value: close.into(),
                    line: group.span_close().start().line,
                    literal: false,
                });
            }
        } else {
            let spelling = token.to_string();
            let value = match syn::parse_str::<syn::Lit>(&spelling) {
                Ok(syn::Lit::Str(value)) => Some(value.value()),
                Ok(syn::Lit::ByteStr(value)) => {
                    Some(String::from_utf8_lossy(&value.value()).into_owned())
                }
                Ok(syn::Lit::CStr(value)) => Some(value.value().to_string_lossy().into_owned()),
                // Character literals cannot be block delimiters or identifiers.
                Ok(syn::Lit::Char(_) | syn::Lit::Byte(_)) => continue,
                _ => None,
            };
            output.push(Token {
                literal: value.is_some(),
                value: value.unwrap_or(spelling),
                line,
            });
        }
    }
}

fn production_tokens(source: &str) -> Result<(Vec<Token>, Vec<String>)> {
    let stream: TokenStream = source.parse().map_err(|error| anyhow::anyhow!("{error}"))?;
    let mut tokens = Vec::new();
    flatten(stream, &mut tokens);
    let mut output = Vec::new();
    let mut external_tests = Vec::new();
    let mut remaining = tokens.iter().peekable();
    while remaining.peek().is_some() {
        let prefix: Vec<_> = remaining
            .clone()
            .take(7)
            .map(|t| t.value.as_str())
            .collect();
        // Rust token streams expand doc comments into #[doc = "..."] (or
        // #![doc = "..."]). Documentation is not a scoring dependency.
        let documentation = match prefix.as_slice() {
            ["#", "[", "doc", "=", _, "]", ..] => 6,
            ["#", "!", "[", "doc", "=", _, "]", ..] => 7,
            _ => 0,
        };
        if documentation > 0 {
            for _ in 0..documentation {
                remaining.next();
            }
            continue;
        }
        if prefix == ["#", "[", "cfg", "(", "test", ")", "]"] {
            for _ in 0..7 {
                remaining.next();
            }
            let mut header = Vec::new();
            while remaining
                .peek()
                .is_some_and(|t| !matches!(t.value.as_str(), "{" | ";"))
            {
                if let Some(token) = remaining.next() {
                    header.push(token.value.clone());
                }
            }
            if remaining.next().is_some_and(|t| t.value == ";") {
                if let Some(index) = header.iter().position(|t| t == "mod")
                    && let Some(module) = header.get(index + 1)
                {
                    external_tests.push(module.clone());
                }
            } else {
                let mut depth = 1;
                for token in remaining.by_ref() {
                    if !token.literal {
                        match token.value.as_str() {
                            "{" => depth += 1,
                            "}" => depth -= 1,
                            _ => {}
                        }
                    }
                    if depth == 0 {
                        break;
                    }
                }
            }
        } else if let Some(token) = remaining.next() {
            output.push(token.clone());
        }
    }
    Ok((output, external_tests))
}

/// Lint source, excluding explicitly `cfg(test)` items only.
pub fn violations(source: &str) -> Result<Vec<Violation>> {
    let (tokens, _) = production_tokens(source)?;
    let full = Regex::new(r"[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)+::[a-zA-Z0-9_-]")?;
    let suffix = Regex::new(r"^::[a-zA-Z0-9_-]+$")?;
    let mut errors = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let predicate = matches!(token.value.as_str(), "contains" | "ends_with")
            || (token.value == "eq" && tokens.get(i + 2).is_some_and(|t| t.literal));
        if i >= 2
            && tokens[i - 2].value == "id"
            && tokens[i - 1].value == "."
            && predicate
            && !token.literal
        {
            errors.push(Violation {
                line: token.line,
                reason: "local trait-ID predicate; match a hierarchy instead",
                value: token.value.clone(),
            });
        }
        if token.literal && (full.is_match(&token.value) || suffix.is_match(&token.value)) {
            errors.push(Violation {
                line: token.line,
                reason: "local trait-ID literal",
                value: token.value.clone(),
            });
        }
    }
    Ok(errors)
}

fn rust_sources(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_sources(&path, files)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

/// Check a source tree, resolving external test modules by their declarations.
pub fn check_tree(root: &Path) -> Result<Vec<(PathBuf, Violation)>> {
    let mut paths = Vec::new();
    rust_sources(&root.join("src"), &mut paths)?;
    let sources: BTreeMap<_, _> = paths
        .into_iter()
        .map(|path| {
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            Ok((path, text))
        })
        .collect::<Result<_>>()?;
    let mut excluded = BTreeSet::new();
    for (path, source) in &sources {
        let (_, modules) = production_tokens(source).with_context(|| path.display().to_string())?;
        let directory = match path.file_name().and_then(|s| s.to_str()) {
            Some("main.rs" | "lib.rs" | "mod.rs") => path.parent().unwrap_or(root).to_path_buf(),
            _ => path.with_extension(""),
        };
        for module in modules {
            excluded.insert(directory.join(format!("{module}.rs")));
            let mut nested = Vec::new();
            rust_sources(&directory.join(module), &mut nested)?;
            excluded.extend(nested);
        }
    }
    let mut errors = Vec::new();
    for (path, source) in sources {
        if !excluded.contains(&path) {
            for error in violations(&source).with_context(|| path.display().to_string())? {
                errors.push((path.clone(), error));
            }
        }
    }
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_full_and_suffix_ids_including_escaped_and_raw_strings() {
        for literal in [
            r#""objectives/example::local-id""#,
            r#""::local-id""#,
            "r###\"metadata/example::local-id\"###",
            r#""metadata/example\x3a\u{3a}local-id""#,
            "\"metadata/example::\\\n   local-id\"",
        ] {
            assert_eq!(
                violations(&format!("let x = {literal};")).unwrap().len(),
                1,
                "{literal}"
            );
        }
    }

    #[test]
    fn rejects_local_name_predicates_including_dynamic_arguments() {
        for expression in [
            r#"finding.id.ends_with("-branch")"#,
            r#"id.contains("download")"#,
            r#"change.id.eq("specific")"#,
            "id.contains(needle)",
            "finding.id.ends_with(suffix)",
        ] {
            assert_eq!(violations(expression).unwrap().len(), 1, "{expression}");
        }
    }

    #[test]
    fn allows_hierarchies_delimiter_parsing_and_rust_paths() {
        assert!(
            violations(
                r#"
            id.starts_with("objectives/example/");
            id.split_once("::");
            id.starts_with("metadata/example::");
            path.ends_with(".rs");
            before.id.eq(&after.id);
            crate::some_module::function();
            #[serde(skip_serializing_if = "Option::is_none")]
            println!("::error title=isomer: {verdict}::{}\n");
        "#
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn comments_and_character_literals_are_not_code() {
        assert!(
            violations(
                r#"
            // "objectives/example::local-id"
            /* outer /* "::local-id" */ nested */
            let brace = '{';
            let quote = '\"';
        "#
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn documentation_comments_do_not_create_literal_violations() {
        assert!(
            violations(
                r#"
            //! Module docs may describe metadata/example::local-id.
            /// A trait id, `micro-behaviors/process/create::exec`.
            /** Another example: metadata/binary/linking/runtime::ifunc. */
            pub struct TraitId;
        "#
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn inline_tests_do_not_hide_following_production() {
        let errors = violations(
            r#"
            #[cfg(test)] mod tests {
                fn example() { let id = "a/b::fixture"; let brace = "}"; }
            }
            fn production() { let id = "a/b::unstable"; }
        "#,
        )
        .unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].value, "a/b::unstable");
        assert_eq!(
            violations(r#"mod tests { const ID: &str = "a/b::id"; }"#)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn external_test_modules_are_resolved_by_declaration() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("src");
        fs::create_dir_all(src.join("analysis")).unwrap();
        fs::write(src.join("main.rs"), "mod analysis;").unwrap();
        fs::write(src.join("analysis.rs"), "#[cfg(test)] mod simulations;").unwrap();
        fs::write(
            src.join("analysis/simulations.rs"),
            r#"const ID: &str = "a/b::fixture";"#,
        )
        .unwrap();
        fs::write(
            src.join("simulations.rs"),
            r#"const ID: &str = "a/b::production";"#,
        )
        .unwrap();
        let errors = check_tree(root.path()).unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, src.join("simulations.rs"));
    }

    #[test]
    fn reports_original_line_numbers_and_lexer_errors() {
        assert_eq!(
            violations("// ignored\n\nlet id = \"::local\";").unwrap()[0].line,
            3
        );
        assert!(violations("let id = \"unterminated").is_err());
    }
}
