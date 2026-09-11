"""Fast source-lint regressions: no scanner, traits checkout, or build."""

import tempfile
from pathlib import Path
import unittest

from lint_trait_ids import check_tree, violations


class TraitIdLintTests(unittest.TestCase):
    def test_rejects_full_and_suffix_ids(self):
        for literal in ['"objectives/example::local-id"', '"::local-id"',
                        'r###"metadata/example::local-id"###',
                        '"metadata/example\\x3a\\u{3a}local-id"',
                        '"metadata/example::\\\n   local-id"']:
            with self.subTest(literal=literal):
                self.assertEqual(len(violations(f'let x = {literal};')), 1)

    def test_rejects_bare_local_name_matching(self):
        for expression in ['finding.id.ends_with("-branch")',
                           'id.contains("download")', 'change.id.eq("specific")',
                           'id.contains(needle)', 'finding.id.ends_with(suffix)']:
            with self.subTest(expression=expression):
                self.assertEqual(len(violations(expression)), 1)

    def test_allows_hierarchies_and_delimiter_parsing(self):
        self.assertEqual(violations('''
            id.starts_with("objectives/example/");
            id.split_once("::");
            id.starts_with("metadata/example::");
            path.ends_with(".rs");
            before.id.eq(&after.id);
            crate::some_module::function();
            #[serde(skip_serializing_if = "Option::is_none")]
            println!("::error title=isomer: {verdict}::{}\\n");
        '''), [])

    def test_comments_are_not_code(self):
        self.assertEqual(violations('''
            // "objectives/example::local-id"
            /* outer /* "::local-id" */ nested */
            let brace = '{';
            let quote = '\\"';
        '''), [])

    def test_inline_tests_do_not_hide_following_production(self):
        errors = violations('''
            #[cfg(test)] mod tests {
                fn example() { let id = "a/b::fixture"; let brace = "}"; }
            }
            fn production() { let id = "a/b::unstable"; }
        ''')
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][2], 'a/b::unstable')

    def test_test_named_production_module_is_not_exempt(self):
        self.assertEqual(len(violations('mod tests { const ID: &str = "a/b::id"; }')), 1)

    def test_external_test_modules_are_resolved_not_filename_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src = root / 'src'
            src.mkdir()
            (src / 'main.rs').write_text('mod analysis;')
            (src / 'analysis.rs').write_text('#[cfg(test)] mod simulations;')
            (src / 'analysis').mkdir()
            (src / 'analysis' / 'simulations.rs').write_text('const ID: &str = "a/b::fixture";')
            (src / 'simulations.rs').write_text('const ID: &str = "a/b::production";')
            errors = check_tree(root)
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0][0], src / 'simulations.rs')

    def test_reports_line_numbers(self):
        self.assertEqual(violations('// ignored\n\nlet id = "::local";')[0][0], 3)


if __name__ == '__main__':
    unittest.main()
