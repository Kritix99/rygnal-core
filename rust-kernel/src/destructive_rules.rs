#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructiveLanguage {
    Python,
    JavaScript,
    TypeScript,
    Go,
    Rust,
    Java,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructiveSeverity {
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructiveOperation {
    DeleteFile,
    DeleteDirectory,
    RecursiveDelete,
    Truncate,
    Overwrite,
    ShellDelete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestructiveSinkMatch {
    pub rule_id: &'static str,
    pub language: DestructiveLanguage,
    pub severity: DestructiveSeverity,
    pub operation: DestructiveOperation,
}

#[derive(Debug, Clone, Copy)]
enum RulePattern {
    Contains(&'static str),
    All(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
struct DestructiveSinkRule {
    id: &'static str,
    language: DestructiveLanguage,
    severity: DestructiveSeverity,
    operation: DestructiveOperation,
    patterns: &'static [RulePattern],
}

const PYTHON_RULES: &[DestructiveSinkRule] = &[
    DestructiveSinkRule {
        id: "python-shutil-rmtree",
        language: DestructiveLanguage::Python,
        severity: DestructiveSeverity::Critical,
        operation: DestructiveOperation::RecursiveDelete,
        patterns: &[RulePattern::Contains("shutil.rmtree(")],
    },
    DestructiveSinkRule {
        id: "python-os-remove",
        language: DestructiveLanguage::Python,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::DeleteFile,
        patterns: &[
            RulePattern::Contains("os.remove("),
            RulePattern::Contains("os.unlink("),
            RulePattern::Contains(".unlink("),
        ],
    },
    DestructiveSinkRule {
        id: "python-shell-rm-rf",
        language: DestructiveLanguage::Python,
        severity: DestructiveSeverity::Critical,
        operation: DestructiveOperation::ShellDelete,
        patterns: &[
            RulePattern::All(&["subprocess.run(", "rm -rf"]),
            RulePattern::All(&["subprocess.call(", "rm -rf"]),
            RulePattern::All(&["os.system(", "rm -rf"]),
        ],
    },
];

const JAVASCRIPT_RULES: &[DestructiveSinkRule] = &[
    DestructiveSinkRule {
        id: "javascript-fs-rm-recursive",
        language: DestructiveLanguage::JavaScript,
        severity: DestructiveSeverity::Critical,
        operation: DestructiveOperation::RecursiveDelete,
        patterns: &[
            RulePattern::All(&["fs.rmSync(", "recursive: true"]),
            RulePattern::All(&["fs.rm(", "recursive: true"]),
        ],
    },
    DestructiveSinkRule {
        id: "javascript-fs-unlink",
        language: DestructiveLanguage::JavaScript,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::DeleteFile,
        patterns: &[
            RulePattern::Contains("fs.unlinkSync("),
            RulePattern::Contains("fs.unlink("),
        ],
    },
    DestructiveSinkRule {
        id: "javascript-shell-rm-rf",
        language: DestructiveLanguage::JavaScript,
        severity: DestructiveSeverity::Critical,
        operation: DestructiveOperation::ShellDelete,
        patterns: &[
            RulePattern::All(&["exec(", "rm -rf"]),
            RulePattern::All(&["execSync(", "rm -rf"]),
            RulePattern::All(&["spawn(", "rm"]),
        ],
    },
];

const TYPESCRIPT_RULES: &[DestructiveSinkRule] = &[
    DestructiveSinkRule {
        id: "typescript-fs-rm-recursive",
        language: DestructiveLanguage::TypeScript,
        severity: DestructiveSeverity::Critical,
        operation: DestructiveOperation::RecursiveDelete,
        patterns: &[
            RulePattern::All(&["fs.rmSync(", "recursive: true"]),
            RulePattern::All(&["fs.rm(", "recursive: true"]),
        ],
    },
    DestructiveSinkRule {
        id: "typescript-fs-unlink",
        language: DestructiveLanguage::TypeScript,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::DeleteFile,
        patterns: &[
            RulePattern::Contains("fs.unlinkSync("),
            RulePattern::Contains("fs.unlink("),
        ],
    },
];

const GO_RULES: &[DestructiveSinkRule] = &[
    DestructiveSinkRule {
        id: "go-os-remove-all",
        language: DestructiveLanguage::Go,
        severity: DestructiveSeverity::Critical,
        operation: DestructiveOperation::RecursiveDelete,
        patterns: &[RulePattern::Contains("os.RemoveAll(")],
    },
    DestructiveSinkRule {
        id: "go-os-remove",
        language: DestructiveLanguage::Go,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::DeleteFile,
        patterns: &[RulePattern::Contains("os.Remove(")],
    },
    DestructiveSinkRule {
        id: "go-os-truncate",
        language: DestructiveLanguage::Go,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::Truncate,
        patterns: &[RulePattern::Contains("os.Truncate(")],
    },
];

const RUST_RULES: &[DestructiveSinkRule] = &[
    DestructiveSinkRule {
        id: "rust-remove-dir-all",
        language: DestructiveLanguage::Rust,
        severity: DestructiveSeverity::Critical,
        operation: DestructiveOperation::RecursiveDelete,
        patterns: &[
            RulePattern::Contains("std::fs::remove_dir_all("),
            RulePattern::Contains("fs::remove_dir_all("),
        ],
    },
    DestructiveSinkRule {
        id: "rust-remove-file",
        language: DestructiveLanguage::Rust,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::DeleteFile,
        patterns: &[
            RulePattern::Contains("std::fs::remove_file("),
            RulePattern::Contains("fs::remove_file("),
        ],
    },
    DestructiveSinkRule {
        id: "rust-open-options-truncate",
        language: DestructiveLanguage::Rust,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::Truncate,
        patterns: &[RulePattern::All(&["OpenOptions::new()", ".truncate(true)"])],
    },
    DestructiveSinkRule {
        id: "rust-fs-write-overwrite",
        language: DestructiveLanguage::Rust,
        severity: DestructiveSeverity::Medium,
        operation: DestructiveOperation::Overwrite,
        patterns: &[
            RulePattern::Contains("std::fs::write("),
            RulePattern::Contains("fs::write("),
        ],
    },
];

const JAVA_RULES: &[DestructiveSinkRule] = &[
    DestructiveSinkRule {
        id: "java-files-delete",
        language: DestructiveLanguage::Java,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::DeleteFile,
        patterns: &[
            RulePattern::Contains("Files.delete("),
            RulePattern::Contains("Files.deleteIfExists("),
        ],
    },
    DestructiveSinkRule {
        id: "java-file-delete",
        language: DestructiveLanguage::Java,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::DeleteFile,
        patterns: &[RulePattern::Contains(".delete()")],
    },
];

const SHELL_RULES: &[DestructiveSinkRule] = &[
    DestructiveSinkRule {
        id: "shell-rm-rf",
        language: DestructiveLanguage::Shell,
        severity: DestructiveSeverity::Critical,
        operation: DestructiveOperation::ShellDelete,
        patterns: &[
            RulePattern::Contains("rm -rf"),
            RulePattern::Contains("rm -fr"),
            RulePattern::Contains("rm -r "),
            RulePattern::Contains("rm -R "),
        ],
    },
    DestructiveSinkRule {
        id: "shell-rmdir",
        language: DestructiveLanguage::Shell,
        severity: DestructiveSeverity::High,
        operation: DestructiveOperation::DeleteDirectory,
        patterns: &[RulePattern::Contains("rmdir ")],
    },
];

pub fn detect_destructive_sinks(path: &str, code: &str) -> Vec<DestructiveSinkMatch> {
    let Some(language) = language_for_path(path) else {
        return Vec::new();
    };

    let mut matches = matching_rules(language, code);

    if language == DestructiveLanguage::Shell && contains_shell_truncation(code) {
        matches.push(DestructiveSinkMatch {
            rule_id: "shell-truncation-redirection",
            language,
            severity: DestructiveSeverity::High,
            operation: DestructiveOperation::Truncate,
        });
    }

    matches
}

pub fn destructive_sink_score_modifier(matches: &[DestructiveSinkMatch]) -> f64 {
    matches
        .iter()
        .map(|sink_match| sink_match.severity.score_modifier())
        .fold(0.0, f64::max)
}

fn matching_rules(language: DestructiveLanguage, code: &str) -> Vec<DestructiveSinkMatch> {
    rules_for_language(language)
        .iter()
        .filter(|rule| {
            rule.patterns
                .iter()
                .any(|pattern| pattern_matches(*pattern, code))
        })
        .map(|rule| DestructiveSinkMatch {
            rule_id: rule.id,
            language: rule.language,
            severity: rule.severity,
            operation: rule.operation,
        })
        .collect()
}

fn pattern_matches(pattern: RulePattern, code: &str) -> bool {
    match pattern {
        RulePattern::Contains(token) => code.contains(token),
        RulePattern::All(tokens) => tokens.iter().all(|token| code.contains(token)),
    }
}

fn rules_for_language(language: DestructiveLanguage) -> &'static [DestructiveSinkRule] {
    match language {
        DestructiveLanguage::Python => PYTHON_RULES,
        DestructiveLanguage::JavaScript => JAVASCRIPT_RULES,
        DestructiveLanguage::TypeScript => TYPESCRIPT_RULES,
        DestructiveLanguage::Go => GO_RULES,
        DestructiveLanguage::Rust => RUST_RULES,
        DestructiveLanguage::Java => JAVA_RULES,
        DestructiveLanguage::Shell => SHELL_RULES,
    }
}

fn language_for_path(path: &str) -> Option<DestructiveLanguage> {
    let path = path.to_ascii_lowercase();

    if path.ends_with(".py") || path.ends_with(".pyi") {
        return Some(DestructiveLanguage::Python);
    }

    if path.ends_with(".ts") || path.ends_with(".tsx") {
        return Some(DestructiveLanguage::TypeScript);
    }

    if path.ends_with(".js")
        || path.ends_with(".jsx")
        || path.ends_with(".mjs")
        || path.ends_with(".cjs")
    {
        return Some(DestructiveLanguage::JavaScript);
    }

    if path.ends_with(".go") {
        return Some(DestructiveLanguage::Go);
    }

    if path.ends_with(".rs") {
        return Some(DestructiveLanguage::Rust);
    }

    if path.ends_with(".java") {
        return Some(DestructiveLanguage::Java);
    }

    if path.ends_with(".sh")
        || path.ends_with(".bash")
        || path.ends_with(".zsh")
        || path.ends_with(".ksh")
    {
        return Some(DestructiveLanguage::Shell);
    }

    None
}

fn contains_shell_truncation(code: &str) -> bool {
    code.lines().any(|line| {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            return false;
        }

        trimmed.starts_with('>') || (trimmed.contains(" > ") && !trimmed.contains(" >> "))
    })
}

impl DestructiveSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            DestructiveSeverity::Medium => "medium",
            DestructiveSeverity::High => "high",
            DestructiveSeverity::Critical => "critical",
        }
    }

    pub fn score_modifier(self) -> f64 {
        match self {
            DestructiveSeverity::Medium => 1.0,
            DestructiveSeverity::High => 2.0,
            DestructiveSeverity::Critical => 3.0,
        }
    }
}

impl DestructiveLanguage {
    pub fn as_str(self) -> &'static str {
        match self {
            DestructiveLanguage::Python => "python",
            DestructiveLanguage::JavaScript => "javascript",
            DestructiveLanguage::TypeScript => "typescript",
            DestructiveLanguage::Go => "go",
            DestructiveLanguage::Rust => "rust",
            DestructiveLanguage::Java => "java",
            DestructiveLanguage::Shell => "shell",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_destructive_sinks_across_initial_languages() {
        let cases = [
            (
                "tools/cleanup.py",
                "import shutil\nshutil.rmtree('./build')\n",
                "python-shutil-rmtree",
            ),
            (
                "scripts/cleanup.js",
                "fs.rmSync('./dist', { recursive: true })",
                "javascript-fs-rm-recursive",
            ),
            (
                "scripts/cleanup.ts",
                "fs.rmSync('./dist', { recursive: true })",
                "typescript-fs-rm-recursive",
            ),
            (
                "cmd/cleanup.go",
                "os.RemoveAll(\"./dist\")",
                "go-os-remove-all",
            ),
            (
                "src/cleanup.rs",
                "std::fs::remove_dir_all(\"target\")?;",
                "rust-remove-dir-all",
            ),
            (
                "src/Cleanup.java",
                "Files.delete(path);",
                "java-files-delete",
            ),
            ("scripts/cleanup.sh", "rm -rf ./target\n", "shell-rm-rf"),
        ];

        for (path, code, expected_rule_id) in cases {
            let matches = detect_destructive_sinks(path, code);

            assert!(
                matches
                    .iter()
                    .any(|matched| matched.rule_id == expected_rule_id),
                "expected {expected_rule_id} for {path}, got {matches:?}"
            );
        }
    }

    #[test]
    fn detects_obvious_shell_delete_strings_in_execution_apis() {
        let python_matches = detect_destructive_sinks(
            "tools/cleanup.py",
            "import subprocess\nsubprocess.run(\"rm -rf ./dist\", shell=True)\n",
        );
        assert!(python_matches
            .iter()
            .any(|matched| matched.rule_id == "python-shell-rm-rf"));

        let javascript_matches = detect_destructive_sinks(
            "tools/cleanup.js",
            "const { exec } = require('child_process');\nexec(\"rm -rf ./dist\");\n",
        );
        assert!(javascript_matches
            .iter()
            .any(|matched| matched.rule_id == "javascript-shell-rm-rf"));
    }

    #[test]
    fn safe_file_reads_are_not_flagged() {
        let cases = [
            ("tools/read.py", "open(\"README.md\").read()\n"),
            ("tools/read.js", "fs.readFileSync(\"README.md\")\n"),
            ("cmd/read.go", "os.ReadFile(\"README.md\")\n"),
            ("src/read.rs", "std::fs::read_to_string(\"README.md\")?;\n"),
            ("src/Read.java", "Files.readString(path);\n"),
            (
                "scripts/read.sh",
                "cat README.md\ngrep hello README.md\nls -la\n",
            ),
        ];

        for (path, code) in cases {
            let matches = detect_destructive_sinks(path, code);

            assert!(
                matches.is_empty(),
                "expected safe code for {path}, got {matches:?}"
            );
        }
    }

    #[test]
    fn shell_truncation_is_flagged_but_append_is_not() {
        let truncation_matches =
            detect_destructive_sinks("scripts/write.sh", "echo reset > important-file.txt\n");
        assert!(truncation_matches
            .iter()
            .any(|matched| matched.rule_id == "shell-truncation-redirection"));

        let append_matches =
            detect_destructive_sinks("scripts/write.sh", "echo keep >> important-file.txt\n");
        assert!(append_matches.is_empty());
    }

    #[test]
    fn severity_modifier_uses_strongest_match_only() {
        let matches = detect_destructive_sinks(
            "tools/cleanup.py",
            "os.remove('single.txt')\nshutil.rmtree('./build')\n",
        );

        assert_eq!(destructive_sink_score_modifier(&matches), 3.0);
    }
}
