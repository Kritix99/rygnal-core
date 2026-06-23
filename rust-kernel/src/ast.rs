use crate::models::SemanticMetrics;
use std::collections::BTreeMap;
use tree_sitter::{Node, Parser};

const MAX_AST_NAMED_NODES: usize = 50_000;
const DEFAULT_MAX_AST_SOURCE_BYTES: usize = 1_000_000;
const DEFAULT_TREE_SITTER_PARSE_TIMEOUT_MICROS: u64 = 2_000_000;
const MAX_AST_SOURCE_BYTES_ENV: &str = "RYGNAL_AST_MAX_SOURCE_BYTES";
const TREE_SITTER_PARSE_TIMEOUT_MICROS_ENV: &str = "RYGNAL_TREE_SITTER_PARSE_TIMEOUT_MICROS";
// Any Tree-Sitter error or missing node means the recovered AST is not
// trustworthy enough for semantic-destruction math. Fall back to text.
const MAX_TRUSTED_AST_ERROR_NODES: usize = 0;

#[derive(Debug)]
pub enum AstError {
    LanguageLoad(String),
    ParseFailed,
    ParseTimedOut {
        timeout_micros: u64,
    },
    SourceTooLarge {
        source_bytes: usize,
        limit: usize,
    },
    SyntaxErrorNodes {
        error_node_count: usize,
        limit: usize,
    },
    AstTooLarge {
        named_node_count: usize,
        limit: usize,
    },
    InvalidUtf8(String),
}

impl std::fmt::Display for AstError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AstError::LanguageLoad(message) => {
                write!(formatter, "failed to load Python grammar: {message}")
            }
            AstError::ParseFailed => write!(formatter, "tree-sitter failed to parse Python code"),
            AstError::ParseTimedOut { timeout_micros } => write!(
                formatter,
                "tree-sitter Python parse timed out after {timeout_micros} microseconds"
            ),
            AstError::SourceTooLarge {
                source_bytes,
                limit,
            } => write!(
                formatter,
                "Python source is {source_bytes} bytes, exceeding Tree-Sitter limit {limit}"
            ),
            AstError::SyntaxErrorNodes {
                error_node_count,
                limit,
            } => write!(
                formatter,
                "Python AST contains {error_node_count} untrusted syntax nodes, exceeding limit {limit}"
            ),
            AstError::AstTooLarge {
                named_node_count,
                limit,
            } => write!(
                formatter,
                "Python AST named node count {named_node_count} exceeds limit {limit}"
            ),
            AstError::InvalidUtf8(message) => {
                write!(
                    formatter,
                    "tree-sitter produced invalid UTF-8 span: {message}"
                )
            }
        }
    }
}

impl std::error::Error for AstError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxFeatures {
    pub named_node_count: usize,
    pub semantic_tokens: BTreeMap<String, usize>,
}

pub fn analyze_python_survival(
    old_code: &str,
    new_code: &str,
) -> Result<SemanticMetrics, AstError> {
    let old_features = extract_python_features(old_code)?;
    let new_features = extract_python_features(new_code)?;

    let old_token_count = old_features
        .semantic_tokens
        .values()
        .try_fold(0usize, |acc, value| acc.checked_add(*value))
        .unwrap_or(usize::MAX);

    let new_token_count = new_features
        .semantic_tokens
        .values()
        .try_fold(0usize, |acc, value| acc.checked_add(*value))
        .unwrap_or(usize::MAX);

    let matched_node_count =
        count_multiset_intersection(&old_features.semantic_tokens, &new_features.semantic_tokens);

    let survival_ratio = if old_token_count == 0 {
        1.0
    } else {
        matched_node_count as f64 / old_token_count as f64
    };

    Ok(SemanticMetrics {
        old_node_count: old_features.named_node_count,
        new_node_count: new_features.named_node_count,
        old_token_count,
        new_token_count,
        matched_node_count,
        survival_ratio: clamp_unit(survival_ratio),
    })
}

fn configured_max_ast_source_bytes() -> usize {
    std::env::var(MAX_AST_SOURCE_BYTES_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_AST_SOURCE_BYTES)
}

fn configured_tree_sitter_parse_timeout_micros() -> u64 {
    std::env::var(TREE_SITTER_PARSE_TIMEOUT_MICROS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_TREE_SITTER_PARSE_TIMEOUT_MICROS)
}

fn extract_python_features(code: &str) -> Result<SyntaxFeatures, AstError> {
    let source_limit = configured_max_ast_source_bytes();
    if code.len() > source_limit {
        return Err(AstError::SourceTooLarge {
            source_bytes: code.len(),
            limit: source_limit,
        });
    }

    let mut parser = Parser::new();
    let language = tree_sitter_python::language();

    parser
        .set_language(language)
        .map_err(|err| AstError::LanguageLoad(err.to_string()))?;
    let timeout_micros = configured_tree_sitter_parse_timeout_micros();
    parser.set_timeout_micros(timeout_micros);

    let tree = parser
        .parse(code, None)
        .ok_or(AstError::ParseTimedOut { timeout_micros })?;
    let root = tree.root_node();

    let untrusted_syntax_count = count_untrusted_syntax_nodes(root);
    if untrusted_syntax_count > MAX_TRUSTED_AST_ERROR_NODES {
        return Err(AstError::SyntaxErrorNodes {
            error_node_count: untrusted_syntax_count,
            limit: MAX_TRUSTED_AST_ERROR_NODES,
        });
    }

    if root.has_error() {
        return Err(AstError::ParseFailed);
    }

    let mut features = SyntaxFeatures {
        named_node_count: count_named_nodes(root)?,
        semantic_tokens: BTreeMap::new(),
    };

    collect_semantic_tokens(root, code.as_bytes(), &mut features.semantic_tokens)?;

    Ok(features)
}

fn count_named_nodes(node: Node<'_>) -> Result<usize, AstError> {
    let mut count = 0;
    count_named_nodes_inner(node, &mut count)?;
    Ok(count)
}

fn count_named_nodes_inner(node: Node<'_>, count: &mut usize) -> Result<(), AstError> {
    if node.kind() == "comment" {
        return Ok(());
    }

    if node.is_named() {
        *count = count.saturating_add(1);
        if *count > MAX_AST_NAMED_NODES {
            return Err(AstError::AstTooLarge {
                named_node_count: *count,
                limit: MAX_AST_NAMED_NODES,
            });
        }
    }

    for index in 0..node.child_count() {
        if let Some(child) = node.child(index) {
            count_named_nodes_inner(child, count)?;
        }
    }

    Ok(())
}

fn count_untrusted_syntax_nodes(node: Node<'_>) -> usize {
    let current = usize::from(node.is_error() || node.is_missing() || node.kind() == "ERROR");

    current
        + (0..node.child_count())
            .filter_map(|index| node.child(index))
            .map(count_untrusted_syntax_nodes)
            .fold(0usize, usize::saturating_add)
}

fn collect_semantic_tokens(
    node: Node<'_>,
    source: &[u8],
    tokens: &mut BTreeMap<String, usize>,
) -> Result<(), AstError> {
    if node.kind() == "comment" {
        return Ok(());
    }

    match node.kind() {
        "function_definition" => {
            if let Some(name) = child_text_by_field(node, "name", source)? {
                add_token(tokens, "function", &name);
            }
        }
        "class_definition" => {
            if let Some(name) = child_text_by_field(node, "name", source)? {
                add_token(tokens, "class", &name);
            }
        }
        "assignment" => {
            if let Some(left) = node.child_by_field_name("left") {
                collect_assignment_identifiers(left, source, tokens)?;
            }
        }
        "import_statement" | "import_from_statement" => {
            collect_import_identifiers(node, source, tokens)?;
        }
        _ => {}
    }

    for index in 0..node.child_count() {
        if let Some(child) = node.child(index) {
            collect_semantic_tokens(child, source, tokens)?;
        }
    }

    Ok(())
}

fn collect_assignment_identifiers(
    node: Node<'_>,
    source: &[u8],
    tokens: &mut BTreeMap<String, usize>,
) -> Result<(), AstError> {
    match node.kind() {
        "identifier" => {
            add_token(tokens, "variable", &node_text(node, source)?);
        }
        "tuple" | "list" | "pattern_list" => {
            for index in 0..node.child_count() {
                if let Some(child) = node.child(index) {
                    collect_assignment_identifiers(child, source, tokens)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn collect_import_identifiers(
    node: Node<'_>,
    source: &[u8],
    tokens: &mut BTreeMap<String, usize>,
) -> Result<(), AstError> {
    match node.kind() {
        "identifier" | "dotted_name" => {
            add_token(tokens, "import", &node_text(node, source)?);
        }
        _ => {
            for index in 0..node.child_count() {
                if let Some(child) = node.child(index) {
                    collect_import_identifiers(child, source, tokens)?;
                }
            }
        }
    }

    Ok(())
}

fn child_text_by_field(
    node: Node<'_>,
    field_name: &str,
    source: &[u8],
) -> Result<Option<String>, AstError> {
    match node.child_by_field_name(field_name) {
        Some(child) => node_text(child, source).map(Some),
        None => Ok(None),
    }
}

fn node_text(node: Node<'_>, source: &[u8]) -> Result<String, AstError> {
    let text = node
        .utf8_text(source)
        .map_err(|err| AstError::InvalidUtf8(err.to_string()))?;

    Ok(text.trim().to_string())
}

fn add_token(tokens: &mut BTreeMap<String, usize>, category: &str, value: &str) {
    let normalized = value.trim();

    if normalized.is_empty() {
        return;
    }

    let key = format!("{category}:{normalized}");
    let count = tokens.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

fn count_multiset_intersection(
    old_tokens: &BTreeMap<String, usize>,
    new_tokens: &BTreeMap<String, usize>,
) -> usize {
    old_tokens
        .iter()
        .map(|(token, old_count)| {
            let new_count = new_tokens.get(token).copied().unwrap_or(0);
            (*old_count).min(new_count)
        })
        .fold(0usize, usize::saturating_add)
}

fn clamp_unit(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }

    value.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_survival_preserves_functions_and_variables() {
        let old_code = r#"
import os

class Worker:
    pass

def cleanup():
    target = "production.db"
    os.remove(target)
"#;
        let new_code = r#"
import os

class Worker:
    pass

def cleanup():
    target = "staging.db"
    print(target)
"#;

        let metrics = analyze_python_survival(old_code, new_code).expect("valid Python code");

        assert!(metrics.old_node_count > 0);
        assert!(metrics.new_node_count > 0);
        assert!(metrics.old_token_count >= 4);
        assert!(metrics.matched_node_count >= 3);
        assert!(metrics.survival_ratio > 0.5);
        assert!(metrics.survival_ratio <= 1.0);
    }

    #[test]
    fn python_survival_penalizes_removed_semantic_tokens() {
        let old_code = r#"
def important_business_rule():
    account_limit = 100
    fraud_threshold = 3
    return account_limit
"#;
        let new_code = r#"
def replacement():
    return 1
"#;

        let metrics = analyze_python_survival(old_code, new_code).expect("valid Python code");

        assert!(metrics.old_token_count >= 3);
        assert_eq!(metrics.matched_node_count, 0);
        assert_eq!(metrics.survival_ratio, 0.0);
    }

    #[test]
    fn empty_old_code_has_full_survival_ratio() {
        let metrics = analyze_python_survival("", "def created():\n    return True\n")
            .expect("valid Python code");

        assert_eq!(metrics.old_token_count, 0);
        assert_eq!(metrics.survival_ratio, 1.0);
    }

    #[test]
    fn python_survival_ignores_comment_only_changes() {
        let old_code = r#"
# keep this comment
def stable():
    value = 1
    return value
"#;
        let new_code = r#"
# changed comment text
def stable():
    value = 1
    return value
"#;

        let metrics = analyze_python_survival(old_code, new_code).expect("valid Python");

        assert_eq!(metrics.survival_ratio, 1.0);
        assert_eq!(metrics.old_token_count, metrics.new_token_count);
        assert_eq!(metrics.old_node_count, metrics.new_node_count);
    }

    #[test]
    fn python_survival_rejects_ast_above_named_node_limit() {
        let large_code = (0..20_000)
            .map(|index| format!("value_{index} = {index}\n"))
            .collect::<String>();

        let error = analyze_python_survival(&large_code, &large_code)
            .expect_err("large AST should be rejected");

        match error {
            AstError::AstTooLarge {
                named_node_count,
                limit,
            } => {
                assert!(named_node_count > limit);
                assert_eq!(limit, MAX_AST_NAMED_NODES);
            }
            other => panic!("expected AstTooLarge, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod hardening_regression_tests {
    use super::*;

    #[test]
    fn multibyte_python_source_does_not_panic_or_break_utf8_boundaries() {
        let old_code = r#"
def load_message():
    message = "नमस्ते 🚀"
    return message
"#;

        let new_code = r#"
def load_message():
    message = "नमस्ते 🌍"
    return message
"#;

        let metrics = analyze_python_survival(old_code, new_code)
            .expect("multi-byte Python source should remain byte-boundary safe");

        assert!(metrics.old_token_count > 0);
        assert!(metrics.new_token_count > 0);
        assert!((0.0..=1.0).contains(&metrics.survival_ratio));
    }

    #[test]
    fn syntax_error_nodes_are_rejected_for_safe_fallback() {
        let broken_code = "def broken_0(:\ndef broken_1(:\ndef broken_2(:\n";

        let error = analyze_python_survival(broken_code, "def ok():\n    return 1\n")
            .expect_err("syntax-error AST should not be trusted");

        match error {
            AstError::SyntaxErrorNodes {
                error_node_count,
                limit,
            } => {
                assert!(error_node_count > limit);
            }
            other => panic!("expected SyntaxErrorNodes, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod ast_dos_hardening_tests {
    use super::*;

    #[test]
    fn oversized_python_source_is_rejected_before_tree_sitter() {
        let code = format!("x = '{}'", "a".repeat(DEFAULT_MAX_AST_SOURCE_BYTES + 1));

        let err = extract_python_features(&code).expect_err("oversized source should be rejected");

        assert!(matches!(
            err,
            AstError::SourceTooLarge {
                source_bytes,
                limit
            } if source_bytes > limit && limit == DEFAULT_MAX_AST_SOURCE_BYTES
        ));
    }

    #[test]
    fn python_source_size_boundary_is_inclusive() {
        let prefix = "x = '";
        let suffix = "'\n";
        let filler_len = DEFAULT_MAX_AST_SOURCE_BYTES - prefix.len() - suffix.len();
        let at_limit = format!("{prefix}{}{suffix}", "a".repeat(filler_len));

        assert_eq!(at_limit.len(), DEFAULT_MAX_AST_SOURCE_BYTES);
        extract_python_features(&at_limit).expect("source exactly at limit should parse");

        let over_limit = format!("{at_limit}x");
        let err = extract_python_features(&over_limit)
            .expect_err("source one byte over limit should be rejected");

        assert!(matches!(
            err,
            AstError::SourceTooLarge {
                source_bytes,
                limit
            } if source_bytes == DEFAULT_MAX_AST_SOURCE_BYTES + 1
                && limit == DEFAULT_MAX_AST_SOURCE_BYTES
        ));
    }

    #[test]
    fn normal_python_still_parses_with_timeout_configured() {
        let features = extract_python_features("def ok():\n    return 1\n")
            .expect("normal Python should still parse");

        assert!(features.named_node_count > 0);
        assert!(features.semantic_tokens.contains_key("function:ok"));
    }
}
