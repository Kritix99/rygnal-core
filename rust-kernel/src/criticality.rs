#![allow(dead_code)] // Task 2 adds the evaluator; Task 3 exposes it through PyO3.

use crate::ast::{analyze_python_survival, AstError};
use crate::destructive_rules::{
    destructive_sink_score_modifier, detect_destructive_sinks, DestructiveSinkMatch,
};
use crate::models::ELEVATED_RISK_WEIGHT_ENV;
use crate::models::{
    CriticalityAssessment, CriticalityInput, CriticalityRiskLevel, FileActionType,
    PathSensitivityCategory, PathSensitivitySeverity, SemanticMetrics,
    DEFAULT_ELEVATED_RISK_WEIGHT,
};
use crate::path_safety;
use crate::path_safety::PathSafetyError;
use std::collections::BTreeMap;

const MAX_CRITICALITY: f64 = 10.0;
const MAX_TEXT_FALLBACK_LINE_BYTES: usize = 1_000;
const MAX_TEXT_FALLBACK_LINES: usize = 20_000;

#[derive(Debug)]
pub enum CriticalityError {
    InvalidPath(PathSafetyError),
    InvalidPathCategory(String),
    InvalidPathSeverity(String),
    Ast(AstError),
}

impl std::fmt::Display for CriticalityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CriticalityError::InvalidPath(err) => write!(formatter, "{err}"),
            CriticalityError::InvalidPathCategory(category) => {
                write!(formatter, "unknown path sensitivity category: {category}")
            }
            CriticalityError::InvalidPathSeverity(severity) => {
                write!(formatter, "unknown path sensitivity severity: {severity}")
            }
            CriticalityError::Ast(err) => write!(formatter, "{err}"),
        }
    }
}

impl std::error::Error for CriticalityError {}

impl From<PathSafetyError> for CriticalityError {
    fn from(value: PathSafetyError) -> Self {
        CriticalityError::InvalidPath(value)
    }
}

impl From<AstError> for CriticalityError {
    fn from(value: AstError) -> Self {
        CriticalityError::Ast(value)
    }
}

pub fn evaluate_criticality(
    input: &CriticalityInput,
) -> Result<CriticalityAssessment, CriticalityError> {
    let normalized_path = path_safety::validate_repo_relative_path(&input.file_path)?;
    let sensitivity = path_safety::classify_path_sensitivity(&normalized_path)?;
    let path_category = path_category_from_str(&sensitivity.category)?;
    let path_severity = path_severity_from_str(&sensitivity.severity)?;
    let semantic_metrics = semantic_metrics_for_input(input, &normalized_path)?;

    let path_base = path_base_score(path_category);
    let action_modifier = action_modifier(input.action_type);
    let semantic_modifier = semantic_modifier(
        input.action_type,
        semantic_metrics.survival_ratio,
        &input.old_code,
    );
    let destructive_sinks = detect_destructive_sinks(&normalized_path, &input.new_code);
    let destructive_modifier = destructive_sink_score_modifier(&destructive_sinks);
    let elevated_modifier = elevated_risk_modifier(input);

    let criticality_index = clamp_criticality(
        path_base + action_modifier + semantic_modifier + elevated_modifier + destructive_modifier,
    );
    let risk_level = risk_level_for_score(criticality_index);

    let reasons = build_reasons(CriticalityReasonContext {
        input,
        category: path_category,
        severity: path_severity,
        action_modifier,
        semantic_metrics,
        semantic_modifier,
        elevated_modifier,
        elevated_field_present: input.elevated.is_some(),
        destructive_sinks: &destructive_sinks,
        destructive_modifier,
        risk_level,
        used_python_ast: is_python_path(&normalized_path),
    });

    Ok(CriticalityAssessment {
        criticality_index,
        risk_level,
        reasons,
        semantic_metrics,
        path_category,
        path_severity,
    })
}

fn semantic_metrics_for_input(
    input: &CriticalityInput,
    normalized_path: &str,
) -> Result<SemanticMetrics, CriticalityError> {
    if input.old_code.trim().is_empty() && input.new_code.trim().is_empty() {
        return Ok(empty_semantic_metrics());
    }

    if is_python_path(normalized_path) {
        return match analyze_python_survival(&input.old_code, &input.new_code) {
            Ok(metrics) => Ok(metrics),
            Err(AstError::ParseFailed) | Err(AstError::SyntaxErrorNodes { .. }) => {
                Ok(text_survival_metrics(&input.old_code, &input.new_code))
            }
            Err(err) => Err(CriticalityError::from(err)),
        };
    }

    Ok(text_survival_metrics(&input.old_code, &input.new_code))
}

fn text_survival_metrics(old_code: &str, new_code: &str) -> SemanticMetrics {
    if should_use_bounded_text_fallback(old_code, new_code) {
        return bounded_text_survival_metrics(old_code, new_code);
    }

    let old_lines = normalized_non_empty_lines(old_code);
    let new_lines = normalized_non_empty_lines(new_code);

    let old_count = old_lines.len();
    let new_count = new_lines.len();

    let matched = count_multiset_intersection(&old_lines, &new_lines);

    let survival_ratio = if old_count == 0 {
        1.0
    } else {
        matched as f64 / old_count as f64
    };

    SemanticMetrics {
        old_node_count: 0,
        new_node_count: 0,
        old_token_count: old_count,
        new_token_count: new_count,
        matched_node_count: matched,
        survival_ratio: clamp_unit(survival_ratio),
    }
}

fn should_use_bounded_text_fallback(old_code: &str, new_code: &str) -> bool {
    has_oversized_trimmed_line(old_code)
        || has_oversized_trimmed_line(new_code)
        || bounded_non_empty_line_count(old_code) > MAX_TEXT_FALLBACK_LINES
        || bounded_non_empty_line_count(new_code) > MAX_TEXT_FALLBACK_LINES
}

fn has_oversized_trimmed_line(code: &str) -> bool {
    code.lines()
        .map(str::trim)
        .any(|line| line.len() > MAX_TEXT_FALLBACK_LINE_BYTES)
}

fn bounded_non_empty_line_count(code: &str) -> usize {
    code.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(MAX_TEXT_FALLBACK_LINES + 1)
        .count()
}

fn bounded_text_survival_metrics(old_code: &str, new_code: &str) -> SemanticMetrics {
    let old_count = bounded_non_empty_line_count(old_code);
    let new_count = bounded_non_empty_line_count(new_code);

    let matched = if old_count == 0 {
        0
    } else if old_code.trim() == new_code.trim() {
        old_count.min(new_count)
    } else {
        0
    };

    let survival_ratio = if old_count == 0 {
        1.0
    } else {
        matched as f64 / old_count as f64
    };

    SemanticMetrics {
        old_node_count: 0,
        new_node_count: 0,
        old_token_count: old_count,
        new_token_count: new_count,
        matched_node_count: matched,
        survival_ratio: clamp_unit(survival_ratio),
    }
}

fn normalized_non_empty_lines(code: &str) -> Vec<String> {
    code.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn count_multiset_intersection(old_lines: &[String], new_lines: &[String]) -> usize {
    let mut new_counts: BTreeMap<&str, usize> = BTreeMap::new();

    for line in new_lines {
        let count = new_counts.entry(line.as_str()).or_insert(0);
        *count = count.saturating_add(1);
    }

    old_lines
        .iter()
        .filter(|line| {
            let Some(count) = new_counts.get_mut(line.as_str()) else {
                return false;
            };

            if *count == 0 {
                return false;
            }

            *count -= 1;
            true
        })
        .count()
}

fn empty_semantic_metrics() -> SemanticMetrics {
    SemanticMetrics {
        old_node_count: 0,
        new_node_count: 0,
        old_token_count: 0,
        new_token_count: 0,
        matched_node_count: 0,
        survival_ratio: 1.0,
    }
}

fn path_base_score(category: PathSensitivityCategory) -> f64 {
    match category {
        PathSensitivityCategory::Secret => 9.0,
        PathSensitivityCategory::Ci | PathSensitivityCategory::Policy => 6.5,
        PathSensitivityCategory::Dependency => 6.0,
        PathSensitivityCategory::Config => 4.5,
        PathSensitivityCategory::Normal => 3.0,
        PathSensitivityCategory::Test => 1.5,
        PathSensitivityCategory::Documentation | PathSensitivityCategory::Generated => 1.0,
    }
}

fn action_modifier(action_type: FileActionType) -> f64 {
    match action_type {
        FileActionType::Deleted => 3.0,
        FileActionType::Renamed | FileActionType::ModeChanged => 1.0,
        FileActionType::Added | FileActionType::Untracked => 0.5,
        FileActionType::Modified => 0.0,
    }
}

fn semantic_modifier(action_type: FileActionType, survival_ratio: f64, old_code: &str) -> f64 {
    if action_type == FileActionType::Added || old_code.trim().is_empty() {
        return 0.0;
    }

    if action_type == FileActionType::Deleted {
        return 3.0;
    }

    let survival_ratio = clamp_unit(survival_ratio);
    let old_line_count = normalized_non_empty_lines(old_code).len();

    let modifier: f64 = if survival_ratio < 0.25 {
        3.0
    } else if survival_ratio < 0.50 {
        2.0
    } else if survival_ratio < 0.75 {
        1.0
    } else {
        0.0
    };

    if old_line_count <= 1 {
        modifier.min(1.0)
    } else {
        modifier
    }
}

fn risk_level_for_score(score: f64) -> CriticalityRiskLevel {
    if score >= 7.5 {
        CriticalityRiskLevel::Critical
    } else if score >= 5.0 {
        CriticalityRiskLevel::High
    } else if score >= 2.5 {
        CriticalityRiskLevel::Medium
    } else {
        CriticalityRiskLevel::Low
    }
}

struct CriticalityReasonContext<'a> {
    input: &'a CriticalityInput,
    category: PathSensitivityCategory,
    severity: PathSensitivitySeverity,
    action_modifier: f64,
    semantic_metrics: SemanticMetrics,
    semantic_modifier: f64,
    elevated_modifier: f64,
    elevated_field_present: bool,
    destructive_sinks: &'a [DestructiveSinkMatch],
    destructive_modifier: f64,
    risk_level: CriticalityRiskLevel,
    used_python_ast: bool,
}

fn build_reasons(context: CriticalityReasonContext<'_>) -> Vec<String> {
    let mut reasons = Vec::new();

    reasons.push(format!(
        "Path category {} has {} sensitivity.",
        context.category.as_str(),
        context.severity.as_str()
    ));

    if context.action_modifier > 0.0 {
        reasons.push(format!(
            "File action {} increases criticality by {:.1}.",
            context.input.action_type.as_str(),
            context.action_modifier
        ));
    }

    if context.used_python_ast {
        reasons.push(format!(
            "Python semantic survival ratio is {:.4}.",
            context.semantic_metrics.survival_ratio
        ));
    } else {
        reasons.push(format!(
            "Whitespace-normalized text survival ratio is {:.4}.",
            context.semantic_metrics.survival_ratio
        ));
    }

    if context.input.action_type == FileActionType::Added {
        reasons.push("Added files are not penalized for semantic destruction.".to_string());
    } else if context.input.old_code.trim().is_empty() {
        reasons.push("Empty old code has no semantic destruction penalty.".to_string());
    } else if context.semantic_modifier > 0.0 {
        reasons.push(format!(
            "Semantic destruction increases criticality by {:.1}.",
            context.semantic_modifier
        ));
    }

    if !context.elevated_field_present {
        reasons.push("Elevated risk field absent in payload; defaulted to false.".to_string());
    }

    if context.elevated_modifier > 0.0 {
        reasons.push(format!(
            "Python elevated risk signal increases criticality by {:.1}.",
            context.elevated_modifier
        ));
    }

    for sink_match in context.destructive_sinks.iter().take(3) {
        reasons.push(format!(
            "Detected {} destructive sink rule {} for {}.",
            sink_match.severity.as_str(),
            sink_match.rule_id,
            sink_match.language.as_str()
        ));
    }

    if context.destructive_modifier > 0.0 {
        reasons.push(format!(
            "Destructive sink rules increase criticality by {:.1}.",
            context.destructive_modifier
        ));
    }

    reasons.push(format!(
        "Final criticality level: {}.",
        context.risk_level.as_str()
    ));

    reasons
}

fn path_category_from_str(category: &str) -> Result<PathSensitivityCategory, CriticalityError> {
    match category {
        "secret" => Ok(PathSensitivityCategory::Secret),
        "ci" => Ok(PathSensitivityCategory::Ci),
        "policy" => Ok(PathSensitivityCategory::Policy),
        "dependency" => Ok(PathSensitivityCategory::Dependency),
        "config" => Ok(PathSensitivityCategory::Config),
        "generated" => Ok(PathSensitivityCategory::Generated),
        "test" => Ok(PathSensitivityCategory::Test),
        "documentation" => Ok(PathSensitivityCategory::Documentation),
        "normal" => Ok(PathSensitivityCategory::Normal),
        other => Err(CriticalityError::InvalidPathCategory(other.to_string())),
    }
}

fn path_severity_from_str(severity: &str) -> Result<PathSensitivitySeverity, CriticalityError> {
    match severity {
        "low" => Ok(PathSensitivitySeverity::Low),
        "medium" => Ok(PathSensitivitySeverity::Medium),
        "high" => Ok(PathSensitivitySeverity::High),
        "critical" => Ok(PathSensitivitySeverity::Critical),
        other => Err(CriticalityError::InvalidPathSeverity(other.to_string())),
    }
}

impl FileActionType {
    fn as_str(self) -> &'static str {
        match self {
            FileActionType::Added => "added",
            FileActionType::Modified => "modified",
            FileActionType::Deleted => "deleted",
            FileActionType::Renamed => "renamed",
            FileActionType::ModeChanged => "mode_changed",
            FileActionType::Untracked => "untracked",
        }
    }
}

impl CriticalityRiskLevel {
    fn as_str(self) -> &'static str {
        match self {
            CriticalityRiskLevel::Low => "low",
            CriticalityRiskLevel::Medium => "medium",
            CriticalityRiskLevel::High => "high",
            CriticalityRiskLevel::Critical => "critical",
        }
    }
}

impl PathSensitivityCategory {
    fn as_str(self) -> &'static str {
        match self {
            PathSensitivityCategory::Secret => "secret",
            PathSensitivityCategory::Ci => "ci",
            PathSensitivityCategory::Policy => "policy",
            PathSensitivityCategory::Dependency => "dependency",
            PathSensitivityCategory::Config => "config",
            PathSensitivityCategory::Generated => "generated",
            PathSensitivityCategory::Test => "test",
            PathSensitivityCategory::Documentation => "documentation",
            PathSensitivityCategory::Normal => "normal",
        }
    }
}

impl PathSensitivitySeverity {
    fn as_str(self) -> &'static str {
        match self {
            PathSensitivitySeverity::Low => "low",
            PathSensitivitySeverity::Medium => "medium",
            PathSensitivitySeverity::High => "high",
            PathSensitivitySeverity::Critical => "critical",
        }
    }
}

fn is_python_path(path: &str) -> bool {
    path.ends_with(".py") || path.ends_with(".pyi")
}

fn elevated_risk_modifier(input: &CriticalityInput) -> f64 {
    if input.elevated != Some(true) {
        return 0.0;
    }

    configured_elevated_risk_weight()
}

fn configured_elevated_risk_weight() -> f64 {
    let raw_weight = std::env::var(ELEVATED_RISK_WEIGHT_ENV).ok();
    parse_elevated_risk_weight(raw_weight.as_deref())
}

fn parse_elevated_risk_weight(raw_weight: Option<&str>) -> f64 {
    let Some(raw_weight) = raw_weight else {
        return DEFAULT_ELEVATED_RISK_WEIGHT;
    };

    let Ok(weight) = raw_weight.trim().parse::<f64>() else {
        return DEFAULT_ELEVATED_RISK_WEIGHT;
    };

    if !weight.is_finite() || weight <= 0.0 {
        return DEFAULT_ELEVATED_RISK_WEIGHT;
    }

    weight.min(MAX_CRITICALITY)
}

fn clamp_criticality(value: f64) -> f64 {
    if !value.is_finite() {
        return MAX_CRITICALITY;
    }

    value.clamp(0.0, MAX_CRITICALITY)
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

    fn input(
        file_path: &str,
        action_type: FileActionType,
        old_code: &str,
        new_code: &str,
    ) -> CriticalityInput {
        CriticalityInput {
            file_path: file_path.to_string(),
            action_type,
            old_code: old_code.to_string(),
            new_code: new_code.to_string(),
            elevated: Some(false),
        }
    }

    #[test]
    fn added_harmless_python_file_does_not_get_destruction_penalty() {
        let assessment = evaluate_criticality(&input(
            "src/utils.py",
            FileActionType::Added,
            "",
            "def helper():\n    return True\n",
        ))
        .expect("valid assessment");

        assert_eq!(assessment.risk_level, CriticalityRiskLevel::Medium);
        assert_eq!(assessment.semantic_metrics.survival_ratio, 1.0);
        assert!(!assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("Semantic destruction")));
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("Added files are not penalized")));
    }

    #[test]
    fn renamed_file_uses_target_path_for_sensitivity() {
        let assessment = evaluate_criticality(&input(
            ".env",
            FileActionType::Renamed,
            "TOKEN=example\n",
            "TOKEN=example\n",
        ))
        .expect("valid assessment");

        assert_eq!(assessment.path_category, PathSensitivityCategory::Secret);
        assert_eq!(assessment.path_severity, PathSensitivitySeverity::Critical);
        assert_eq!(assessment.risk_level, CriticalityRiskLevel::Critical);
    }

    #[test]
    fn non_python_text_fallback_ignores_indentation_only_changes() {
        let assessment = evaluate_criticality(&input(
            "config/settings.yml",
            FileActionType::Modified,
            "service:\n  enabled: true\n",
            "service:\n    enabled: true\n",
        ))
        .expect("valid assessment");

        assert_eq!(assessment.semantic_metrics.survival_ratio, 1.0);
        assert!(!assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("Semantic destruction")));
    }

    #[test]
    fn deleting_empty_file_has_no_semantic_destruction_penalty() {
        let assessment =
            evaluate_criticality(&input("src/empty.py", FileActionType::Deleted, "", ""))
                .expect("valid assessment");

        assert_eq!(assessment.semantic_metrics.survival_ratio, 1.0);
        assert!(!assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("Semantic destruction")));
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("Empty old code")));
    }

    #[test]
    fn secret_path_is_critical() {
        let assessment = evaluate_criticality(&input(
            ".env",
            FileActionType::Modified,
            "TOKEN=old\n",
            "TOKEN=new\n",
        ))
        .expect("valid assessment");

        assert_eq!(assessment.path_category, PathSensitivityCategory::Secret);
        assert_eq!(assessment.risk_level, CriticalityRiskLevel::Critical);
        assert!(assessment.criticality_index >= 9.0);
    }

    #[test]
    fn dependency_path_is_high() {
        let assessment = evaluate_criticality(&input(
            "Cargo.toml",
            FileActionType::Modified,
            "[dependencies]\nold = \"1\"\n",
            "[dependencies]\nnew = \"1\"\n",
        ))
        .expect("valid assessment");

        assert_eq!(
            assessment.path_category,
            PathSensitivityCategory::Dependency
        );
        assert_eq!(assessment.risk_level, CriticalityRiskLevel::High);
    }

    #[test]
    fn python_semantic_destruction_raises_risk() {
        let old_code = (0..10)
            .map(|index| {
                format!(
                    "old_symbol_{index} = {index}
"
                )
            })
            .collect::<String>();
        let new_code = (0..10)
            .map(|index| {
                format!(
                    "new_symbol_{index} = {index}
"
                )
            })
            .collect::<String>();

        let input = CriticalityInput {
            file_path: "src/service.py".to_string(),
            action_type: FileActionType::Modified,
            old_code,
            new_code,
            elevated: Some(false),
        };

        let assessment = evaluate_criticality(&input).expect("valid criticality input");

        assert_eq!(assessment.semantic_metrics.survival_ratio, 0.0);
        assert_eq!(assessment.risk_level, CriticalityRiskLevel::High);
        assert!(assessment.criticality_index >= 5.0);
        assert!(assessment.criticality_index < 7.5);
    }

    #[test]
    fn elevated_risk_signal_increases_criticality_with_configurable_weight() {
        let baseline = evaluate_criticality(&input(
            "src/service.py",
            FileActionType::Modified,
            "value = 1\\n",
            "value = 1\\n",
        ))
        .expect("valid baseline assessment");

        let mut elevated_input = input(
            "src/service.py",
            FileActionType::Modified,
            "value = 1\\n",
            "value = 1\\n",
        );
        elevated_input.elevated = Some(true);

        let elevated = evaluate_criticality(&elevated_input).expect("valid elevated assessment");

        assert!(elevated.criticality_index > baseline.criticality_index);
        assert!(
            (elevated.criticality_index
                - baseline.criticality_index
                - DEFAULT_ELEVATED_RISK_WEIGHT)
                .abs()
                < f64::EPSILON
        );
        assert!(elevated.reasons.iter().any(|reason| {
            reason.contains("Python elevated risk signal increases criticality by 2.0.")
        }));
    }
    #[test]
    fn elevated_risk_weight_config_accepts_positive_values() {
        assert_eq!(parse_elevated_risk_weight(Some("1.5")), 1.5);
    }

    #[test]
    fn elevated_risk_weight_config_rejects_zero_negative_and_non_finite_values() {
        assert_eq!(
            parse_elevated_risk_weight(Some("0")),
            DEFAULT_ELEVATED_RISK_WEIGHT
        );
        assert_eq!(
            parse_elevated_risk_weight(Some("-1.0")),
            DEFAULT_ELEVATED_RISK_WEIGHT
        );
        assert_eq!(
            parse_elevated_risk_weight(Some("NaN")),
            DEFAULT_ELEVATED_RISK_WEIGHT
        );
        assert_eq!(
            parse_elevated_risk_weight(Some("not-a-number")),
            DEFAULT_ELEVATED_RISK_WEIGHT
        );
    }

    #[test]
    fn destructive_sink_rules_increase_criticality_score() {
        let safe = evaluate_criticality(&input(
            "tools/cleanup.py",
            FileActionType::Modified,
            "print('safe')\n",
            "print('safe')\n",
        ))
        .expect("valid safe assessment");

        let destructive = evaluate_criticality(&input(
            "tools/cleanup.py",
            FileActionType::Modified,
            "import shutil\nshutil.rmtree('./build')\n",
            "import shutil\nshutil.rmtree('./build')\n",
        ))
        .expect("valid destructive assessment");

        assert!(destructive.criticality_index > safe.criticality_index);
        assert!(destructive
            .reasons
            .iter()
            .any(|reason| reason.contains("python-shutil-rmtree")));
        assert!(destructive
            .reasons
            .iter()
            .any(|reason| reason.contains("Destructive sink rules increase criticality")));
    }

    #[test]
    fn invalid_path_returns_error() {
        let err = evaluate_criticality(&input(
            "../evil.py",
            FileActionType::Modified,
            "def old(): pass\n",
            "def new(): pass\n",
        ))
        .expect_err("invalid path");

        match err {
            CriticalityError::InvalidPath(path_error) => {
                assert_eq!(path_error.code(), "parent-traversal");
            }
            other => panic!("expected invalid path error, got {other:?}"),
        }
    }

    #[test]
    fn tiny_python_rewrite_caps_semantic_destruction_penalty() {
        let input = CriticalityInput {
            file_path: "src/config.py".to_string(),
            action_type: FileActionType::Modified,
            old_code: "old_setting = 'old'\n".to_string(),
            new_code: "new_setting = 'new'\n".to_string(),
            elevated: Some(false),
        };

        let assessment = evaluate_criticality(&input).expect("valid criticality input");

        assert_eq!(assessment.semantic_metrics.survival_ratio, 0.0);
        assert_eq!(assessment.risk_level, CriticalityRiskLevel::High);
        assert!(assessment.criticality_index < 7.5);
    }

    #[test]
    fn larger_python_rewrite_still_gets_full_semantic_destruction_penalty() {
        let old_code = (0..10)
            .map(|index| format!("old_value_{index} = {index}\n"))
            .collect::<String>();
        let new_code = (0..10)
            .map(|index| format!("new_value_{index} = {index}\n"))
            .collect::<String>();

        let input = CriticalityInput {
            file_path: "src/config.py".to_string(),
            action_type: FileActionType::Modified,
            old_code,
            new_code,
            elevated: Some(false),
        };

        let assessment = evaluate_criticality(&input).expect("valid criticality input");

        assert_eq!(assessment.semantic_metrics.survival_ratio, 0.0);
        assert_eq!(assessment.risk_level, CriticalityRiskLevel::Critical);
        assert!(assessment.criticality_index >= 7.5);
    }

    #[test]
    fn invalid_python_syntax_falls_back_to_text_survival() {
        let input = CriticalityInput {
            file_path: "src/broken.py".to_string(),
            action_type: FileActionType::Modified,
            old_code: "def broken(:\n    value = 1\n".to_string(),
            new_code: "def broken(:\n    value = 1\n".to_string(),
            elevated: Some(false),
        };

        let assessment = evaluate_criticality(&input).expect("parse errors should fall back");

        assert_eq!(assessment.semantic_metrics.old_node_count, 0);
        assert_eq!(assessment.semantic_metrics.new_node_count, 0);
        assert_eq!(assessment.semantic_metrics.matched_node_count, 2);
        assert_eq!(assessment.semantic_metrics.survival_ratio, 1.0);
        assert_eq!(assessment.risk_level, CriticalityRiskLevel::Medium);
    }
}

#[cfg(test)]
mod hardening_regression_tests {
    use super::*;

    fn hardening_input(old_code: &str, new_code: &str) -> CriticalityInput {
        CriticalityInput {
            file_path: "src/service.py".to_string(),
            action_type: FileActionType::Modified,
            old_code: old_code.to_string(),
            new_code: new_code.to_string(),
            elevated: Some(false),
        }
    }

    #[test]
    fn broken_python_uses_text_fallback_instead_of_partial_ast_metrics() {
        let assessment = evaluate_criticality(&hardening_input(
            "def broken_0(:\ndef broken_1(:\ndef broken_2(:\n",
            "def fixed():\n    return 1\n",
        ))
        .expect("broken Python should fall back safely");

        assert_eq!(assessment.semantic_metrics.old_node_count, 0);
        assert_eq!(assessment.semantic_metrics.new_node_count, 0);
        assert!((0.0..=1.0).contains(&assessment.semantic_metrics.survival_ratio));
    }

    #[test]
    fn broken_minified_python_uses_bounded_text_fallback() {
        let old_code = format!("def broken(:\n{}\n", "x".repeat(2_000));
        let new_code = format!("def broken(:\n{}\n", "y".repeat(2_000));

        let assessment = evaluate_criticality(&hardening_input(&old_code, &new_code))
            .expect("broken minified Python should remain bounded");

        assert_eq!(assessment.semantic_metrics.old_node_count, 0);
        assert_eq!(assessment.semantic_metrics.new_node_count, 0);
        assert_eq!(assessment.semantic_metrics.old_token_count, 2);
        assert_eq!(assessment.semantic_metrics.new_token_count, 2);
        assert_eq!(assessment.semantic_metrics.matched_node_count, 0);
        assert_eq!(assessment.semantic_metrics.survival_ratio, 0.0);
    }

    #[test]
    fn large_multibyte_lines_remain_bounded_and_deterministic() {
        let old_code = format!("def value():\n    return {:?}\n", "🚀".repeat(1_500));
        let new_code = format!("def value():\n    return {:?}\n", "🌍".repeat(1_500));

        let assessment = evaluate_criticality(&hardening_input(&old_code, &new_code))
            .expect("large multi-byte lines should not panic or hang");

        assert!((0.0..=1.0).contains(&assessment.semantic_metrics.survival_ratio));
    }
}
