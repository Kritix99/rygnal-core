use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileChange {
    pub path: String,
    pub kind: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GitPatch {
    pub sha256: String,
    pub changes: Vec<FileChange>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AgentAction {
    pub file_path: String,
    pub action_type: String,
    pub raw_code: String,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct RiskAssessment {
    pub criticality_index: f64,
    pub risk_level: String,
    pub reasons: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct HumanContext {
    pub days_since_edit: f64,
    pub days_since_burst: f64,
    pub line_ownership_ratio: f64,
    pub is_explicitly_locked: bool,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SubjectiveRiskInput {
    pub file_path: String,
    pub action_type: String,
    pub system_risk: f64,
    pub old_code: String,
    pub new_code: String,
    pub human_context: HumanContext,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
pub struct SemanticMetrics {
    pub old_node_count: usize,
    pub new_node_count: usize,
    pub old_token_count: usize,
    pub new_token_count: usize,
    pub matched_node_count: usize,
    pub survival_ratio: f64,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct SubjectiveRiskAssessment {
    pub total_criticality: f64,
    pub judgment: String,
    pub reasons: Vec<String>,
    pub human_multiplier: f64,
    pub destruction_penalty: f64,
    pub semantic_metrics: SemanticMetrics,
}

#[allow(dead_code)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileActionType {
    Added,
    Modified,
    Deleted,
    Renamed,
    ModeChanged,
    Untracked,
}

#[allow(dead_code)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CriticalityRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[allow(dead_code)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathSensitivityCategory {
    Secret,
    Ci,
    Policy,
    Dependency,
    Config,
    Generated,
    Test,
    Documentation,
    Normal,
}

#[allow(dead_code)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathSensitivitySeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub const DEFAULT_ELEVATED_RISK_WEIGHT: f64 = 2.0;

#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CriticalityInput {
    pub file_path: String,
    pub action_type: FileActionType,
    pub old_code: String,
    pub new_code: String,
    #[serde(default)]
    pub elevated: bool,
    #[serde(default)]
    pub elevated_weight: Option<f64>,
}

#[allow(dead_code)]
#[derive(Serialize, Debug, PartialEq)]
pub struct CriticalityAssessment {
    pub criticality_index: f64,
    pub risk_level: CriticalityRiskLevel,
    pub reasons: Vec<String>,
    pub semantic_metrics: SemanticMetrics,
    pub path_category: PathSensitivityCategory,
    pub path_severity: PathSensitivitySeverity,
}

#[cfg(test)]
mod criticality_model_tests {
    use super::*;

    #[test]
    fn criticality_input_accepts_minimal_contract() {
        let payload = r#"{
            "file_path": "src/service.py",
            "action_type": "modified",
            "old_code": "def old(): pass",
            "new_code": "def new(): pass"
        }"#;

        let input = serde_json::from_str::<CriticalityInput>(payload).expect("valid input");

        assert_eq!(input.file_path, "src/service.py");
        assert_eq!(input.action_type, FileActionType::Modified);
        assert_eq!(input.old_code, "def old(): pass");
        assert_eq!(input.new_code, "def new(): pass");
        assert!(!input.elevated);
        assert_eq!(input.elevated_weight, None);
    }

    #[test]
    fn criticality_input_accepts_elevated_signal_contract() {
        let payload = r#"{
            "file_path": "package-lock.json",
            "action_type": "modified",
            "old_code": "{}",
            "new_code": "{bad-json",
            "elevated": true,
            "elevated_weight": 1.5
        }"#;

        let input = serde_json::from_str::<CriticalityInput>(payload).expect("valid input");

        assert!(input.elevated);
        assert_eq!(input.elevated_weight, Some(1.5));
    }

    #[test]
    fn criticality_input_accepts_all_supported_action_types() {
        let cases = [
            ("added", FileActionType::Added),
            ("modified", FileActionType::Modified),
            ("deleted", FileActionType::Deleted),
            ("renamed", FileActionType::Renamed),
            ("mode_changed", FileActionType::ModeChanged),
            ("untracked", FileActionType::Untracked),
        ];

        for (raw_action, expected_action) in cases {
            let payload = format!(
                r#"{{
                    "file_path": "src/service.py",
                    "action_type": "{raw_action}",
                    "old_code": "",
                    "new_code": ""
                }}"#
            );

            let input = serde_json::from_str::<CriticalityInput>(&payload).expect("valid action");

            assert_eq!(input.action_type, expected_action);
        }
    }

    #[test]
    fn criticality_input_rejects_unknown_action_type() {
        let payload = r#"{
            "file_path": "src/service.py",
            "action_type": "modifed",
            "old_code": "def old(): pass",
            "new_code": "def new(): pass"
        }"#;

        let result = serde_json::from_str::<CriticalityInput>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn criticality_input_rejects_unknown_fields() {
        let payload = r#"{
            "file_path": "src/service.py",
            "action_type": "modified",
            "old_code": "def old(): pass",
            "new_code": "def new(): pass",
            "unexpected": true
        }"#;

        let result = serde_json::from_str::<CriticalityInput>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn criticality_enums_serialize_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&CriticalityRiskLevel::Critical).unwrap(),
            r#""critical""#
        );
        assert_eq!(
            serde_json::to_string(&FileActionType::ModeChanged).unwrap(),
            r#""mode_changed""#
        );
        assert_eq!(
            serde_json::to_string(&PathSensitivityCategory::Documentation).unwrap(),
            r#""documentation""#
        );
        assert_eq!(
            serde_json::to_string(&PathSensitivitySeverity::High).unwrap(),
            r#""high""#
        );
    }

    #[test]
    fn criticality_assessment_serializes_stable_shape() {
        let assessment = CriticalityAssessment {
            criticality_index: 7.5,
            risk_level: CriticalityRiskLevel::High,
            reasons: vec!["semantic survival dropped below threshold".to_string()],
            semantic_metrics: SemanticMetrics {
                old_node_count: 10,
                new_node_count: 5,
                old_token_count: 4,
                new_token_count: 2,
                matched_node_count: 1,
                survival_ratio: 0.25,
            },
            path_category: PathSensitivityCategory::Dependency,
            path_severity: PathSensitivitySeverity::High,
        };

        let value = serde_json::to_value(&assessment).expect("serializable assessment");

        assert_eq!(value["criticality_index"], 7.5);
        assert_eq!(value["risk_level"], "high");
        assert_eq!(
            value["reasons"][0],
            "semantic survival dropped below threshold"
        );
        assert_eq!(value["path_category"], "dependency");
        assert_eq!(value["path_severity"], "high");
        assert_eq!(value["semantic_metrics"]["survival_ratio"], 0.25);
    }
}
