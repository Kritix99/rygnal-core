mod ast;
mod criticality;
mod destructive_rules;
mod models;
mod path_safety;
mod subjective;

use crate::criticality::{evaluate_criticality as evaluate_criticality_inner, CriticalityError};
use crate::models::{AgentAction, CriticalityInput, GitPatch, RiskAssessment, SubjectiveRiskInput};
use crate::path_safety::{PathSensitivity, PathValidationOutcome};
use crate::subjective::evaluate_subjective_risk as evaluate_subjective_risk_inner;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::panic::{catch_unwind, AssertUnwindSafe};
use tree_sitter::Parser;

create_exception!(rygnal_kernel, CriticalityEvaluationError, PyException);

#[pyfunction]
fn verify_bridge(payload: String) -> PyResult<String> {
    Ok(format!(
        "[Rust Kernel]: Connection secure. Received payload -> {}",
        payload
    ))
}

#[pyfunction]
fn engine_version() -> PyResult<String> {
    Ok(path_safety::engine_version().to_string())
}

#[pyfunction]
fn validate_repo_relative_path(py: Python<'_>, path: String) -> PyResult<PyObject> {
    path_validation_outcome_to_python(py, path_safety::check_repo_relative_path(&path))
}

#[pyfunction]
fn validate_patch_path(py: Python<'_>, path: String) -> PyResult<PyObject> {
    path_validation_outcome_to_python(py, path_safety::check_patch_path(&path))
}

#[pyfunction]
fn classify_path_sensitivity(py: Python<'_>, path: String) -> PyResult<PyObject> {
    match path_safety::classify_path_sensitivity(&path) {
        Ok(sensitivity) => path_sensitivity_to_python(py, sensitivity),
        Err(err) => Err(PyValueError::new_err(format!("{}: {}", err.code(), err))),
    }
}

fn path_validation_outcome_to_python(
    py: Python<'_>,
    outcome: PathValidationOutcome,
) -> PyResult<PyObject> {
    let dict = PyDict::new(py);

    dict.set_item("safe", outcome.safe)?;
    match outcome.normalized_path {
        Some(path) => dict.set_item("normalized_path", path)?,
        None => dict.set_item("normalized_path", py.None())?,
    }
    match outcome.error_code {
        Some(code) => dict.set_item("error_code", code)?,
        None => dict.set_item("error_code", py.None())?,
    }
    match outcome.reason {
        Some(reason) => dict.set_item("reason", reason)?,
        None => dict.set_item("reason", py.None())?,
    }
    dict.set_item("is_sentinel", outcome.is_sentinel)?;

    Ok(dict.into())
}

fn path_sensitivity_to_python(py: Python<'_>, sensitivity: PathSensitivity) -> PyResult<PyObject> {
    let dict = PyDict::new(py);

    dict.set_item("category", sensitivity.category)?;
    dict.set_item("severity", sensitivity.severity)?;
    dict.set_item("reason", sensitivity.reason)?;

    Ok(dict.into())
}

#[pyfunction]
fn evaluate_patch_risk(json_payload: String) -> PyResult<String> {
    let patch: GitPatch = serde_json::from_str(&json_payload).map_err(|err| {
        PyValueError::new_err(format!("Rust safety kernel failed to parse JSON: {}", err))
    })?;

    let deleted_paths: Vec<&str> = patch
        .changes
        .iter()
        .filter(|change| change.kind == "deleted")
        .map(|change| change.path.as_str())
        .collect();

    Ok(format!(
        "Kernel evaluated patch [{}]. Analyzed {} files. High-risk deletions detected: {}",
        patch.sha256,
        patch.changes.len(),
        deleted_paths.len()
    ))
}

#[pyfunction]
fn analyze_code_structure(raw_code: String) -> PyResult<String> {
    let mut parser = Parser::new();

    let language = tree_sitter_python::language();
    parser
        .set_language(language)
        .map_err(|err| PyValueError::new_err(format!("Failed to load Python grammar: {}", err)))?;

    let tree = parser
        .parse(&raw_code, None)
        .ok_or_else(|| PyValueError::new_err("Tree-Sitter failed to parse the provided code"))?;

    let root_node = tree.root_node();

    Ok(format!(
        "AST Parsed Successfully.\nNode Count: {}\nStructure: {}",
        root_node.child_count(),
        root_node.to_sexp()
    ))
}

#[pyfunction]
fn evaluate_agent_action(json_payload: String) -> PyResult<String> {
    let action: AgentAction = serde_json::from_str(&json_payload)
        .map_err(|err| PyValueError::new_err(format!("Invalid action payload: {}", err)))?;

    let mut base_score: f64 = 0.0;
    let mut risk_reasons: Vec<String> = Vec::new();

    if action.file_path.contains("config") || action.file_path.contains("settings") {
        base_score += 4.0;
        risk_reasons.push("Modifies core configuration path".to_string());
    } else if action.file_path.starts_with("tests/") {
        base_score += 0.5;
    } else {
        base_score += 2.0;
    }

    if action.action_type == "deleted" {
        base_score += 5.0;
        risk_reasons.push("Destructive action: File deletion".to_string());
    }

    if !action.raw_code.is_empty() && action.action_type != "deleted" {
        let mut parser = Parser::new();
        let language = tree_sitter_python::language();

        parser.set_language(language).map_err(|err| {
            PyValueError::new_err(format!("Failed to load Python grammar: {}", err))
        })?;

        let tree = parser
            .parse(&action.raw_code, None)
            .ok_or_else(|| PyValueError::new_err("Tree-Sitter failed to parse action raw_code"))?;

        let s_exp = tree.root_node().to_sexp();

        if s_exp.contains("import_statement") {
            base_score += 2.5;
            risk_reasons.push("Introduces or modifies dependencies (import statement)".to_string());
        }

        if s_exp.contains("call") && s_exp.contains("attribute") {
            base_score += 1.5;
            risk_reasons.push("Contains system or external attribute calls".to_string());
        }
    }

    let criticality_index = base_score.min(10.0);

    let risk_level = if criticality_index >= 7.5 {
        "dangerous"
    } else if criticality_index >= 4.0 {
        "risky"
    } else {
        "safe"
    };

    let assessment = RiskAssessment {
        criticality_index,
        risk_level: risk_level.to_string(),
        reasons: risk_reasons,
    };

    serde_json::to_string(&assessment)
        .map_err(|err| PyValueError::new_err(format!("Failed to serialize assessment: {}", err)))
}

#[derive(Debug)]
enum CriticalityBoundaryError {
    InvalidPayload(String),
    Evaluation(CriticalityError),
    Serialize(String),
    NativePanic,
}

#[pyfunction]
fn evaluate_criticality(py: Python<'_>, json_payload: String) -> PyResult<String> {
    py.allow_threads(move || {
        evaluate_criticality_with_panic_boundary(|| evaluate_criticality_json(&json_payload))
    })
    .map_err(criticality_boundary_error_to_py_error)
}

fn evaluate_criticality_with_panic_boundary<F>(
    operation: F,
) -> Result<String, CriticalityBoundaryError>
where
    F: FnOnce() -> Result<String, CriticalityBoundaryError>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => Err(CriticalityBoundaryError::NativePanic),
    }
}

fn evaluate_criticality_json(json_payload: &str) -> Result<String, CriticalityBoundaryError> {
    let input: CriticalityInput = serde_json::from_str(json_payload)
        .map_err(|err| CriticalityBoundaryError::InvalidPayload(err.to_string()))?;

    let assessment =
        evaluate_criticality_inner(&input).map_err(CriticalityBoundaryError::Evaluation)?;

    serde_json::to_string(&assessment)
        .map_err(|err| CriticalityBoundaryError::Serialize(err.to_string()))
}

fn criticality_boundary_error_to_py_error(err: CriticalityBoundaryError) -> PyErr {
    match err {
        CriticalityBoundaryError::InvalidPayload(message) => {
            PyValueError::new_err(format!("Invalid criticality payload: {message}"))
        }
        CriticalityBoundaryError::Evaluation(err) => criticality_error_to_py_error(err),
        CriticalityBoundaryError::Serialize(message) => PyValueError::new_err(format!(
            "Failed to serialize criticality assessment: {message}"
        )),
        CriticalityBoundaryError::NativePanic => {
            CriticalityEvaluationError::new_err(native_panic_error_json())
        }
    }
}

fn native_panic_error_json() -> String {
    serde_json::json!({
        "error_code": "native-panic",
        "reason": "Rust criticality evaluation panicked and was safely contained",
    })
    .to_string()
}

fn criticality_error_to_py_error(err: CriticalityError) -> PyErr {
    let error_json = serde_json::json!({
        "error_code": criticality_error_code(&err),
        "reason": err.to_string(),
    })
    .to_string();

    CriticalityEvaluationError::new_err(error_json)
}

fn criticality_error_code(err: &CriticalityError) -> &'static str {
    match err {
        CriticalityError::InvalidPath(path_error) => path_error.code(),
        CriticalityError::InvalidPathCategory(_) => "invalid-path-category",
        CriticalityError::InvalidPathSeverity(_) => "invalid-path-severity",
        CriticalityError::Ast(_) => "ast-analysis-failed",
    }
}

#[pyfunction]
fn evaluate_subjective_risk(json_payload: String) -> PyResult<String> {
    let input: SubjectiveRiskInput = serde_json::from_str(&json_payload).map_err(|err| {
        PyValueError::new_err(format!("Invalid subjective risk payload: {}", err))
    })?;

    let assessment = evaluate_subjective_risk_inner(&input).map_err(|err| {
        PyValueError::new_err(format!("Subjective risk evaluation failed: {}", err))
    })?;

    serde_json::to_string(&assessment).map_err(|err| {
        PyValueError::new_err(format!(
            "Failed to serialize subjective risk assessment: {}",
            err
        ))
    })
}

#[pymodule]
fn rygnal_kernel(py: Python, module: &PyModule) -> PyResult<()> {
    module.add(
        "CriticalityEvaluationError",
        py.get_type::<CriticalityEvaluationError>(),
    )?;
    module.add_function(wrap_pyfunction!(verify_bridge, module)?)?;
    module.add_function(wrap_pyfunction!(engine_version, module)?)?;
    module.add_function(wrap_pyfunction!(validate_repo_relative_path, module)?)?;
    module.add_function(wrap_pyfunction!(validate_patch_path, module)?)?;
    module.add_function(wrap_pyfunction!(classify_path_sensitivity, module)?)?;
    module.add_function(wrap_pyfunction!(evaluate_patch_risk, module)?)?;
    module.add_function(wrap_pyfunction!(analyze_code_structure, module)?)?;
    module.add_function(wrap_pyfunction!(evaluate_agent_action, module)?)?;
    module.add_function(wrap_pyfunction!(evaluate_criticality, module)?)?;
    module.add_function(wrap_pyfunction!(evaluate_subjective_risk, module)?)?;
    Ok(())
}

#[cfg(test)]
mod criticality_boundary_hardening_tests {
    use super::*;

    #[test]
    fn criticality_boundary_converts_native_panic_to_structured_error() {
        let result = evaluate_criticality_with_panic_boundary(
            || -> Result<String, CriticalityBoundaryError> {
                panic!("simulated criticality panic");
            },
        );

        match result {
            Err(CriticalityBoundaryError::NativePanic) => {}
            other => panic!("expected NativePanic boundary error, got {other:?}"),
        }

        let payload: serde_json::Value =
            serde_json::from_str(&native_panic_error_json()).expect("valid panic error JSON");

        assert_eq!(payload["error_code"], "native-panic");
        assert!(payload["reason"]
            .as_str()
            .expect("reason should be a string")
            .contains("safely contained"));
    }

    #[test]
    fn criticality_boundary_preserves_invalid_payload_as_value_error_path() {
        let result =
            evaluate_criticality_with_panic_boundary(|| evaluate_criticality_json("{not-json}"));

        match result {
            Err(CriticalityBoundaryError::InvalidPayload(message)) => {
                assert!(!message.trim().is_empty());
            }
            other => panic!("expected InvalidPayload boundary error, got {other:?}"),
        }
    }
}
