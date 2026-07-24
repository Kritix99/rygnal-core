package cli

import (
	"strings"
	"testing"

	"github.com/Rygnal/rygnal-core/internal/engineclient"
)

func testDecisionRunRecord(status string, approvalRequired bool) runReviewRecord {
	return runReviewRecord{
		RunID:    "run_test",
		Baseline: "abc123",
		Patch: engineclient.PatchInfo{
			SHA256: "patch123",
		},
		Approval: engineclient.ApprovalInfo{
			Required: approvalRequired,
		},
		Decision: &localDecisionRecord{
			Schema:            localDecisionSchemaV1,
			RunID:             "run_test",
			Status:            status,
			PatchSHA256:       "patch123",
			BaselineCommitSHA: "abc123",
			Reason:            "test reason",
		},
	}
}

func TestDecisionApplyRejectsRejectedRun(t *testing.T) {
	record := testDecisionRunRecord(localDecisionRejected, false)

	err := assertDecisionAllowsApply(record)
	if err == nil {
		t.Fatal("expected rejected run to be refused")
	}

	if !strings.Contains(err.Error(), "was rejected") {
		t.Fatalf("expected rejected error, got %v", err)
	}
}

func TestDecisionApplyRequiresApprovalForApprovalRequiredRun(t *testing.T) {
	record := runReviewRecord{
		RunID:    "run_test",
		Baseline: "abc123",
		Patch: engineclient.PatchInfo{
			SHA256: "patch123",
		},
		Approval: engineclient.ApprovalInfo{
			Required: true,
		},
	}

	err := assertDecisionAllowsApply(record)
	if err == nil {
		t.Fatal("expected approval-required run without decision to be refused")
	}

	if !strings.Contains(err.Error(), "requires approval before apply") {
		t.Fatalf("expected approval-required error, got %v", err)
	}
}

func TestDecisionApplyAllowsValidApprovedApprovalRequiredRun(t *testing.T) {
	record := testDecisionRunRecord(localDecisionApproved, true)

	if err := assertDecisionAllowsApply(record); err != nil {
		t.Fatalf("expected approved approval-required run to apply, got %v", err)
	}
}

func TestDecisionApplyRejectsCorruptDecisionRecord(t *testing.T) {
	record := runReviewRecord{
		RunID:                 "run_test",
		Baseline:              "abc123",
		DecisionInvalidReason: "decode decision record: invalid json",
		Patch: engineclient.PatchInfo{
			SHA256: "patch123",
		},
	}

	err := assertDecisionAllowsApply(record)
	if err == nil {
		t.Fatal("expected corrupt decision record to be refused")
	}

	if !strings.Contains(err.Error(), "invalid or corrupt") {
		t.Fatalf("expected corrupt decision error, got %v", err)
	}
}
