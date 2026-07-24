package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Rygnal/rygnal-core/internal/engineclient"
	"github.com/spf13/cobra"
)

const (
	decisionRecordFileName          = "decision.json"
	localDecisionSchemaV1           = "rygnal.local_decision.v1"
	localDecisionSchema             = "rygnal.local_decision.v2"
	localDecisionEventSchema        = "rygnal.local_decision_event.v2"
	localDecisionAuthorityLocal     = "local"
	localDecisionAuthoritySharedAPI = "shared_api"

	localDecisionApproved = "approved"
	localDecisionRejected = "rejected"
)

type localDecisionRecord struct {
	Schema                string `json:"schema"`
	RunID                 string `json:"run_id"`
	ApprovalID            string `json:"approval_id,omitempty"`
	Status                string `json:"status"`
	DecidedAt             string `json:"decided_at"`
	DecidedBy             string `json:"decided_by"`
	Reason                string `json:"reason,omitempty"`
	PatchSHA256           string `json:"patch_sha256,omitempty"`
	BaselineCommitSHA     string `json:"baseline_commit_sha,omitempty"`
	EngineProtocolVersion string `json:"engine_protocol_version,omitempty"`
	RygnalVersion         string `json:"rygnal_version,omitempty"`
	Authority             string `json:"authority,omitempty"`
	AuthoritySynchronized bool   `json:"authority_synchronized"`
	ReceiptSHA256         string `json:"receipt_sha256,omitempty"`
}

type localDecisionAuditEvent struct {
	Schema                string `json:"schema"`
	Event                 string `json:"event"`
	RunID                 string `json:"run_id"`
	ApprovalID            string `json:"approval_id,omitempty"`
	Status                string `json:"status"`
	DecidedAt             string `json:"decided_at"`
	DecidedBy             string `json:"decided_by"`
	Reason                string `json:"reason,omitempty"`
	PatchSHA256           string `json:"patch_sha256,omitempty"`
	BaselineCommitSHA     string `json:"baseline_commit_sha,omitempty"`
	EngineProtocolVersion string `json:"engine_protocol_version,omitempty"`
	RygnalVersion         string `json:"rygnal_version,omitempty"`
	Authority             string `json:"authority,omitempty"`
	AuthoritySynchronized bool   `json:"authority_synchronized"`
	ReceiptSHA256         string `json:"receipt_sha256,omitempty"`
}

type decisionOptions struct {
	yes       bool
	reason    string
	decidedBy string
	status    string
}

func newApproveCmd() *cobra.Command {
	opts := &decisionOptions{
		status: localDecisionApproved,
		reason: "Approved for local apply.",
	}

	cmd := &cobra.Command{
		Use:   "approve [run_id]",
		Short: "Approve a reviewed local patch for rygnal apply",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecisionCommand(cmd, args[0], opts)
		},
	}

	cmd.Flags().BoolVar(&opts.yes, "yes", false, "Confirm approval decision")
	cmd.Flags().StringVar(&opts.reason, "reason", opts.reason, "Approval reason")
	cmd.Flags().StringVar(&opts.decidedBy, "decided-by", "", "Decision actor; defaults to git identity or OS user")

	return cmd
}

func newRejectCmd() *cobra.Command {
	opts := &decisionOptions{
		status: localDecisionRejected,
	}

	cmd := &cobra.Command{
		Use:   "reject [run_id]",
		Short: "Reject a reviewed local patch and prevent rygnal apply",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecisionCommand(cmd, args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.reason, "reason", "", "Rejection reason")
	cmd.Flags().StringVar(&opts.decidedBy, "decided-by", "", "Decision actor; defaults to git identity or OS user")

	return cmd
}

func runDecisionCommand(cmd *cobra.Command, runID string, opts *decisionOptions) error {
	store, err := localReviewStoreFromCurrentRepo()
	if err != nil {
		return err
	}

	return withLocalReviewLock(store, func() error {
		return runDecisionCommandLocked(cmd, store, runID, opts)
	})
}

func runDecisionCommandLocked(cmd *cobra.Command, store localReviewStore, runID string, opts *decisionOptions) error {
	opts.reason = strings.TrimSpace(opts.reason)
	opts.decidedBy = strings.TrimSpace(opts.decidedBy)
	if opts.decidedBy == "" {
		opts.decidedBy = defaultDecisionActor(store)
	}

	if opts.status == localDecisionApproved && !opts.yes {
		return fmt.Errorf("refusing to approve without explicit --yes confirmation")
	}

	if opts.status == localDecisionRejected && opts.reason == "" {
		return fmt.Errorf("reject requires --reason")
	}

	record, err := findRunReviewRecord(store, runID)
	if err != nil {
		return err
	}

	if record.Apply != nil {
		return fmt.Errorf("run %s was already applied; refusing to change approval decision", record.RunID)
	}

	if record.DecisionInvalidReason != "" {
		return fmt.Errorf("run %s has invalid decision state: %s", record.RunID, record.DecisionInvalidReason)
	}

	if record.Decision != nil {
		return fmt.Errorf("run %s already has a decision: %s", record.RunID, decisionStatus(record))
	}

	if err := validateReviewBindingForDecision(record); err != nil {
		return err
	}

	decision := localDecisionRecord{
		Schema:                localDecisionSchema,
		RunID:                 record.RunID,
		ApprovalID:            record.Approval.ApprovalID,
		Status:                opts.status,
		DecidedAt:             time.Now().UTC().Format(time.RFC3339Nano),
		DecidedBy:             opts.decidedBy,
		Reason:                opts.reason,
		PatchSHA256:           record.Patch.SHA256,
		BaselineCommitSHA:     record.Baseline,
		EngineProtocolVersion: engineclient.ProtocolVersion,
		RygnalVersion:         Version,
	}

	synchronization, err := synchronizeSharedApprovalDecision(
		cmd.Context(),
		record,
		decision,
	)
	if err != nil {
		return err
	}

	decision.Authority = synchronization.authority
	decision.AuthoritySynchronized = synchronization.synchronized

	if synchronization.decidedAt != "" {
		decision.DecidedAt = synchronization.decidedAt
	}
	if synchronization.decidedBy != "" {
		decision.DecidedBy = synchronization.decidedBy
	}
	if synchronization.reason != "" {
		decision.Reason = synchronization.reason
	}

	decision.ReceiptSHA256, err = calculateLocalDecisionReceipt(decision)
	if err != nil {
		return err
	}

	decisionPath := store.runDir(record.RunID) + "/" + decisionRecordFileName
	if err := writeLocalDecisionRecord(decisionPath, decision); err != nil {
		return err
	}

	if err := appendLocalDecisionAuditEvent(store, decision); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Rygnal decision: %s\n", record.RunID)
	fmt.Fprintf(out, "Status: %s\n", decision.Status)
	fmt.Fprintf(out, "Patch digest: sha256:%s\n", shortValue(decision.PatchSHA256, 12))
	if decision.BaselineCommitSHA != "" {
		fmt.Fprintf(out, "Baseline: %s\n", shortValue(decision.BaselineCommitSHA, 12))
	}
	if decision.DecidedBy != "" {
		fmt.Fprintf(out, "Decided by: %s\n", decision.DecidedBy)
	}
	if decision.Reason != "" {
		fmt.Fprintf(out, "Reason: %s\n", decision.Reason)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	if decision.Status == localDecisionApproved {
		fmt.Fprintf(out, "  rygnal apply %s --yes\n", record.RunID)
	} else {
		fmt.Fprintf(out, "  rygnal audit show %s\n", record.RunID)
	}

	return nil
}

func writeLocalDecisionRecord(path string, decision localDecisionRecord) error {
	payload, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		return fmt.Errorf("encode decision record: %w", err)
	}

	file, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if os.IsExist(err) {
		return fmt.Errorf("decision record already exists")
	}
	if err != nil {
		return fmt.Errorf("create decision record: %w", err)
	}

	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()

	if _, err := file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write decision record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync decision record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close decision record: %w", err)
	}

	closed = true
	return nil
}

func readLocalDecisionRecord(path string) (localDecisionRecord, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return localDecisionRecord{}, err
	}

	var decision localDecisionRecord
	if err := json.Unmarshal(payload, &decision); err != nil {
		return localDecisionRecord{}, fmt.Errorf("decode decision record %s: %w", path, err)
	}

	return decision, nil
}

func appendLocalDecisionAuditEvent(store localReviewStore, decision localDecisionRecord) error {
	event := localDecisionAuditEvent{
		Schema:                localDecisionEventSchema,
		Event:                 "local_decision." + decision.Status,
		RunID:                 decision.RunID,
		ApprovalID:            decision.ApprovalID,
		Status:                decision.Status,
		DecidedAt:             decision.DecidedAt,
		DecidedBy:             decision.DecidedBy,
		Reason:                decision.Reason,
		PatchSHA256:           decision.PatchSHA256,
		BaselineCommitSHA:     decision.BaselineCommitSHA,
		EngineProtocolVersion: decision.EngineProtocolVersion,
		RygnalVersion:         decision.RygnalVersion,
		Authority:             decision.Authority,
		AuthoritySynchronized: decision.AuthoritySynchronized,
		ReceiptSHA256:         decision.ReceiptSHA256,
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode decision audit event: %w", err)
	}

	file, err := os.OpenFile(
		store.auditPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open decision audit log: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("append decision audit event: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync decision audit event: %w", err)
	}

	return nil
}

func defaultDecisionActor(store localReviewStore) string {
	email, emailErr := gitOutput(store.trustedRepo, "config", "--get", "user.email")
	name, nameErr := gitOutput(store.trustedRepo, "config", "--get", "user.name")

	email = strings.TrimSpace(email)
	name = strings.TrimSpace(name)

	if emailErr == nil && email != "" {
		if nameErr == nil && name != "" {
			return name + " <" + email + ">"
		}
		return email
	}

	if nameErr == nil && name != "" {
		return name
	}

	for _, key := range []string{"USER", "USERNAME", "LOGNAME"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}

	return "unknown-local-user"
}

type localDecisionReceiptPayload struct {
	Schema                string `json:"schema"`
	RunID                 string `json:"run_id"`
	ApprovalID            string `json:"approval_id"`
	Status                string `json:"status"`
	DecidedAt             string `json:"decided_at"`
	DecidedBy             string `json:"decided_by"`
	Reason                string `json:"reason"`
	PatchSHA256           string `json:"patch_sha256"`
	BaselineCommitSHA     string `json:"baseline_commit_sha"`
	EngineProtocolVersion string `json:"engine_protocol_version"`
	RygnalVersion         string `json:"rygnal_version"`
	Authority             string `json:"authority"`
	AuthoritySynchronized bool   `json:"authority_synchronized"`
}

func validateReviewBindingForDecision(record runReviewRecord) error {
	if record.Patch.SHA256 == "" {
		return fmt.Errorf(
			"run %s has no patch digest to bind a decision to",
			record.RunID,
		)
	}

	if record.Baseline == "" {
		return fmt.Errorf(
			"run %s has no baseline commit to bind a decision to",
			record.RunID,
		)
	}

	if !record.Approval.Required {
		return nil
	}

	if record.Approval.ApprovalID == "" {
		return fmt.Errorf(
			"run %s is missing the Python approval identity",
			record.RunID,
		)
	}

	if record.Approval.Target == "" {
		return fmt.Errorf(
			"run %s is missing the approval target digest",
			record.RunID,
		)
	}

	if record.Approval.Target != record.Patch.SHA256 {
		return fmt.Errorf(
			"approval target does not match review patch digest for run %s",
			record.RunID,
		)
	}

	return nil
}

func calculateLocalDecisionReceipt(
	decision localDecisionRecord,
) (string, error) {
	payload := localDecisionReceiptPayload{
		Schema:                decision.Schema,
		RunID:                 decision.RunID,
		ApprovalID:            decision.ApprovalID,
		Status:                decision.Status,
		DecidedAt:             decision.DecidedAt,
		DecidedBy:             decision.DecidedBy,
		Reason:                decision.Reason,
		PatchSHA256:           decision.PatchSHA256,
		BaselineCommitSHA:     decision.BaselineCommitSHA,
		EngineProtocolVersion: decision.EngineProtocolVersion,
		RygnalVersion:         decision.RygnalVersion,
		Authority:             decision.Authority,
		AuthoritySynchronized: decision.AuthoritySynchronized,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf(
			"encode local decision receipt: %w",
			err,
		)
	}

	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func isSupportedLocalDecisionSchema(schema string) bool {
	return schema == localDecisionSchema ||
		schema == localDecisionSchemaV1
}

func decisionStatus(record runReviewRecord) string {
	if record.DecisionInvalidReason != "" {
		return "invalid"
	}

	if record.Decision == nil {
		return "undecided"
	}

	if err := validateDecisionRecordForRun(record); err != nil {
		return "invalid"
	}

	return record.Decision.Status
}

func renderDecision(out interface{ Write([]byte) (int, error) }, record runReviewRecord) {
	if record.DecisionInvalidReason != "" {
		fmt.Fprintln(out, "Decision: invalid")
		fmt.Fprintln(out, "Decision state: INVALID/CORRUPT")
		fmt.Fprintf(out, "Decision error: %s\n", record.DecisionInvalidReason)
		return
	}

	if record.Decision == nil {
		fmt.Fprintln(out, "Decision: undecided")
		return
	}

	if decisionStatus(record) == "invalid" {
		fmt.Fprintln(out, "Decision: invalid")
		fmt.Fprintln(out, "Decision state: INVALID/CORRUPT")
		fmt.Fprintf(out, "Decision status: %s\n", valueOrDash(record.Decision.Status))
		if record.Decision.Schema != "" {
			fmt.Fprintf(out, "Decision schema: %s\n", record.Decision.Schema)
		}
		if record.Decision.RunID != "" {
			fmt.Fprintf(out, "Decision run ID: %s\n", record.Decision.RunID)
		}
		return
	}

	fmt.Fprintf(out, "Decision: %s\n", record.Decision.Status)
	if record.Decision.DecidedAt != "" {
		fmt.Fprintf(out, "Decided at: %s\n", record.Decision.DecidedAt)
	}
	if record.Decision.DecidedBy != "" {
		fmt.Fprintf(out, "Decided by: %s\n", record.Decision.DecidedBy)
	}
	if record.Decision.PatchSHA256 != "" {
		fmt.Fprintf(out, "Decision patch digest: sha256:%s\n", shortValue(record.Decision.PatchSHA256, 12))
	}
	if record.Decision.Reason != "" {
		fmt.Fprintf(out, "Decision reason: %s\n", record.Decision.Reason)
	}
}

func validateDecisionRecordForRun(record runReviewRecord) error {
	if record.DecisionInvalidReason != "" {
		return fmt.Errorf(
			"decision record for run %s is invalid or corrupt: %s",
			record.RunID,
			record.DecisionInvalidReason,
		)
	}

	if record.Decision == nil {
		return nil
	}

	decision := record.Decision

	if !isSupportedLocalDecisionSchema(decision.Schema) {
		return fmt.Errorf(
			"decision record for run %s has unsupported schema %q",
			record.RunID,
			decision.Schema,
		)
	}

	if decision.RunID != record.RunID {
		return fmt.Errorf(
			"decision record run_id %q does not match requested run %s",
			decision.RunID,
			record.RunID,
		)
	}

	switch decision.Status {
	case localDecisionApproved, localDecisionRejected:
	default:
		return fmt.Errorf(
			"decision record for run %s has unsupported status %q",
			record.RunID,
			decision.Status,
		)
	}

	if decision.PatchSHA256 == "" {
		return fmt.Errorf(
			"decision record for run %s is missing patch digest",
			record.RunID,
		)
	}

	if record.Patch.SHA256 != "" &&
		decision.PatchSHA256 != record.Patch.SHA256 {
		return fmt.Errorf(
			"decision patch digest does not match review patch digest for run %s",
			record.RunID,
		)
	}

	if decision.BaselineCommitSHA == "" {
		return fmt.Errorf(
			"decision record for run %s is missing baseline commit",
			record.RunID,
		)
	}

	if record.Baseline != "" &&
		decision.BaselineCommitSHA != record.Baseline {
		return fmt.Errorf(
			"decision baseline does not match review baseline for run %s",
			record.RunID,
		)
	}

	if decision.Schema == localDecisionSchemaV1 {
		return nil
	}

	if decision.EngineProtocolVersion != engineclient.ProtocolVersion {
		return fmt.Errorf(
			"decision record for run %s has unsupported engine protocol %q",
			record.RunID,
			decision.EngineProtocolVersion,
		)
	}

	if decision.RygnalVersion == "" {
		return fmt.Errorf(
			"decision record for run %s is missing Rygnal version",
			record.RunID,
		)
	}

	if record.Approval.Required {
		if decision.ApprovalID == "" {
			return fmt.Errorf(
				"decision record for run %s is missing approval identity",
				record.RunID,
			)
		}

		if decision.ApprovalID != record.Approval.ApprovalID {
			return fmt.Errorf(
				"decision approval identity does not match review approval for run %s",
				record.RunID,
			)
		}
	}

	switch decision.Authority {
	case localDecisionAuthorityLocal:
		if decision.AuthoritySynchronized {
			return fmt.Errorf(
				"local decision for run %s cannot claim shared synchronization",
				record.RunID,
			)
		}
	case localDecisionAuthoritySharedAPI:
		if !record.Approval.Required {
			return fmt.Errorf(
				"shared decision for run %s has no approval requirement",
				record.RunID,
			)
		}
		if !decision.AuthoritySynchronized {
			return fmt.Errorf(
				"shared decision for run %s is not synchronized",
				record.RunID,
			)
		}
	default:
		return fmt.Errorf(
			"decision record for run %s has unsupported authority %q",
			record.RunID,
			decision.Authority,
		)
	}

	if decision.ReceiptSHA256 == "" {
		return fmt.Errorf(
			"decision record for run %s is missing receipt digest",
			record.RunID,
		)
	}

	expectedReceipt, err := calculateLocalDecisionReceipt(*decision)
	if err != nil {
		return err
	}

	if decision.ReceiptSHA256 != expectedReceipt {
		return fmt.Errorf(
			"decision receipt digest does not match record contents for run %s",
			record.RunID,
		)
	}

	return nil
}

func assertDecisionAllowsApply(record runReviewRecord) error {
	if err := validateDecisionRecordForRun(record); err != nil {
		return err
	}

	if record.Decision != nil &&
		record.Decision.Status == localDecisionRejected {
		return fmt.Errorf(
			"run %s was rejected: %s",
			record.RunID,
			valueOrDash(record.Decision.Reason),
		)
	}

	if record.Approval.Required {
		if record.Decision == nil {
			return fmt.Errorf(
				"run %s requires approval before apply; run `rygnal approve %s --yes` or `rygnal reject %s --reason ...`",
				record.RunID,
				record.RunID,
				record.RunID,
			)
		}

		if record.Decision.Status != localDecisionApproved {
			return fmt.Errorf(
				"run %s requires an approved decision before apply; current decision: %s",
				record.RunID,
				record.Decision.Status,
			)
		}
	}

	return nil
}
