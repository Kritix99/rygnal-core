package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Rygnal/rygnal-core/internal/engineclient"
	"github.com/spf13/cobra"
)

func sharedApprovalRunRecord() runReviewRecord {
	return runReviewRecord{
		RunID:    "run_shared",
		Baseline: "baseline123",
		Patch: engineclient.PatchInfo{
			Generated: true,
			SHA256:    "patch123",
		},
		Approval: engineclient.ApprovalInfo{
			Required:   true,
			ApprovalID: "apr_shared",
			Target:     "patch123",
		},
		ArtifactSchema: "rygnal.local_review.v1",
	}
}

func sharedApprovalResponse(
	status string,
	decidedBy string,
	reason string,
) map[string]any {
	decision := map[string]any{
		"status":     nil,
		"decided_by": nil,
		"decided_at": nil,
		"reason":     nil,
	}

	if status != "pending" {
		decision = map[string]any{
			"status":     status,
			"decided_by": decidedBy,
			"decided_at": "2026-07-22T16:00:00Z",
			"reason":     reason,
		}
	}

	return map[string]any{
		"approval": map[string]any{
			"approval_id": "apr_shared",
			"status":      status,
			"decision":    decision,
		},
		"artifact": map[string]any{
			"artifact_id":         "art_shared",
			"state":               "pending",
			"expired":             false,
			"patch_sha256":        "patch123",
			"baseline_commit_sha": "baseline123",
		},
	}
}

func TestSharedApprovalConfigRejectsRemotePlainHTTP(
	t *testing.T,
) {
	_, err := parseSharedApprovalConfig(
		"http://example.com",
		"operator-token",
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"loopback",
		) {
		t.Fatalf(
			"expected remote plain HTTP to fail, got %v",
			err,
		)
	}
}

func TestSharedApprovalConfigRequiresRemoteCredential(
	t *testing.T,
) {
	_, err := parseSharedApprovalConfig(
		"https://example.com",
		"",
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"credential",
		) {
		t.Fatalf(
			"expected remote credential requirement, got %v",
			err,
		)
	}
}

func TestSharedApprovalConfigAllowsLoopbackHTTP(
	t *testing.T,
) {
	config, err := parseSharedApprovalConfig(
		"http://127.0.0.1:8787",
		"",
	)

	if err != nil {
		t.Fatalf(
			"loopback HTTP configuration failed: %v",
			err,
		)
	}

	if config.baseURL.Host != "127.0.0.1:8787" {
		t.Fatalf(
			"unexpected host: %s",
			config.baseURL.Host,
		)
	}
}

func TestSharedApprovalSynchronizationBindsAndApproves(
	t *testing.T,
) {
	const (
		actor  = "reviewer@example.com"
		reason = "Reviewed and approved."
	)

	var mu sync.Mutex
	decisionCalls := 0

	server := httptest.NewServer(
		http.HandlerFunc(
			func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				if request.Header.Get(
					"Authorization",
				) != "Bearer operator-secret" {
					t.Errorf(
						"missing bearer credential",
					)
				}
				if request.Header.Get(
					"X-Rygnal-Operator-Token",
				) != "operator-secret" {
					t.Errorf(
						"missing operator credential header",
					)
				}

				status := "pending"

				switch request.Method {
				case http.MethodGet:
					if request.URL.Path !=
						"/v1/patch-approvals/apr_shared" {
						t.Errorf(
							"unexpected GET path: %s",
							request.URL.Path,
						)
					}
				case http.MethodPost:
					mu.Lock()
					decisionCalls++
					mu.Unlock()

					if request.URL.Path !=
						"/v1/patch-approvals/apr_shared/approve" {
						t.Errorf(
							"unexpected POST path: %s",
							request.URL.Path,
						)
					}

					var payload map[string]string

					if err := json.NewDecoder(
						request.Body,
					).Decode(&payload); err != nil {
						t.Errorf(
							"decode request: %v",
							err,
						)
					}

					if payload["decided_by"] != actor ||
						payload["reason"] != reason {
						t.Errorf(
							"unexpected decision payload: %#v",
							payload,
						)
					}

					status = localDecisionApproved
				default:
					t.Errorf(
						"unexpected method: %s",
						request.Method,
					)
				}

				writer.Header().Set(
					"Content-Type",
					"application/json",
				)
				_ = json.NewEncoder(
					writer,
				).Encode(
					sharedApprovalResponse(
						status,
						actor,
						reason,
					),
				)
			},
		),
	)
	defer server.Close()

	t.Setenv(
		sharedApprovalAPIURLEnv,
		server.URL,
	)
	t.Setenv(
		sharedApprovalTokenEnv,
		"operator-secret",
	)

	decision := localDecisionRecord{
		Schema:                localDecisionSchema,
		RunID:                 "run_shared",
		ApprovalID:            "apr_shared",
		Status:                localDecisionApproved,
		DecidedBy:             actor,
		Reason:                reason,
		PatchSHA256:           "patch123",
		BaselineCommitSHA:     "baseline123",
		EngineProtocolVersion: engineclient.ProtocolVersion,
		RygnalVersion:         Version,
	}

	result, err := synchronizeSharedApprovalDecision(
		context.Background(),
		sharedApprovalRunRecord(),
		decision,
	)

	if err != nil {
		t.Fatalf(
			"shared synchronization failed: %v",
			err,
		)
	}

	if result.authority !=
		localDecisionAuthoritySharedAPI ||
		!result.synchronized ||
		result.decidedAt == "" ||
		result.decidedBy != actor ||
		result.reason != reason {
		t.Fatalf(
			"unexpected synchronization result: %#v",
			result,
		)
	}

	mu.Lock()
	defer mu.Unlock()

	if decisionCalls != 1 {
		t.Fatalf(
			"expected one remote decision, got %d",
			decisionCalls,
		)
	}
}

func TestSharedApprovalSynchronizationRejectsAndBinds(
	t *testing.T,
) {
	const (
		actor  = "reviewer"
		reason = "Unsafe change."
	)

	server := httptest.NewServer(
		http.HandlerFunc(
			func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				status := "pending"

				if request.Method == http.MethodPost {
					if request.URL.Path !=
						"/v1/patch-approvals/apr_shared/reject" {
						t.Errorf(
							"unexpected reject path: %s",
							request.URL.Path,
						)
					}
					status = localDecisionRejected
				}

				writer.Header().Set(
					"Content-Type",
					"application/json",
				)
				_ = json.NewEncoder(
					writer,
				).Encode(
					sharedApprovalResponse(
						status,
						actor,
						reason,
					),
				)
			},
		),
	)
	defer server.Close()

	t.Setenv(
		sharedApprovalAPIURLEnv,
		server.URL,
	)
	t.Setenv(
		sharedApprovalTokenEnv,
		"",
	)

	decision := localDecisionRecord{
		Schema:                localDecisionSchema,
		RunID:                 "run_shared",
		ApprovalID:            "apr_shared",
		Status:                localDecisionRejected,
		DecidedBy:             actor,
		Reason:                reason,
		PatchSHA256:           "patch123",
		BaselineCommitSHA:     "baseline123",
		EngineProtocolVersion: engineclient.ProtocolVersion,
		RygnalVersion:         Version,
	}

	result, err := synchronizeSharedApprovalDecision(
		context.Background(),
		sharedApprovalRunRecord(),
		decision,
	)

	if err != nil {
		t.Fatalf(
			"shared rejection failed: %v",
			err,
		)
	}
	if !result.synchronized ||
		result.authority !=
			localDecisionAuthoritySharedAPI {
		t.Fatalf(
			"unexpected rejection result: %#v",
			result,
		)
	}
}

func TestSharedApprovalSynchronizationIsIdempotent(
	t *testing.T,
) {
	const (
		actor  = "reviewer"
		reason = "Reviewed."
	)

	postCalls := 0

	server := httptest.NewServer(
		http.HandlerFunc(
			func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				if request.Method == http.MethodPost {
					postCalls++
				}

				writer.Header().Set(
					"Content-Type",
					"application/json",
				)
				_ = json.NewEncoder(
					writer,
				).Encode(
					sharedApprovalResponse(
						localDecisionApproved,
						actor,
						reason,
					),
				)
			},
		),
	)
	defer server.Close()

	t.Setenv(
		sharedApprovalAPIURLEnv,
		server.URL,
	)
	t.Setenv(
		sharedApprovalTokenEnv,
		"",
	)

	decision := localDecisionRecord{
		ApprovalID: "apr_shared",
		Status:     localDecisionApproved,
		DecidedBy:  actor,
		Reason:     reason,
	}

	result, err := synchronizeSharedApprovalDecision(
		context.Background(),
		sharedApprovalRunRecord(),
		decision,
	)

	if err != nil {
		t.Fatalf(
			"idempotent synchronization failed: %v",
			err,
		)
	}
	if !result.synchronized {
		t.Fatal(
			"expected idempotent synchronization",
		)
	}
	if postCalls != 0 {
		t.Fatalf(
			"expected no duplicate POST, got %d",
			postCalls,
		)
	}
}

func TestSharedApprovalSynchronizationRejectsBindingMismatch(
	t *testing.T,
) {
	response := sharedApprovalResponse(
		"pending",
		"",
		"",
	)
	response["artifact"].(map[string]any)["patch_sha256"] = "different"

	server := httptest.NewServer(
		http.HandlerFunc(
			func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				writer.Header().Set(
					"Content-Type",
					"application/json",
				)
				_ = json.NewEncoder(
					writer,
				).Encode(response)
			},
		),
	)
	defer server.Close()

	t.Setenv(
		sharedApprovalAPIURLEnv,
		server.URL,
	)
	t.Setenv(
		sharedApprovalTokenEnv,
		"",
	)

	decision := localDecisionRecord{
		ApprovalID: "apr_shared",
		Status:     localDecisionRejected,
		DecidedBy:  "reviewer",
		Reason:     "Rejected.",
	}

	_, err := synchronizeSharedApprovalDecision(
		context.Background(),
		sharedApprovalRunRecord(),
		decision,
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"patch digest",
		) {
		t.Fatalf(
			"expected binding mismatch, got %v",
			err,
		)
	}
}

func writeSharedApprovalReview(
	t *testing.T,
	store localReviewStore,
	record runReviewRecord,
) string {
	t.Helper()

	if err := store.ensure(); err != nil {
		t.Fatal(err)
	}

	runDir := store.runDir(record.RunID)

	if err := os.MkdirAll(
		runDir,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	summary, err := json.MarshalIndent(
		record,
		"",
		"  ",
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(
			runDir,
			summaryFileName,
		),
		append(summary, '\n'),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	return runDir
}

func TestDecisionCommandPersistsSharedAuthorityReceipt(
	t *testing.T,
) {
	const (
		actor  = "reviewer"
		reason = "Reviewed."
	)

	record := sharedApprovalRunRecord()
	repoRoot := newTestGitRepo(t)
	store, err := newLocalReviewStore(repoRoot)

	if err != nil {
		t.Fatal(err)
	}

	runDir := writeSharedApprovalReview(
		t,
		store,
		record,
	)

	server := httptest.NewServer(
		http.HandlerFunc(
			func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				status := "pending"

				if request.Method == http.MethodPost {
					status = localDecisionApproved
				}

				writer.Header().Set(
					"Content-Type",
					"application/json",
				)
				_ = json.NewEncoder(
					writer,
				).Encode(
					sharedApprovalResponse(
						status,
						actor,
						reason,
					),
				)
			},
		),
	)
	defer server.Close()

	t.Setenv(
		sharedApprovalAPIURLEnv,
		server.URL,
	)
	t.Setenv(
		sharedApprovalTokenEnv,
		"",
	)

	command := &cobra.Command{}
	var output bytes.Buffer
	command.SetOut(&output)

	options := &decisionOptions{
		yes:       true,
		reason:    reason,
		decidedBy: actor,
		status:    localDecisionApproved,
	}

	if err := runDecisionCommandLocked(
		command,
		store,
		record.RunID,
		options,
	); err != nil {
		t.Fatalf(
			"decision command failed: %v",
			err,
		)
	}

	saved, err := readLocalDecisionRecord(
		filepath.Join(
			runDir,
			decisionRecordFileName,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	if saved.Schema != localDecisionSchema ||
		saved.ApprovalID !=
			record.Approval.ApprovalID ||
		saved.EngineProtocolVersion !=
			engineclient.ProtocolVersion ||
		saved.RygnalVersion != Version ||
		saved.Authority !=
			localDecisionAuthoritySharedAPI ||
		!saved.AuthoritySynchronized ||
		saved.ReceiptSHA256 == "" {
		t.Fatalf(
			"unexpected saved decision: %#v",
			saved,
		)
	}

	loaded := record
	loaded.Decision = &saved

	if err := validateDecisionRecordForRun(
		loaded,
	); err != nil {
		t.Fatalf(
			"saved decision did not validate: %v",
			err,
		)
	}
}

func TestDecisionCommandPersistsOfflineAuthorityReceipt(
	t *testing.T,
) {
	record := sharedApprovalRunRecord()
	repoRoot := newTestGitRepo(t)
	store, err := newLocalReviewStore(repoRoot)

	if err != nil {
		t.Fatal(err)
	}

	runDir := writeSharedApprovalReview(
		t,
		store,
		record,
	)

	t.Setenv(
		sharedApprovalAPIURLEnv,
		"",
	)
	t.Setenv(
		sharedApprovalTokenEnv,
		"",
	)

	command := &cobra.Command{}
	command.SetOut(&bytes.Buffer{})

	options := &decisionOptions{
		yes:       true,
		reason:    "Offline review.",
		decidedBy: "reviewer",
		status:    localDecisionApproved,
	}

	if err := runDecisionCommandLocked(
		command,
		store,
		record.RunID,
		options,
	); err != nil {
		t.Fatalf(
			"offline decision failed: %v",
			err,
		)
	}

	saved, err := readLocalDecisionRecord(
		filepath.Join(
			runDir,
			decisionRecordFileName,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	if saved.Authority !=
		localDecisionAuthorityLocal ||
		saved.AuthoritySynchronized ||
		saved.ReceiptSHA256 == "" {
		t.Fatalf(
			"unexpected offline decision: %#v",
			saved,
		)
	}

	loaded := record
	loaded.Decision = &saved

	if err := validateDecisionRecordForRun(
		loaded,
	); err != nil {
		t.Fatalf(
			"offline decision did not validate: %v",
			err,
		)
	}
}

func TestDecisionCommandDoesNotWriteLocalSuccessOnSharedFailure(
	t *testing.T,
) {
	record := sharedApprovalRunRecord()
	repoRoot := newTestGitRepo(t)
	store, err := newLocalReviewStore(repoRoot)

	if err != nil {
		t.Fatal(err)
	}

	runDir := writeSharedApprovalReview(
		t,
		store,
		record,
	)

	server := httptest.NewServer(
		http.HandlerFunc(
			func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				http.Error(
					writer,
					"unavailable",
					http.StatusServiceUnavailable,
				)
			},
		),
	)
	defer server.Close()

	t.Setenv(
		sharedApprovalAPIURLEnv,
		server.URL,
	)
	t.Setenv(
		sharedApprovalTokenEnv,
		"",
	)

	command := &cobra.Command{}
	options := &decisionOptions{
		yes:       true,
		reason:    "Reviewed.",
		decidedBy: "reviewer",
		status:    localDecisionApproved,
	}

	err = runDecisionCommandLocked(
		command,
		store,
		record.RunID,
		options,
	)

	if err == nil {
		t.Fatal(
			"expected shared authority failure",
		)
	}

	decisionPath := filepath.Join(
		runDir,
		decisionRecordFileName,
	)

	if _, statErr := os.Stat(
		decisionPath,
	); !os.IsNotExist(statErr) {
		t.Fatalf(
			"local success record must not exist after shared failure: %v",
			statErr,
		)
	}
}

func TestDecisionReceiptDetectsTampering(
	t *testing.T,
) {
	record := sharedApprovalRunRecord()
	decision := localDecisionRecord{
		Schema:                localDecisionSchema,
		RunID:                 record.RunID,
		ApprovalID:            record.Approval.ApprovalID,
		Status:                localDecisionApproved,
		DecidedAt:             "2026-07-22T16:00:00Z",
		DecidedBy:             "reviewer",
		Reason:                "Reviewed.",
		PatchSHA256:           record.Patch.SHA256,
		BaselineCommitSHA:     record.Baseline,
		EngineProtocolVersion: engineclient.ProtocolVersion,
		RygnalVersion:         Version,
		Authority:             localDecisionAuthorityLocal,
		AuthoritySynchronized: false,
	}

	receipt, err := calculateLocalDecisionReceipt(
		decision,
	)
	if err != nil {
		t.Fatal(err)
	}

	decision.ReceiptSHA256 = receipt
	record.Decision = &decision

	if err := validateDecisionRecordForRun(
		record,
	); err != nil {
		t.Fatalf(
			"untampered decision failed: %v",
			err,
		)
	}

	record.Decision.Reason = "Modified."

	err = validateDecisionRecordForRun(record)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"receipt digest",
		) {
		t.Fatalf(
			"expected tampering failure, got %v",
			err,
		)
	}
}

func TestDecisionCommandRejectsMissingApprovalIdentity(
	t *testing.T,
) {
	record := sharedApprovalRunRecord()
	record.Approval.ApprovalID = ""

	repoRoot := newTestGitRepo(t)
	store, err := newLocalReviewStore(repoRoot)

	if err != nil {
		t.Fatal(err)
	}

	runDir := writeSharedApprovalReview(
		t,
		store,
		record,
	)

	t.Setenv(
		sharedApprovalAPIURLEnv,
		"",
	)

	command := &cobra.Command{}
	options := &decisionOptions{
		yes:       true,
		reason:    "Reviewed.",
		decidedBy: "reviewer",
		status:    localDecisionApproved,
	}

	err = runDecisionCommandLocked(
		command,
		store,
		record.RunID,
		options,
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"approval identity",
		) {
		t.Fatalf(
			"expected missing approval identity failure, got %v",
			err,
		)
	}

	if _, statErr := os.Stat(
		filepath.Join(
			runDir,
			decisionRecordFileName,
		),
	); !os.IsNotExist(statErr) {
		t.Fatalf(
			"invalid decision must not be persisted: %v",
			statErr,
		)
	}
}
