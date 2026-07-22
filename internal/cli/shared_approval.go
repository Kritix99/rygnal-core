package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	sharedApprovalAPIURLEnv      = "RYGNAL_APPROVAL_API_URL"
	sharedApprovalTokenEnv       = "RYGNAL_OPERATOR_TOKEN"
	sharedApprovalRequestTimeout = 10 * time.Second
	sharedApprovalDialTimeout    = 5 * time.Second
	sharedApprovalMaxBodyBytes   = 256 * 1024
	sharedApprovalMaxTokenBytes  = 8 * 1024
)

var sharedApprovalIDPattern = regexp.MustCompile(
	`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
)

type sharedApprovalConfig struct {
	baseURL *url.URL
	token   string
	timeout time.Duration
}

type sharedApprovalSyncResult struct {
	authority    string
	synchronized bool
	decidedAt    string
	decidedBy    string
	reason       string
}

type sharedApprovalView struct {
	Approval struct {
		ApprovalID string `json:"approval_id"`
		Status     string `json:"status"`
		Decision   struct {
			Status    string `json:"status"`
			DecidedBy string `json:"decided_by"`
			DecidedAt string `json:"decided_at"`
			Reason    string `json:"reason"`
		} `json:"decision"`
	} `json:"approval"`
	Artifact struct {
		ArtifactID        string `json:"artifact_id"`
		State             string `json:"state"`
		Expired           bool   `json:"expired"`
		PatchSHA256       string `json:"patch_sha256"`
		BaselineCommitSHA string `json:"baseline_commit_sha"`
	} `json:"artifact"`
}

type sharedApprovalClient struct {
	config sharedApprovalConfig
	http   *http.Client
}

func sharedApprovalConfigFromEnvironment() (*sharedApprovalConfig, error) {
	rawURL := strings.TrimSpace(
		os.Getenv(sharedApprovalAPIURLEnv),
	)
	if rawURL == "" {
		return nil, nil
	}

	token := strings.TrimSpace(
		os.Getenv(sharedApprovalTokenEnv),
	)

	return parseSharedApprovalConfig(
		rawURL,
		token,
	)
}

func parseSharedApprovalConfig(
	rawURL string,
	token string,
) (*sharedApprovalConfig, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf(
			"shared approval API URL is empty",
		)
	}
	if len(rawURL) > 2048 {
		return nil, fmt.Errorf(
			"shared approval API URL exceeds its size limit",
		)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf(
			"shared approval API URL is invalid",
		)
	}

	if parsed.Scheme != "http" &&
		parsed.Scheme != "https" {
		return nil, fmt.Errorf(
			"shared approval API URL must use HTTP or HTTPS",
		)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf(
			"shared approval API URL requires a host",
		)
	}
	if parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.Opaque != "" ||
		parsed.RawPath != "" {
		return nil, fmt.Errorf(
			"shared approval API URL contains unsupported components",
		)
	}
	if hasParentPathSegment(parsed.Path) {
		return nil, fmt.Errorf(
			"shared approval API URL contains an unsafe path",
		)
	}

	loopback := isLoopbackApprovalHost(
		parsed.Hostname(),
	)
	if parsed.Scheme == "http" && !loopback {
		return nil, fmt.Errorf(
			"unencrypted shared approval API access is allowed only on loopback",
		)
	}

	token = strings.TrimSpace(token)
	if len(token) > sharedApprovalMaxTokenBytes {
		return nil, fmt.Errorf(
			"operator credential exceeds its size limit",
		)
	}
	if !loopback && token == "" {
		return nil, fmt.Errorf(
			"remote shared approval API access requires an operator credential",
		)
	}

	parsed.Path = strings.TrimRight(
		parsed.Path,
		"/",
	)

	return &sharedApprovalConfig{
		baseURL: parsed,
		token:   token,
		timeout: sharedApprovalRequestTimeout,
	}, nil
}

func newSharedApprovalClient(
	config sharedApprovalConfig,
) *sharedApprovalClient {
	dialer := &net.Dialer{
		Timeout:   sharedApprovalDialTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   sharedApprovalDialTimeout,
		ResponseHeaderTimeout: config.timeout,
		IdleConnTimeout:       30 * time.Second,
	}

	return &sharedApprovalClient{
		config: config,
		http: &http.Client{
			Transport: transport,
			Timeout:   config.timeout,
			CheckRedirect: func(
				_ *http.Request,
				_ []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func synchronizeSharedApprovalDecision(
	ctx context.Context,
	record runReviewRecord,
	decision localDecisionRecord,
) (sharedApprovalSyncResult, error) {
	config, err := sharedApprovalConfigFromEnvironment()
	if err != nil {
		return sharedApprovalSyncResult{}, err
	}

	if config == nil {
		return sharedApprovalSyncResult{
			authority:    localDecisionAuthorityLocal,
			synchronized: false,
		}, nil
	}

	if !record.Approval.Required {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"shared approval authority is configured, but run %s has no approval requirement",
			record.RunID,
		)
	}
	if decision.ApprovalID == "" {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"run %s is missing the Python approval identity",
			record.RunID,
		)
	}
	if !sharedApprovalIDPattern.MatchString(
		decision.ApprovalID,
	) {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"shared approval identity is invalid",
		)
	}
	if record.Approval.Target !=
		record.Patch.SHA256 {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"approval target does not match review patch digest for run %s",
			record.RunID,
		)
	}

	client := newSharedApprovalClient(*config)
	defer client.http.CloseIdleConnections()

	current, err := client.inspect(
		ctx,
		decision.ApprovalID,
	)
	if err != nil {
		return sharedApprovalSyncResult{}, err
	}
	if err := validateSharedApprovalBinding(
		current,
		record,
	); err != nil {
		return sharedApprovalSyncResult{}, err
	}

	desiredStatus := decision.Status

	switch current.Approval.Status {
	case desiredStatus:
		return canonicalSharedDecision(
			current,
			decision,
		)
	case "pending":
	default:
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"shared approval %s is already %s",
			decision.ApprovalID,
			current.Approval.Status,
		)
	}

	if desiredStatus == localDecisionApproved &&
		current.Artifact.Expired {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"shared approval artifact is expired",
		)
	}

	updated, err := client.decide(
		ctx,
		decision.ApprovalID,
		desiredStatus,
		decision.DecidedBy,
		decision.Reason,
	)
	if err != nil {
		return sharedApprovalSyncResult{}, err
	}
	if err := validateSharedApprovalBinding(
		updated,
		record,
	); err != nil {
		return sharedApprovalSyncResult{}, err
	}
	if updated.Approval.Status != desiredStatus {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"shared approval API returned an unexpected decision state",
		)
	}

	return canonicalSharedDecision(
		updated,
		decision,
	)
}

func canonicalSharedDecision(
	view sharedApprovalView,
	requested localDecisionRecord,
) (sharedApprovalSyncResult, error) {
	remote := view.Approval.Decision

	if remote.Status != requested.Status {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"shared approval decision details are inconsistent",
		)
	}
	if remote.DecidedBy == "" ||
		remote.DecidedAt == "" ||
		remote.Reason == "" {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"shared approval decision details are incomplete",
		)
	}
	if remote.DecidedBy != requested.DecidedBy ||
		remote.Reason != requested.Reason {
		return sharedApprovalSyncResult{}, fmt.Errorf(
			"shared approval already has different decision details",
		)
	}

	return sharedApprovalSyncResult{
		authority:    localDecisionAuthoritySharedAPI,
		synchronized: true,
		decidedAt:    remote.DecidedAt,
		decidedBy:    remote.DecidedBy,
		reason:       remote.Reason,
	}, nil
}

func (client *sharedApprovalClient) inspect(
	ctx context.Context,
	approvalID string,
) (sharedApprovalView, error) {
	var view sharedApprovalView

	err := client.requestJSON(
		ctx,
		http.MethodGet,
		client.endpoint(approvalID, ""),
		nil,
		&view,
	)

	return view, err
}

func (client *sharedApprovalClient) decide(
	ctx context.Context,
	approvalID string,
	status string,
	decidedBy string,
	reason string,
) (sharedApprovalView, error) {
	if status != localDecisionApproved &&
		status != localDecisionRejected {
		return sharedApprovalView{}, fmt.Errorf(
			"unsupported shared approval decision",
		)
	}

	payload := map[string]string{
		"decided_by": decidedBy,
		"reason":     reason,
	}

	var view sharedApprovalView

	err := client.requestJSON(
		ctx,
		http.MethodPost,
		client.endpoint(
			approvalID,
			statusVerb(status),
		),
		payload,
		&view,
	)

	return view, err
}

func (client *sharedApprovalClient) endpoint(
	approvalID string,
	action string,
) string {
	if !sharedApprovalIDPattern.MatchString(
		approvalID,
	) {
		return ""
	}

	cloned := *client.config.baseURL
	cloned.Path = strings.TrimRight(
		cloned.Path,
		"/",
	) + "/v1/patch-approvals/" +
		url.PathEscape(approvalID)

	if action != "" {
		cloned.Path += "/" + action
	}

	return cloned.String()
}

func (client *sharedApprovalClient) requestJSON(
	ctx context.Context,
	method string,
	endpoint string,
	payload any,
	output any,
) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if endpoint == "" {
		return fmt.Errorf(
			"shared approval identity is invalid",
		)
	}

	var body io.Reader

	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf(
				"encode shared approval request: %w",
				err,
			)
		}

		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		method,
		endpoint,
		body,
	)
	if err != nil {
		return fmt.Errorf(
			"create shared approval request: %w",
			err,
		)
	}

	request.Header.Set(
		"Accept",
		"application/json",
	)
	if payload != nil {
		request.Header.Set(
			"Content-Type",
			"application/json",
		)
	}
	if client.config.token != "" {
		request.Header.Set(
			"Authorization",
			"Bearer "+client.config.token,
		)
		request.Header.Set(
			"X-Rygnal-Operator-Token",
			client.config.token,
		)
	}

	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf(
			"shared approval API request failed",
		)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 ||
		response.StatusCode >= 300 {
		return sharedApprovalHTTPError(
			response.StatusCode,
		)
	}

	limited := io.LimitReader(
		response.Body,
		sharedApprovalMaxBodyBytes+1,
	)
	responsePayload, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf(
			"read shared approval API response: %w",
			err,
		)
	}
	if len(responsePayload) >
		sharedApprovalMaxBodyBytes {
		return fmt.Errorf(
			"shared approval API response exceeds its size limit",
		)
	}
	if err := json.Unmarshal(
		responsePayload,
		output,
	); err != nil {
		return fmt.Errorf(
			"shared approval API returned invalid JSON",
		)
	}

	return nil
}

func validateSharedApprovalBinding(
	view sharedApprovalView,
	record runReviewRecord,
) error {
	if view.Approval.ApprovalID !=
		record.Approval.ApprovalID {
		return fmt.Errorf(
			"shared approval identity does not match the local review record",
		)
	}
	if view.Artifact.PatchSHA256 !=
		record.Patch.SHA256 {
		return fmt.Errorf(
			"shared approval patch digest does not match the local review record",
		)
	}
	if view.Artifact.BaselineCommitSHA !=
		record.Baseline {
		return fmt.Errorf(
			"shared approval baseline does not match the local review record",
		)
	}

	return nil
}

func sharedApprovalHTTPError(
	statusCode int,
) error {
	switch statusCode {
	case http.StatusUnauthorized,
		http.StatusForbidden:
		return fmt.Errorf(
			"shared approval API authentication failed",
		)
	case http.StatusNotFound:
		return fmt.Errorf(
			"shared approval request was not found",
		)
	case http.StatusConflict:
		return fmt.Errorf(
			"shared approval request has a conflicting state",
		)
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests:
		return fmt.Errorf(
			"shared approval API is temporarily unavailable",
		)
	default:
		if statusCode >= 500 {
			return fmt.Errorf(
				"shared approval API is unavailable",
			)
		}

		return fmt.Errorf(
			"shared approval API rejected the request with HTTP %d",
			statusCode,
		)
	}
}

func statusVerb(
	status string,
) string {
	if status == localDecisionApproved {
		return "approve"
	}

	return "reject"
}

func isLoopbackApprovalHost(
	host string,
) bool {
	if strings.EqualFold(
		host,
		"localhost",
	) {
		return true
	}

	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func hasParentPathSegment(
	value string,
) bool {
	for _, segment := range strings.Split(
		value,
		"/",
	) {
		if segment == ".." {
			return true
		}
	}

	return false
}
