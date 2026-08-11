package httpapi

import (
	"errors"
	"time"
)

const (
	AdminAPIPageSizeDefault = 50
	AdminAPIPageSizeMax     = 100
	AdminAPICursorMaxBytes  = 512
)

var ErrInvalidPageRequest = errors.New("invalid page request")

// PageRequest is shared by every administration list operation. Cursor values
// are opaque to clients and are interpreted only by the server.
type PageRequest struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

func (request PageRequest) Validate() error {
	if request.Limit < 0 || request.Limit > AdminAPIPageSizeMax || len(request.Cursor) > AdminAPICursorMaxBytes {
		return ErrInvalidPageRequest
	}
	return nil
}

func (request PageRequest) EffectiveLimit() int {
	if request.Limit == 0 {
		return AdminAPIPageSizeDefault
	}
	return request.Limit
}

type Pagination struct {
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

type PagedResponse[T any] struct {
	Data       []T        `json:"data"`
	Pagination Pagination `json:"pagination"`
}

type AccountStatus string

const (
	AccountStatusPending  AccountStatus = "pending"
	AccountStatusActive   AccountStatus = "active"
	AccountStatusDisabled AccountStatus = "disabled"
)

type Account struct {
	ID         string        `json:"id"`
	Email      string        `json:"email"`
	Role       Role          `json:"role"`
	Status     AccountStatus `json:"status"`
	TeamIDs    []string      `json:"team_ids,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  *time.Time    `json:"updated_at,omitempty"`
	DisabledAt *time.Time    `json:"disabled_at,omitempty"`
}

type CreateSessionRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SessionResponse struct {
	Account              Account    `json:"account"`
	ExpiresAt            time.Time  `json:"expires_at"`
	ReauthenticatedUntil *time.Time `json:"reauthenticated_until,omitempty"`
}

type ReauthenticateRequest struct {
	Password string `json:"password"`
}

type ListAccountsRequest struct {
	PageRequest
	Status *AccountStatus `json:"status,omitempty"`
	Role   *Role          `json:"role,omitempty"`
}

type CreateInvitationRequest struct {
	Email  string `json:"email"`
	TeamID string `json:"team_id"`
}

type ListInvitationsRequest struct {
	PageRequest
	Status *AccountStatus `json:"status,omitempty"`
}

type Invitation struct {
	AccountID string        `json:"account_id"`
	Email     string        `json:"email"`
	TeamID    string        `json:"team_id"`
	Status    AccountStatus `json:"status"`
	ExpiresAt time.Time     `json:"expires_at"`
	CreatedAt time.Time     `json:"created_at"`
}

type InvitationIssuance struct {
	Invitation     Invitation `json:"invitation"`
	ActivationCode string     `json:"activation_code"`
}

type CompleteActivationRequest struct {
	Email          string `json:"email"`
	ActivationCode string `json:"activation_code"`
	Password       string `json:"password"`
}

type UpdateAccountRequest struct {
	Email  *string        `json:"email,omitempty"`
	Role   *Role          `json:"role,omitempty"`
	Status *AccountStatus `json:"status,omitempty"`
}

type IssuePasswordResetRequest struct {
	Email                  string `json:"email"`
	ManualIdentityVerified bool   `json:"manual_identity_verified"`
	CompromiseResponse     bool   `json:"compromise_response"`
}

type PasswordResetCodeIssuance struct {
	Code      string    `json:"code"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CompletePasswordResetRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

type TeamStatus string

const (
	TeamStatusActive   TeamStatus = "active"
	TeamStatusDisabled TeamStatus = "disabled"
)

type Team struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Status      TeamStatus `json:"status"`
	MemberCount int        `json:"member_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
}

type CreateTeamRequest struct {
	Name string `json:"name"`
}

type UpdateTeamRequest struct {
	Name   *string     `json:"name,omitempty"`
	Status *TeamStatus `json:"status,omitempty"`
}

type ListTeamsRequest struct {
	PageRequest
	Status *TeamStatus `json:"status,omitempty"`
}

type TeamMember struct {
	AccountID string        `json:"account_id"`
	Email     string        `json:"email"`
	Role      Role          `json:"role"`
	Status    AccountStatus `json:"status"`
	JoinedAt  time.Time     `json:"joined_at"`
}

type AddTeamMemberRequest struct {
	AccountID string `json:"account_id"`
}

type ListTeamMembersRequest struct {
	PageRequest
}

type KeyKind string

const (
	KeyKindPersonal KeyKind = "personal"
	KeyKindService  KeyKind = "service"
)

type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "active"
	KeyStatusRevoked KeyStatus = "revoked"
)

type Key struct {
	ID               string     `json:"id"`
	Kind             KeyKind    `json:"kind"`
	OwnerAccountID   string     `json:"owner_account_id,omitempty"`
	ServiceAccountID string     `json:"service_account_id,omitempty"`
	TeamID           string     `json:"team_id,omitempty"`
	Name             string     `json:"name"`
	Prefix           string     `json:"prefix"`
	Status           KeyStatus  `json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

// IssuedCredential is returned only by an issuance or rotation operation and
// is never part of Key or any list response.
type IssuedCredential struct {
	Value string `json:"value"`
}

type KeyIssuance struct {
	Key        Key              `json:"key"`
	Credential IssuedCredential `json:"credential"`
}

type CreatePersonalKeyRequest struct {
	Name string `json:"name"`
}

type CreateServiceAccountRequest struct {
	TeamID               string `json:"team_id"`
	ResponsibleAccountID string `json:"responsible_account_id"`
	Name                 string `json:"name"`
}

type ServiceAccountStatus string

const (
	ServiceAccountStatusActive   ServiceAccountStatus = "active"
	ServiceAccountStatusDisabled ServiceAccountStatus = "disabled"
)

type ServiceAccount struct {
	ID                   string               `json:"id"`
	TeamID               string               `json:"team_id"`
	ResponsibleAccountID string               `json:"responsible_account_id"`
	Name                 string               `json:"name"`
	Status               ServiceAccountStatus `json:"status"`
	CreatedAt            time.Time            `json:"created_at"`
	UpdatedAt            *time.Time           `json:"updated_at,omitempty"`
	DisabledAt           *time.Time           `json:"disabled_at,omitempty"`
}

type UpdateServiceAccountRequest struct {
	Name   *string               `json:"name,omitempty"`
	Status *ServiceAccountStatus `json:"status,omitempty"`
}

type ListServiceAccountsRequest struct {
	PageRequest
	TeamID *string               `json:"team_id,omitempty"`
	Status *ServiceAccountStatus `json:"status,omitempty"`
}

type CreateServiceKeyRequest struct {
	Name string `json:"name"`
}

type RotateServiceKeyRequest struct {
	Name string `json:"name"`
}

type ListKeysRequest struct {
	PageRequest
	Status *KeyStatus `json:"status,omitempty"`
}

type ListServiceKeysRequest struct {
	PageRequest
	Status *KeyStatus `json:"status,omitempty"`
}

type ModelStatus string

const (
	ModelStatusAllowed  ModelStatus = "allowed"
	ModelStatusDisabled ModelStatus = "disabled"
)

type Model struct {
	ID              string      `json:"id"`
	Status          ModelStatus `json:"status"`
	InputUnitPrice  *string     `json:"input_unit_price,omitempty"`
	OutputUnitPrice *string     `json:"output_unit_price,omitempty"`
	PriceVersion    *string     `json:"price_version,omitempty"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

type ListModelsRequest struct {
	PageRequest
	Status *ModelStatus `json:"status,omitempty"`
}

type ReplaceModelAllowlistRequest struct {
	Models []Model `json:"models"`
}

type ModelAllowlistResponse struct {
	Data       []Model    `json:"data"`
	Pagination Pagination `json:"pagination"`
}

type UsageOutcome string

const (
	UsageOutcomeSuccess       UsageOutcome = "success"
	UsageOutcomeUpstreamError UsageOutcome = "upstream_error"
	UsageOutcomeCancelled     UsageOutcome = "cancelled"
	UsageOutcomeLocalError    UsageOutcome = "local_error"
)

type TokenUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
}

type UsageRecord struct {
	ID               string       `json:"id"`
	AuditID          string       `json:"audit_id"`
	RequestID        string       `json:"request_id"`
	KeyID            string       `json:"key_id"`
	OwnerAccountID   string       `json:"owner_account_id,omitempty"`
	ServiceAccountID string       `json:"service_account_id,omitempty"`
	TeamID           string       `json:"team_id"`
	ModelID          string       `json:"model_id"`
	Outcome          UsageOutcome `json:"outcome"`
	Usage            *TokenUsage  `json:"usage,omitempty"`
	UsageReported    bool         `json:"usage_reported"`
	PriceVersion     string       `json:"price_version,omitempty"`
	CalculatedAmount string       `json:"calculated_amount,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
}

type ListUsageRequest struct {
	PageRequest
	AccountID *string    `json:"account_id,omitempty"`
	TeamID    *string    `json:"team_id,omitempty"`
	ModelID   *string    `json:"model_id,omitempty"`
	From      *time.Time `json:"from,omitempty"`
	To        *time.Time `json:"to,omitempty"`
}

type TeamUsageAggregate struct {
	RequestCount       int64 `json:"request_count"`
	ReportedUsageCount int64 `json:"reported_usage_count"`
	InputTokens        int64 `json:"input_tokens"`
	OutputTokens       int64 `json:"output_tokens"`
	TotalTokens        int64 `json:"total_tokens"`
}

type TeamUsageResponse struct {
	Data       []UsageRecord      `json:"data"`
	Pagination Pagination         `json:"pagination"`
	Aggregate  TeamUsageAggregate `json:"aggregate"`
}

type AuditCaptureStatus string

const (
	AuditCaptureStatusPending    AuditCaptureStatus = "pending"
	AuditCaptureStatusComplete   AuditCaptureStatus = "complete"
	AuditCaptureStatusTruncated  AuditCaptureStatus = "truncated"
	AuditCaptureStatusIncomplete AuditCaptureStatus = "incomplete"
)

type AuditOutcome string

const (
	AuditOutcomePending       AuditOutcome = "pending"
	AuditOutcomeSuccess       AuditOutcome = "success"
	AuditOutcomeUpstreamError AuditOutcome = "upstream_error"
	AuditOutcomeCancelled     AuditOutcome = "cancelled"
	AuditOutcomeLocalError    AuditOutcome = "local_error"
)

type AuditMetadata struct {
	ID                    string             `json:"id"`
	RequestID             string             `json:"request_id"`
	KeyID                 string             `json:"key_id"`
	OwnerAccountID        string             `json:"owner_account_id,omitempty"`
	ServiceAccountID      string             `json:"service_account_id,omitempty"`
	ResponsibleAccountID  string             `json:"responsible_account_id,omitempty"`
	TeamID                string             `json:"team_id"`
	ModelID               string             `json:"model_id"`
	CaptureStatus         AuditCaptureStatus `json:"capture_status"`
	Outcome               AuditOutcome       `json:"outcome"`
	UpstreamRequestID     string             `json:"upstream_request_id,omitempty"`
	UpstreamHTTPStatus    *int               `json:"upstream_http_status,omitempty"`
	ErrorCode             string             `json:"error_code,omitempty"`
	FinishReason          string             `json:"finish_reason,omitempty"`
	ObservedRequestBytes  int64              `json:"observed_request_bytes"`
	ObservedResponseBytes int64              `json:"observed_response_bytes"`
	CreatedAt             time.Time          `json:"created_at"`
	UpdatedAt             time.Time          `json:"updated_at"`
	CompletedAt           *time.Time         `json:"completed_at,omitempty"`
}

type ListAuditMetadataRequest struct {
	PageRequest
	AccountID     *string             `json:"account_id,omitempty"`
	TeamID        *string             `json:"team_id,omitempty"`
	ModelID       *string             `json:"model_id,omitempty"`
	CaptureStatus *AuditCaptureStatus `json:"capture_status,omitempty"`
}

type SecurityEventOutcome string

const (
	SecurityEventOutcomeSuccess SecurityEventOutcome = "success"
	SecurityEventOutcomeDenied  SecurityEventOutcome = "denied"
	SecurityEventOutcomeFailure SecurityEventOutcome = "failure"
)

type SecurityEventMetadata struct {
	ID                     string               `json:"id"`
	EventType              string               `json:"event_type"`
	ActorAccountID         string               `json:"actor_account_id,omitempty"`
	TargetAccountID        string               `json:"target_account_id,omitempty"`
	TargetServiceAccountID string               `json:"target_service_account_id,omitempty"`
	TargetKeyID            string               `json:"target_key_id,omitempty"`
	TargetAuditID          string               `json:"target_audit_id,omitempty"`
	RequestID              string               `json:"request_id"`
	Outcome                SecurityEventOutcome `json:"outcome"`
	Reason                 string               `json:"reason,omitempty"`
	DetailCode             string               `json:"detail_code,omitempty"`
	OccurredAt             time.Time            `json:"occurred_at"`
}

type ListSecurityEventsRequest struct {
	PageRequest
	EventType *string               `json:"event_type,omitempty"`
	Outcome   *SecurityEventOutcome `json:"outcome,omitempty"`
	From      *time.Time            `json:"from,omitempty"`
	To        *time.Time            `json:"to,omitempty"`
}

type RetentionPolicy struct {
	Days        int       `json:"days"`
	MaximumDays int       `json:"maximum_days"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ReplaceRetentionPolicyRequest struct {
	Days      int  `json:"days"`
	Confirmed bool `json:"confirmed"`
}

type HealthState string

const (
	HealthStateHealthy   HealthState = "healthy"
	HealthStateDegraded  HealthState = "degraded"
	HealthStateUnhealthy HealthState = "unhealthy"
)

type HealthComponent struct {
	Name       string      `json:"name"`
	State      HealthState `json:"state"`
	DetailCode string      `json:"detail_code,omitempty"`
	CheckedAt  time.Time   `json:"checked_at"`
}

type HealthResponse struct {
	State      HealthState       `json:"state"`
	Components []HealthComponent `json:"components"`
	CheckedAt  time.Time         `json:"checked_at"`
}

type OperationalEvent struct {
	ID         string    `json:"id"`
	EventType  string    `json:"event_type"`
	Severity   string    `json:"severity"`
	DetailCode string    `json:"detail_code,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type ListOperationalEventsRequest struct {
	PageRequest
	Severity *string    `json:"severity,omitempty"`
	From     *time.Time `json:"from,omitempty"`
	To       *time.Time `json:"to,omitempty"`
}
