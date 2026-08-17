package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"n-api-p/internal/access"
	"n-api-p/internal/observability"
)

type AdminInvitationCreator interface {
	Create(context.Context, access.CreateInvitationInput) (access.Invitation, error)
}

type AdminModelPolicyService interface {
	AdminModelPolicyReader
	Replace(context.Context, access.ActivePortalSession, access.ModelAllowlistChangeInput) ([]access.ModelAllowlistEntry, error)
}

type AdminRetentionPolicyService interface {
	AdminRetentionPolicyReader
	Change(context.Context, access.ActivePortalSession, access.RetentionPolicyChangeInput) (access.RetentionPolicy, error)
}

type AdminServiceKeyCreator interface {
	CreateKey(context.Context, access.CreateServiceAccountKeyInput) (access.ServiceAccountKeyIssuance, error)
}

type AdminServiceKeyRevoker interface {
	RevokeKey(context.Context, access.RevokeServiceAccountKeyInput) error
}

type AdminAdministrationService interface {
	ListInvitations(context.Context, access.Actor, access.AdministrationInvitationFilter) (access.AdministrationInvitationPage, error)
	ListAccounts(context.Context, access.Actor, access.AdministrationAccountFilter) (access.AdministrationAccountPage, error)
	ListTeams(context.Context, access.Actor, access.AdministrationTeamFilter) (access.AdministrationTeamPage, error)
	ListServiceAccounts(context.Context, access.Actor, access.AdministrationServiceAccountFilter) (access.AdministrationServiceAccountPage, error)
	GetAccount(context.Context, access.Actor, string) (access.AdministrationAccount, error)
	GetTeam(context.Context, access.Actor, string) (access.AdministrationTeam, error)
	GetServiceAccount(context.Context, access.Actor, string) (access.ServiceAccount, error)
	CreateTeam(context.Context, access.CreateAdministrationTeamInput) (access.AdministrationTeam, error)
	UpdateTeam(context.Context, access.UpdateAdministrationTeamInput) (access.AdministrationTeam, error)
	ChangeRole(context.Context, access.ChangeRoleInput) error
	AddMembership(context.Context, access.ChangeMembershipInput) error
	RemoveMembership(context.Context, access.ChangeMembershipInput) error
}

func NewAdminInvitationListHandler(service interface {
	ListInvitations(context.Context, access.Actor, access.AdministrationInvitationFilter) (access.AdministrationInvitationPage, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		limit, err := parsePageLimit(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		filter := access.AdministrationInvitationFilter{Limit: limit, Cursor: request.URL.Query().Get("cursor")}
		if raw := strings.TrimSpace(request.URL.Query().Get("status")); raw != "" {
			value := access.IdentityStatus(raw)
			filter.Status = &value
		}
		page, err := service.ListInvitations(request.Context(), adminActor(session), filter)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		data := make([]Invitation, 0, len(page.Invitations))
		for _, invitation := range page.Invitations {
			data = append(data, Invitation{
				AccountID: invitation.IdentityID, Email: invitation.Email, TeamID: invitation.TeamID,
				Status: AccountStatus(invitation.Status), ExpiresAt: invitation.ExpiresAt, CreatedAt: invitation.CreatedAt,
			})
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[Invitation]{Data: data, Pagination: Pagination{NextCursor: page.NextCursor, HasMore: page.NextCursor != ""}})
	})
}

type AdminOffboardingService interface {
	DisableEmployee(context.Context, access.DisableEmployeeInput) error
	DisableTeam(context.Context, access.DisableTeamInput) error
	DisableServiceAccount(context.Context, access.DisableServiceAccountInput) error
}

type AdminServiceAccountService interface {
	AdminServiceAccountCreator
	AdminServiceAccountLister
	AdminServiceAccountKeyLister
	AdminServiceKeyCreator
	AdminServiceKeyRevoker
	AdminServiceKeyRotator
}

type AdminServiceAccountCreator interface {
	Create(context.Context, access.CreateServiceAccountInput) (access.ServiceAccount, error)
}

type AdminServiceAccountLister interface {
	List(context.Context, access.Actor) ([]access.ServiceAccount, error)
}

type AdminServiceAccountKeyLister interface {
	ListKeys(context.Context, access.ListServiceAccountKeysInput) ([]access.ServiceAccountKey, error)
}

type AdminServiceKeyRotator interface {
	RotateKey(context.Context, access.RotateServiceAccountKeyInput) (access.ServiceAccountKeyIssuance, error)
}

type AdminModelPolicyReader interface {
	Get(context.Context, access.ActivePortalSession) ([]access.ModelAllowlistEntry, error)
}

type AdminRetentionPolicyReader interface {
	Get(context.Context, access.ActivePortalSession) (access.RetentionPolicy, error)
}

type AdminPortalDependencies struct {
	Sessions         PortalSessionService
	AllowedOrigin    string
	Invitations      AdminInvitationCreator
	PasswordResets   PasswordResetCodeIssuer
	ServiceKeys      AdminServiceKeyCreator
	ServiceKeyRevoke AdminServiceKeyRevoker
	Models           AdminModelPolicyService
	Retention        AdminRetentionPolicyService
	Administration   AdminAdministrationService
	Audits           AdminAuditMetadataService
	RawView          RawViewInspector
	Operations       AdminOperationsService
	Offboarding      AdminOffboardingService
	ServiceAccount   AdminServiceAccountService
}

var ErrAdminPortalDependencies = errors.New("admin portal services are required")

func NewAdminPasswordResetCodeHandler(service PasswordResetCodeIssuer) http.Handler {
	return NewPasswordResetCodeHandler(service)
}

func NewAdminServiceKeyRevokeHandler(service AdminServiceKeyRevoker) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input struct {
			Confirmed bool `json:"confirmed"`
		}
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		if !input.Confirmed {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		serviceAccountID := pathIdentifier(request, "serviceAccountID", "service-accounts")
		keyID := pathIdentifier(request, "keyID", "keys")
		if serviceAccountID == "" || keyID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if err := service.RevokeKey(request.Context(), access.RevokeServiceAccountKeyInput{
			Actor: adminActor(session), ServiceAccountID: serviceAccountID, KeyID: keyID, RequestID: adminRequestID(request),
		}); err != nil {
			writeAdminError(writer, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewAdminAccountListHandler(service interface {
	ListAccounts(context.Context, access.Actor, access.AdministrationAccountFilter) (access.AdministrationAccountPage, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		limit, err := parsePageLimit(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		filter := access.AdministrationAccountFilter{Limit: limit, Cursor: request.URL.Query().Get("cursor")}
		if raw := strings.TrimSpace(request.URL.Query().Get("status")); raw != "" {
			value := access.IdentityStatus(raw)
			filter.Status = &value
		}
		if raw := strings.TrimSpace(request.URL.Query().Get("role")); raw != "" {
			value := access.Role(raw)
			filter.Role = &value
		}
		page, err := service.ListAccounts(request.Context(), adminActor(session), filter)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		data := make([]Account, 0, len(page.Accounts))
		for _, account := range page.Accounts {
			data = append(data, accountResponse(account))
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[Account]{Data: data, Pagination: Pagination{NextCursor: page.NextCursor, HasMore: page.NextCursor != ""}})
	})
}

func NewAdminAccountGetHandler(service interface {
	GetAccount(context.Context, access.Actor, string) (access.AdministrationAccount, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		identityID := pathIdentifier(request, "userID", "users")
		if identityID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		account, err := service.GetAccount(request.Context(), adminActor(session), identityID)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, accountResponse(account))
	})
}

func NewAdminTeamListHandler(service interface {
	ListTeams(context.Context, access.Actor, access.AdministrationTeamFilter) (access.AdministrationTeamPage, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		limit, err := parsePageLimit(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		filter := access.AdministrationTeamFilter{Limit: limit, Cursor: request.URL.Query().Get("cursor")}
		if raw := strings.TrimSpace(request.URL.Query().Get("status")); raw != "" {
			filter.Status = &raw
		}
		page, err := service.ListTeams(request.Context(), adminActor(session), filter)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		data := make([]Team, 0, len(page.Teams))
		for _, team := range page.Teams {
			data = append(data, teamResponse(team))
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[Team]{Data: data, Pagination: Pagination{NextCursor: page.NextCursor, HasMore: page.NextCursor != ""}})
	})
}

func NewAdminTeamCreateHandler(service interface {
	CreateTeam(context.Context, access.CreateAdministrationTeamInput) (access.AdministrationTeam, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input CreateTeamRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		team, err := service.CreateTeam(request.Context(), access.CreateAdministrationTeamInput{
			Actor: adminActor(session), Name: input.Name, RequestID: adminRequestID(request),
		})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusCreated, teamResponse(team))
	})
}

func NewAdminTeamGetHandler(service interface {
	GetTeam(context.Context, access.Actor, string) (access.AdministrationTeam, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		teamID := pathIdentifier(request, "teamID", "teams")
		if teamID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		team, err := service.GetTeam(request.Context(), adminActor(session), teamID)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, teamResponse(team))
	})
}

func NewAdminTeamUpdateHandler(administration interface {
	UpdateTeam(context.Context, access.UpdateAdministrationTeamInput) (access.AdministrationTeam, error)
}, offboarding interface {
	DisableTeam(context.Context, access.DisableTeamInput) error
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input UpdateTeamRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		teamID := pathIdentifier(request, "teamID", "teams")
		changeCount := 0
		for _, provided := range []bool{input.Name != nil, input.Status != nil} {
			if provided {
				changeCount++
			}
		}
		if teamID == "" || changeCount != 1 {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		if input.Status != nil {
			if *input.Status != TeamStatusDisabled || !input.Confirmed {
				writeErrorResponse(writer, CodeInvalidRequest)
				return
			}
			if err := offboarding.DisableTeam(request.Context(), access.DisableTeamInput{
				Actor: adminActor(session), TeamID: teamID, RequestID: adminRequestID(request),
			}); err != nil {
				writeAdminError(writer, err)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.TrimSpace(*input.Name) == "" {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		team, err := administration.UpdateTeam(request.Context(), access.UpdateAdministrationTeamInput{
			Actor: adminActor(session), TeamID: teamID, Name: *input.Name, Confirmed: input.Confirmed, RequestID: adminRequestID(request),
		})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, teamResponse(team))
	})
}

func NewAdminServiceAccountListHandler(service interface {
	ListServiceAccounts(context.Context, access.Actor, access.AdministrationServiceAccountFilter) (access.AdministrationServiceAccountPage, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		limit, err := parsePageLimit(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		filter := access.AdministrationServiceAccountFilter{Limit: limit, Cursor: request.URL.Query().Get("cursor")}
		if raw := strings.TrimSpace(request.URL.Query().Get("team_id")); raw != "" {
			filter.TeamID = &raw
		}
		if raw := strings.TrimSpace(request.URL.Query().Get("status")); raw != "" {
			value := access.ServiceAccountStatus(raw)
			filter.Status = &value
		}
		page, err := service.ListServiceAccounts(request.Context(), adminActor(session), filter)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		data := make([]ServiceAccount, 0, len(page.ServiceAccounts))
		for _, account := range page.ServiceAccounts {
			data = append(data, serviceAccountResponse(account))
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[ServiceAccount]{Data: data, Pagination: Pagination{NextCursor: page.NextCursor, HasMore: page.NextCursor != ""}})
	})
}

func NewAdminServiceAccountGetHandler(service interface {
	GetServiceAccount(context.Context, access.Actor, string) (access.ServiceAccount, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		serviceAccountID := pathIdentifier(request, "serviceAccountID", "service-accounts")
		if serviceAccountID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		account, err := service.GetServiceAccount(request.Context(), adminActor(session), serviceAccountID)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, serviceAccountResponse(account))
	})
}

func NewAdminAccountUpdateHandler(administration interface {
	ChangeRole(context.Context, access.ChangeRoleInput) error
}, offboarding interface {
	DisableEmployee(context.Context, access.DisableEmployeeInput) error
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input UpdateAccountRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		identityID := pathIdentifier(request, "userID", "users")
		changeCount := 0
		for _, provided := range []bool{input.Role != nil, input.Status != nil, input.Email != nil} {
			if provided {
				changeCount++
			}
		}
		if identityID == "" || changeCount != 1 || input.Email != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		if input.Status != nil && (*input.Status != AccountStatusDisabled || !input.Confirmed) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		if input.Role != nil && !input.Confirmed {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		if input.Role != nil {
			if err := administration.ChangeRole(request.Context(), access.ChangeRoleInput{Actor: adminActor(session), IdentityID: identityID, Role: access.Role(*input.Role), RequestID: adminRequestID(request)}); err != nil {
				writeAdminError(writer, err)
				return
			}
		}
		if input.Status != nil {
			if err := offboarding.DisableEmployee(request.Context(), access.DisableEmployeeInput{Actor: adminActor(session), IdentityID: identityID, RequestID: adminRequestID(request)}); err != nil {
				writeAdminError(writer, err)
				return
			}
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewAdminMembershipAddHandler(service interface {
	AddMembership(context.Context, access.ChangeMembershipInput) error
}) http.Handler {
	return adminMembershipAddHandler(service)
}

func NewAdminTeamDisableHandler(service AdminOffboardingService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input struct {
			Confirmed bool `json:"confirmed"`
		}
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		if !input.Confirmed {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		teamID := pathIdentifier(request, "teamID", "teams")
		if teamID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if err := service.DisableTeam(request.Context(), access.DisableTeamInput{
			Actor: adminActor(session), TeamID: teamID, RequestID: adminRequestID(request),
		}); err != nil {
			writeAdminError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewAdminMembershipRemoveHandler(service interface {
	RemoveMembership(context.Context, access.ChangeMembershipInput) error
}) http.Handler {
	return adminMembershipRemoveHandler(service)
}

func adminMembershipAddHandler(service interface {
	AddMembership(context.Context, access.ChangeMembershipInput) error
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		identityID := pathIdentifier(request, "userID", "members")
		teamID := pathIdentifier(request, "teamID", "teams")
		if identityID == "" || teamID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		input := access.ChangeMembershipInput{Actor: adminActor(session), IdentityID: identityID, TeamID: teamID, RequestID: adminRequestID(request)}
		err := service.AddMembership(request.Context(), input)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func adminMembershipRemoveHandler(service interface {
	RemoveMembership(context.Context, access.ChangeMembershipInput) error
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var body struct {
			Confirmed bool `json:"confirmed"`
		}
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		if !body.Confirmed {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		identityID := pathIdentifier(request, "userID", "members")
		teamID := pathIdentifier(request, "teamID", "teams")
		if identityID == "" || teamID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		err := service.RemoveMembership(request.Context(), access.ChangeMembershipInput{
			Actor: adminActor(session), IdentityID: identityID, TeamID: teamID, RequestID: adminRequestID(request),
		})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewAdminServiceAccountCreateHandler(service AdminServiceAccountCreator) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input CreateServiceAccountRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		if strings.TrimSpace(input.TeamID) == "" || strings.TrimSpace(input.ResponsibleAccountID) == "" || strings.TrimSpace(input.Name) == "" {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		account, err := service.Create(request.Context(), access.CreateServiceAccountInput{Actor: adminActor(session), TeamID: input.TeamID, ResponsibleIdentityID: input.ResponsibleAccountID, Name: input.Name, RequestID: adminRequestID(request)})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusCreated, serviceAccountResponse(account))
	})
}

func NewAdminServiceAccountUpdateHandler(service AdminOffboardingService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input UpdateServiceAccountRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		serviceAccountID := pathIdentifier(request, "serviceAccountID", "service-accounts")
		if serviceAccountID == "" || input.Status == nil || *input.Status != ServiceAccountStatusDisabled || !input.Confirmed || input.Name != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		if err := service.DisableServiceAccount(request.Context(), access.DisableServiceAccountInput{
			Actor: adminActor(session), ServiceAccountID: serviceAccountID, RequestID: adminRequestID(request),
		}); err != nil {
			writeAdminError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewAdminServiceAccountDeleteHandler(service AdminOffboardingService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input struct {
			Confirmed bool `json:"confirmed"`
		}
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		serviceAccountID := pathIdentifier(request, "serviceAccountID", "service-accounts")
		if serviceAccountID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if !input.Confirmed {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		if err := service.DisableServiceAccount(request.Context(), access.DisableServiceAccountInput{
			Actor: adminActor(session), ServiceAccountID: serviceAccountID, RequestID: adminRequestID(request),
		}); err != nil {
			writeAdminError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewAdminServiceKeyListHandler(service AdminServiceAccountKeyLister) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		id := pathIdentifier(request, "serviceAccountID", "service-accounts")
		if id == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		keys, err := service.ListKeys(request.Context(), access.ListServiceAccountKeysInput{Actor: adminActor(session), ServiceAccountID: id})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		data := make([]Key, 0, len(keys))
		for _, key := range keys {
			data = append(data, serviceKeyResponse(key))
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[Key]{Data: data, Pagination: Pagination{HasMore: false}})
	})
}

func NewAdminServiceKeyRotateHandler(service AdminServiceKeyRotator) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input RotateServiceKeyRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		if strings.TrimSpace(input.Name) == "" || !input.Confirmed {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		serviceAccountID := pathIdentifier(request, "serviceAccountID", "service-accounts")
		keyID := pathIdentifier(request, "keyID", "keys")
		if serviceAccountID == "" || keyID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		issuance, err := service.RotateKey(request.Context(), access.RotateServiceAccountKeyInput{Actor: adminActor(session), ServiceAccountID: serviceAccountID, KeyID: keyID, Name: input.Name, RequestID: adminRequestID(request)})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		value, revealed := issuance.Credential.Reveal()
		if !revealed || value == "" {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeJSON(writer, http.StatusCreated, KeyIssuance{Key: serviceKeyResponse(issuance.Key), Credential: IssuedCredential{Value: value}})
	})
}

func NewAdminModelAllowlistGetHandler(service AdminModelPolicyReader) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		entries, err := service.Get(request.Context(), session)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, modelAllowlistResponse(entries))
	})
}

func NewAdminRetentionPolicyGetHandler(service AdminRetentionPolicyReader) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		policy, err := service.Get(request.Context(), session)
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, retentionPolicyResponse(policy))
	})
}

func NewAdminPortalRouter(deps AdminPortalDependencies) (http.Handler, error) {
	if deps.Sessions == nil || deps.Invitations == nil || deps.PasswordResets == nil || deps.ServiceKeys == nil || deps.ServiceKeyRevoke == nil || deps.Models == nil || deps.Retention == nil || deps.Administration == nil || deps.Audits == nil || deps.RawView == nil || deps.Operations == nil || deps.Offboarding == nil || deps.ServiceAccount == nil {
		return nil, ErrAdminPortalDependencies
	}
	middleware, err := NewPortalSessionMiddleware(deps.Sessions, deps.AllowedOrigin)
	if err != nil {
		return nil, err
	}
	guard := NewAuthorizationGuard()
	mux := http.NewServeMux()
	registerAdminRoute := func(name RouteName, method, pattern string, handler http.Handler) error {
		route := routeByNameValue(name)
		if route.Pattern == "" || route.Auth != AuthPortalSession || len(route.Roles) != 1 || route.Roles[0] != RoleSystemAdministrator {
			return ErrAdminPortalDependencies
		}
		mux.Handle(method+" "+pattern, guard.Wrap(route, handler))
		return nil
	}
	if err := registerAdminRoute("admin.invitations.create", http.MethodPost, "/api/v1/invitations", NewAdminInvitationCreateHandler(deps.Invitations)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.invitations.list", http.MethodGet, "/api/v1/invitations", NewAdminInvitationListHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.users.issue_password_reset", http.MethodPost, "/api/v1/users/{userID}/password-reset-codes", NewAdminPasswordResetCodeHandler(deps.PasswordResets)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.users.list", http.MethodGet, "/api/v1/users", NewAdminAccountListHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.users.get", http.MethodGet, "/api/v1/users/{userID}", NewAdminAccountGetHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.users.update", http.MethodPatch, "/api/v1/users/{userID}", NewAdminAccountUpdateHandler(deps.Administration, deps.Offboarding)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.teams.list", http.MethodGet, "/api/v1/teams", NewAdminTeamListHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.teams.create", http.MethodPost, "/api/v1/teams", NewAdminTeamCreateHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.teams.get", http.MethodGet, "/api/v1/teams/{teamID}", NewAdminTeamGetHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.teams.update", http.MethodPatch, "/api/v1/teams/{teamID}", NewAdminTeamUpdateHandler(deps.Administration, deps.Offboarding)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.teams.delete", http.MethodDelete, "/api/v1/teams/{teamID}", NewAdminTeamDisableHandler(deps.Offboarding)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.team_members.add", http.MethodPut, "/api/v1/teams/{teamID}/members/{userID}", NewAdminMembershipAddHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.team_members.remove", http.MethodDelete, "/api/v1/teams/{teamID}/members/{userID}", NewAdminMembershipRemoveHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_accounts.list", http.MethodGet, "/api/v1/service-accounts", NewAdminServiceAccountListHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_accounts.create", http.MethodPost, "/api/v1/service-accounts", NewAdminServiceAccountCreateHandler(deps.ServiceAccount)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_accounts.get", http.MethodGet, "/api/v1/service-accounts/{serviceAccountID}", NewAdminServiceAccountGetHandler(deps.Administration)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_accounts.update", http.MethodPatch, "/api/v1/service-accounts/{serviceAccountID}", NewAdminServiceAccountUpdateHandler(deps.Offboarding)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_accounts.delete", http.MethodDelete, "/api/v1/service-accounts/{serviceAccountID}", NewAdminServiceAccountDeleteHandler(deps.Offboarding)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_keys.list", http.MethodGet, "/api/v1/service-accounts/{serviceAccountID}/keys", NewAdminServiceKeyListHandler(deps.ServiceAccount)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_keys.create", http.MethodPost, "/api/v1/service-accounts/{serviceAccountID}/keys", NewAdminServiceKeyCreateHandler(deps.ServiceKeys)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_keys.revoke", http.MethodDelete, "/api/v1/service-accounts/{serviceAccountID}/keys/{keyID}", NewAdminServiceKeyRevokeHandler(deps.ServiceKeyRevoke)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.service_keys.rotate", http.MethodPost, "/api/v1/service-accounts/{serviceAccountID}/keys/{keyID}/rotations", NewAdminServiceKeyRotateHandler(deps.ServiceAccount)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.model_allowlist.get", http.MethodGet, "/api/v1/model-allowlist", NewAdminModelAllowlistGetHandler(deps.Models)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.model_allowlist.replace", http.MethodPut, "/api/v1/model-allowlist", NewAdminModelAllowlistReplaceHandler(deps.Models)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.retention_policy.replace", http.MethodPut, "/api/v1/retention-policy", NewAdminRetentionPolicyReplaceHandler(deps.Retention)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.retention_policy.get", http.MethodGet, "/api/v1/retention-policy", NewAdminRetentionPolicyGetHandler(deps.Retention)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.audits.list", http.MethodGet, "/api/v1/audits", NewAdminAuditMetadataListHandler(deps.Audits)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.audits.get", http.MethodGet, "/api/v1/audits/{auditID}", NewAdminAuditMetadataGetHandler(deps.Audits)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.audits.view_raw", http.MethodPost, "/api/v1/audits/{auditID}/raw-views", NewRawViewHandler(deps.RawView)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.operations.health", http.MethodGet, "/api/v1/operations/health", NewAdminOperationsHealthHandler(deps.Operations)); err != nil {
		return nil, err
	}
	if err := registerAdminRoute("admin.operations.events", http.MethodGet, "/api/v1/operations/events", NewAdminOperationalEventsHandler(deps.Operations)); err != nil {
		return nil, err
	}
	return observability.NewRequestIDMiddleware(middleware.Wrap(mux), observability.DefaultLogger()), nil
}

func NewAdminInvitationCreateHandler(service AdminInvitationCreator) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input CreateInvitationRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		if strings.TrimSpace(input.Email) == "" || strings.TrimSpace(input.TeamID) == "" {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		invitation, err := service.Create(request.Context(), access.CreateInvitationInput{
			Actor: adminActor(session), Email: input.Email, TeamID: input.TeamID, RequestID: adminRequestID(request),
		})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusCreated, InvitationIssuance{
			Invitation: Invitation{
				AccountID: invitation.IdentityID, Email: invitation.Email, TeamID: strings.TrimSpace(input.TeamID),
				Status: AccountStatusPending, ExpiresAt: invitation.ExpiresAt, CreatedAt: invitation.CreatedAt,
			},
			ActivationCode: invitation.ActivationValue,
		})
	})
}

func NewAdminModelAllowlistReplaceHandler(service AdminModelPolicyService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input ReplaceModelAllowlistRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		entries := make([]access.ModelAllowlistEntry, 0, len(input.Models))
		for _, model := range input.Models {
			entries = append(entries, access.ModelAllowlistEntry{
				ModelID: model.ID, Status: access.ModelStatus(model.Status),
				InputUnitPrice: stringValue(model.InputUnitPrice), OutputUnitPrice: stringValue(model.OutputUnitPrice),
				PriceVersion: stringValue(model.PriceVersion),
			})
		}
		result, err := service.Replace(request.Context(), session, access.ModelAllowlistChangeInput{
			Entries: entries, Confirmed: input.Confirmed, RequestID: adminRequestID(request),
		})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, modelAllowlistResponse(result))
	})
}

func NewAdminRetentionPolicyReplaceHandler(service AdminRetentionPolicyService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input ReplaceRetentionPolicyRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		policy, err := service.Change(request.Context(), session, access.RetentionPolicyChangeInput{
			Days: input.Days, Confirmed: input.Confirmed, RequestID: adminRequestID(request),
		})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, retentionPolicyResponse(policy))
	})
}

func NewAdminServiceKeyCreateHandler(service AdminServiceKeyCreator) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var input CreateServiceKeyRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		if strings.TrimSpace(input.Name) == "" {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		serviceAccountID := pathIdentifier(request, "serviceAccountID", "service-accounts")
		if serviceAccountID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		issuance, err := service.CreateKey(request.Context(), access.CreateServiceAccountKeyInput{
			Actor: adminActor(session), ServiceAccountID: serviceAccountID, Name: input.Name, RequestID: adminRequestID(request),
		})
		if err != nil {
			writeAdminError(writer, err)
			return
		}
		value, revealed := issuance.Credential.Reveal()
		if !revealed || value == "" {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		writeJSON(writer, http.StatusCreated, KeyIssuance{Key: serviceKeyResponse(issuance.Key), Credential: IssuedCredential{Value: value}})
	})
}

func requireSystemAdministrator(writer http.ResponseWriter, request *http.Request) (access.ActivePortalSession, bool) {
	session, ok := PortalSessionFromContext(request.Context())
	if !ok || session.IdentityID == "" {
		writeErrorResponse(writer, CodeAuthenticationRequired)
		return access.ActivePortalSession{}, false
	}
	if session.Role != access.RoleSystemAdministrator {
		writeErrorResponse(writer, CodeForbidden)
		return access.ActivePortalSession{}, false
	}
	return session, true
}

func adminActor(session access.ActivePortalSession) access.Actor {
	return access.Actor{IdentityID: session.IdentityID, Role: session.Role}
}

func adminRequestID(request *http.Request) string {
	if value, ok := observability.RequestIDFromContext(request.Context()); ok {
		return value
	}
	value, err := observability.ResolveRequestID(request.Header.Get(observability.RequestIDHeader))
	if err != nil {
		return ""
	}
	return value
}

func pathIdentifier(request *http.Request, pathName, segment string) string {
	if value := strings.TrimSpace(request.PathValue(pathName)); value != "" {
		return value
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	for index, part := range parts {
		if part == segment && index+1 < len(parts) {
			return strings.TrimSpace(parts[index+1])
		}
	}
	return ""
}

func serviceKeyResponse(key access.ServiceAccountKey) Key {
	return Key{
		ID: key.ID, Kind: KeyKindService, ServiceAccountID: key.ServiceAccountID, TeamID: key.TeamID,
		Name: key.Name, Prefix: key.Prefix, Status: KeyStatus(key.Status), CreatedAt: key.CreatedAt,
		LastUsedAt: key.LastUsedAt, RevokedAt: key.RevokedAt,
	}
}

func accountResponse(account access.AdministrationAccount) Account {
	updatedAt := account.UpdatedAt
	return Account{
		ID: account.ID, Email: account.Email, Role: Role(account.Role), Status: AccountStatus(account.Status),
		TeamIDs: account.TeamIDs, CreatedAt: account.CreatedAt, UpdatedAt: &updatedAt, DisabledAt: account.DisabledAt,
	}
}

func teamResponse(team access.AdministrationTeam) Team {
	updatedAt := team.UpdatedAt
	return Team{
		ID: team.ID, Name: team.Name, Status: TeamStatus(team.Status), MemberCount: team.MemberCount,
		CreatedAt: team.CreatedAt, UpdatedAt: &updatedAt, DisabledAt: team.DisabledAt,
	}
}

func serviceAccountResponse(account access.ServiceAccount) ServiceAccount {
	updatedAt := account.UpdatedAt
	return ServiceAccount{
		ID: account.ID, TeamID: account.TeamID, ResponsibleAccountID: account.ResponsibleIdentityID,
		Name: account.Name, Status: ServiceAccountStatus(account.Status), CreatedAt: account.CreatedAt,
		UpdatedAt: &updatedAt, DisabledAt: account.DisabledAt,
	}
}

func modelAllowlistResponse(entries []access.ModelAllowlistEntry) ModelAllowlistResponse {
	models := make([]Model, 0, len(entries))
	for _, entry := range entries {
		models = append(models, Model{
			ID: entry.ModelID, Status: ModelStatus(entry.Status),
			InputUnitPrice: optionalStringPointer(entry.InputUnitPrice), OutputUnitPrice: optionalStringPointer(entry.OutputUnitPrice),
			PriceVersion: optionalStringPointer(entry.PriceVersion), UpdatedAt: entry.UpdatedAt,
		})
	}
	return ModelAllowlistResponse{Data: models, Pagination: Pagination{HasMore: false}}
}

func retentionPolicyResponse(policy access.RetentionPolicy) RetentionPolicy {
	return RetentionPolicy{Days: policy.Days, MaximumDays: policy.MaximumDays, UpdatedAt: policy.UpdatedAt}
}

func optionalStringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func writeAdminError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, access.ErrForbidden):
		writeErrorResponse(writer, CodeForbidden)
	case errors.Is(err, access.ErrReauthenticationRequired):
		writeErrorResponse(writer, CodeReauthenticationRequired)
	case errors.Is(err, access.ErrInvalidInvitation),
		errors.Is(err, access.ErrManualIdentityVerificationRequired),
		errors.Is(err, access.ErrInvalidServiceAccount),
		errors.Is(err, access.ErrInvalidServiceAccountKey),
		errors.Is(err, access.ErrInvalidModelAllowlist),
		errors.Is(err, access.ErrModelAllowlistConfirmationRequired),
		errors.Is(err, access.ErrInvalidRetentionPolicy),
		errors.Is(err, access.ErrRetentionConfirmationRequired),
		errors.Is(err, access.ErrInvalidAdministrationRequest):
		writeErrorResponse(writer, CodeInvalidRequest)
	case errors.Is(err, access.ErrEmailAlreadyExists),
		errors.Is(err, access.ErrServiceAccountNameConflict),
		errors.Is(err, access.ErrServiceAccountKeyNameConflict),
		errors.Is(err, access.ErrAdministrationConflict):
		writeErrorResponse(writer, CodeConflict)
	case errors.Is(err, access.ErrServiceAccountKeyLimitReached):
		writeErrorResponse(writer, CodeKeyLimitReached)
	case errors.Is(err, access.ErrPasswordResetRejected),
		errors.Is(err, access.ErrServiceAccountKeyNotFound),
		errors.Is(err, access.ErrAdministrationNotFound),
		errors.Is(err, access.ErrInvalidOffboardingTarget):
		writeErrorResponse(writer, CodeNotFound)
	default:
		writeErrorResponse(writer, CodeInternalError)
	}
}
