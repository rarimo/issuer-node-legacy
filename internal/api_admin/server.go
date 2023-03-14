package api_admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"

	"github.com/polygonid/sh-id-platform/internal/config"
	"github.com/polygonid/sh-id-platform/internal/core/domain"
	"github.com/polygonid/sh-id-platform/internal/core/ports"
	"github.com/polygonid/sh-id-platform/internal/core/services"
	"github.com/polygonid/sh-id-platform/internal/health"
	"github.com/polygonid/sh-id-platform/internal/log"
)

// Server implements StrictServerInterface and holds the implementation of all API controllers
// This is the glue to the API autogenerated code
type Server struct {
	cfg                *config.Configuration
	identityService    ports.IdentityService
	claimService       ports.ClaimsService
	schemaService      ports.SchemaAdminService
	connectionsService ports.ConnectionsService
	publisherGateway   ports.Publisher
	packageManager     *iden3comm.PackageManager
	health             *health.Status
}

// NewServer is a Server constructor
func NewServer(cfg *config.Configuration, identityService ports.IdentityService, claimsService ports.ClaimsService, schemaService ports.SchemaAdminService, connectionsService ports.ConnectionsService, publisherGateway ports.Publisher, packageManager *iden3comm.PackageManager, health *health.Status) *Server {
	return &Server{
		cfg:                cfg,
		identityService:    identityService,
		claimService:       claimsService,
		schemaService:      schemaService,
		connectionsService: connectionsService,
		publisherGateway:   publisherGateway,
		packageManager:     packageManager,
		health:             health,
	}
}

// Health is a method
func (s *Server) Health(_ context.Context, _ HealthRequestObject) (HealthResponseObject, error) {
	var resp Health200JSONResponse = s.health.Status()

	return resp, nil
}

// ImportSchema is the UI endpoint to import schema metadata
func (s *Server) ImportSchema(ctx context.Context, request ImportSchemaRequestObject) (ImportSchemaResponseObject, error) {
	req := request.Body
	if err := guardImportSchemaReq(req); err != nil {
		log.Debug(ctx, "Importing schema bad request", "err", err, "req", req)
		return ImportSchema400JSONResponse{N400JSONResponse{Message: fmt.Sprintf("bad request: %s", err.Error())}}, nil
	}
	schema, err := s.schemaService.ImportSchema(ctx, s.cfg.APIUI.IssuerDID, req.Url, req.SchemaType)
	if err != nil {
		log.Error(ctx, "Importing schema", "err", err, "req", req)
		return ImportSchema500JSONResponse{N500JSONResponse{Message: err.Error()}}, nil
	}
	return ImportSchema201JSONResponse{Id: schema.ID.String()}, nil
}

func guardImportSchemaReq(req *ImportSchemaJSONRequestBody) error {
	if req == nil {
		return errors.New("empty body")
	}
	if strings.TrimSpace(req.Url) == "" {
		return errors.New("empty url")
	}
	if strings.TrimSpace(req.SchemaType) == "" {
		return errors.New("empty type")
	}
	if _, err := url.ParseRequestURI(req.Url); err != nil {
		return fmt.Errorf("parsing url: %w", err)
	}
	return nil
}

// GetDocumentation this method will be overridden in the main function
func (s *Server) GetDocumentation(_ context.Context, _ GetDocumentationRequestObject) (GetDocumentationResponseObject, error) {
	return nil, nil
}

// AuthCallback receives the authentication information of a holder
func (s *Server) AuthCallback(ctx context.Context, request AuthCallbackRequestObject) (AuthCallbackResponseObject, error) {
	if request.Params.SessionID == nil || *request.Params.SessionID == "" {
		log.Debug(ctx, "empty sessionID auth-callback request")
		return AuthCallback400JSONResponse{N400JSONResponse{"Cannot proceed with empty sessionID"}}, nil
	}

	if request.Body == nil || *request.Body == "" {
		log.Debug(ctx, "empty request body auth-callback request")
		return AuthCallback400JSONResponse{N400JSONResponse{"Cannot proceed with empty body"}}, nil
	}

	err := s.identityService.Authenticate(ctx, *request.Body, *request.Params.SessionID, s.cfg.APIUI.ServerURL, s.cfg.APIUI.IssuerDID)
	if err != nil {
		log.Debug(ctx, "error authenticating", err.Error())
		return AuthCallback500JSONResponse{}, nil
	}

	return AuthCallback200Response{}, nil
}

// AuthQRCode returns the qr code for authenticating a user
func (s *Server) AuthQRCode(ctx context.Context, _ AuthQRCodeRequestObject) (AuthQRCodeResponseObject, error) {
	qrCode, err := s.identityService.CreateAuthenticationQRCode(ctx, s.cfg.APIUI.ServerURL, s.cfg.APIUI.IssuerDID)
	if err != nil {
		return AuthQRCode500JSONResponse{N500JSONResponse{"Unexpected error while creating qr code"}}, nil
	}

	return AuthQRCode200JSONResponse{
		Body: struct {
			CallbackUrl string        `json:"callbackUrl"`
			Reason      string        `json:"reason"`
			Scope       []interface{} `json:"scope"`
		}{
			qrCode.Body.CallbackURL,
			qrCode.Body.Reason,
			[]interface{}{},
		},
		From: qrCode.From,
		Id:   qrCode.ID,
		Thid: qrCode.ThreadID,
		Typ:  string(qrCode.Typ),
		Type: string(qrCode.Type),
	}, nil
}

// DeleteConnection deletes a connection
func (s *Server) DeleteConnection(ctx context.Context, request DeleteConnectionRequestObject) (DeleteConnectionResponseObject, error) {
	err := s.connectionsService.Delete(ctx, request.Id)
	if err != nil {
		if errors.Is(err, services.ErrConnectionDoesNotExist) {
			return DeleteConnection400JSONResponse{N400JSONResponse{"The given connection does not exist"}}, nil
		}
		return DeleteConnection500JSONResponse{N500JSONResponse{"There was an error deleting the connection"}}, nil
	}

	return DeleteConnection200JSONResponse{Message: "Connection successfully deleted"}, nil
}

// GetCredential returns a credential
func (s *Server) GetCredential(ctx context.Context, request GetCredentialRequestObject) (GetCredentialResponseObject, error) {
	credential, err := s.claimService.GetByID(ctx, &s.cfg.APIUI.IssuerDID, request.Id)
	if err != nil {
		if errors.Is(err, services.ErrClaimNotFound) {
			return GetCredential400JSONResponse{N400JSONResponse{"The given credential id does not exist"}}, nil
		}
		return GetCredential500JSONResponse{N500JSONResponse{"There was an error trying to retrieve the credential information"}}, nil
	}

	w3c, err := s.schemaService.FromClaimModelToW3CCredential(*credential)
	if err != nil {
		return GetCredential500JSONResponse{N500JSONResponse{"Invalid claim format"}}, nil
	}

	return toCredential(w3c, credential), nil
}

// GetYaml this method will be overridden in the main function
func (s *Server) GetYaml(_ context.Context, _ GetYamlRequestObject) (GetYamlResponseObject, error) {
	return nil, nil
}

// RegisterStatic add method to the mux that are not documented in the API.
func RegisterStatic(mux *chi.Mux) {
	mux.Get("/", documentation)
	mux.Get("/static/docs/api_ui/api.yaml", swagger)
}

func documentation(w http.ResponseWriter, _ *http.Request) {
	writeFile("api_ui/spec.html", w)
}

func swagger(w http.ResponseWriter, _ *http.Request) {
	writeFile("api_ui/api.yaml", w)
}

func writeFile(path string, w http.ResponseWriter) {
	f, err := os.ReadFile(path)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(f)
}

// CreateCredential - creates a new credential
func (s *Server) CreateCredential(ctx context.Context, request CreateCredentialRequestObject) (CreateCredentialResponseObject, error) {
	req := ports.NewCreateClaimRequest(&s.cfg.APIUI.IssuerDID, request.Body.CredentialSchema, request.Body.CredentialSubject, request.Body.Expiration, request.Body.Type, nil, nil, nil)
	resp, err := s.claimService.CreateClaim(ctx, req)
	if err != nil {
		if errors.Is(err, services.ErrJSONLdContext) {
			return CreateCredential400JSONResponse{N400JSONResponse{Message: err.Error()}}, nil
		}
		if errors.Is(err, services.ErrProcessSchema) {
			return CreateCredential400JSONResponse{N400JSONResponse{Message: err.Error()}}, nil
		}
		if errors.Is(err, services.ErrLoadingSchema) {
			return CreateCredential422JSONResponse{N422JSONResponse{Message: err.Error()}}, nil
		}
		if errors.Is(err, services.ErrMalformedURL) {
			return CreateCredential400JSONResponse{N400JSONResponse{Message: err.Error()}}, nil
		}
		return CreateCredential500JSONResponse{N500JSONResponse{Message: err.Error()}}, nil
	}
	return CreateCredential201JSONResponse{Id: resp.ID.String()}, nil
}

func toCredential(w3c *verifiable.W3CCredential, credential *domain.Claim) GetCredential200JSONResponse {
	expired := false
	if w3c.Expiration != nil {
		if time.Now().UTC().After(w3c.Expiration.UTC()) {
			expired = true
		}
	}

	proofs := make([]string, len(w3c.Proof))
	for i := range w3c.Proof {
		proofs[i] = string(w3c.Proof[i].ProofType())
	}

	return GetCredential200JSONResponse{
		Attributes: w3c.CredentialSubject,
		CreatedAt:  *w3c.IssuanceDate,
		Expired:    expired,
		ExpiresAt:  w3c.Expiration,
		Id:         credential.ID,
		ProofTypes: proofs,
		RevNonce:   uint64(credential.RevNonce),
		Revoked:    credential.Revoked,
		SchemaHash: credential.SchemaHash,
		SchemaType: credential.SchemaType,
	}
}
