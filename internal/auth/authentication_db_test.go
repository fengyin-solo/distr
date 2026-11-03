package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/distr-sh/distr/internal/auth"
	"github.com/distr-sh/distr/internal/authjwt"
	internalctx "github.com/distr-sh/distr/internal/context"
	"github.com/distr-sh/distr/internal/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	. "github.com/onsi/gomega"
)

func TestArtifactsAuthenticationControllerSuccess(t *testing.T) {
	targetID := uuid.New()
	orgID := uuid.New()
	fixture := &deploymentTargetDBFixture{targetID: targetID, orgID: orgID}

	serve := func(t *testing.T, setAuth func(*http.Request)) *httptest.ResponseRecorder {
		t.Helper()
		served := false
		handler := auth.ArtifactsAuthentication.Middleware(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				principal, ok := auth.ArtifactsPrincipal(r.Context())
				if !ok {
					t.Fatal("artifact principal is missing")
				}
				if got := principal.CurrentDeploymentTargetID(); got == nil || *got != targetID {
					t.Fatalf("deployment target id = %v, want %s", got, targetID)
				}
				if got := principal.CurrentOrgID(); got == nil || *got != orgID {
					t.Fatalf("organization id = %v, want %s", got, orgID)
				}
				served = true
				w.WriteHeader(http.StatusNoContent)
			}),
		)
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		req = req.WithContext(internalctx.WithDb(req.Context(), fixture))
		setAuth(req)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if (w.Code == http.StatusNoContent) != served {
			t.Fatalf("served=%v but status=%v", served, w.Code)
		}
		return w
	}

	for _, tt := range []struct {
		name    string
		setAuth func(string, *http.Request)
	}{
		{
			name: "Basic",
			setAuth: func(token string, r *http.Request) {
				r.SetBasicAuth("-", token)
			},
		},
		{
			name: "Bearer",
			setAuth: func(token string, r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+token)
			},
		},
	} {
		t.Run("a valid controller token presented as "+tt.name+" credentials authenticates", func(t *testing.T) {
			g := NewWithT(t)
			_, token, err := authjwt.GenerateControllerTokenValidFor(targetID, orgID, time.Hour)
			g.Expect(err).ToNot(HaveOccurred())
			fixture.queries = 0
			w := serve(t, func(r *http.Request) { tt.setAuth(token, r) })
			g.Expect(w.Code).To(Equal(http.StatusNoContent))
			g.Expect(fixture.queries).To(Equal(1), "the controller database fixture must be read")
		})
	}
}

type deploymentTargetDBFixture struct {
	targetID uuid.UUID
	orgID    uuid.UUID
	queries  int
}

func (f *deploymentTargetDBFixture) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected Exec call")
}

func (f *deploymentTargetDBFixture) Query(
	_ context.Context,
	_ string,
	args ...any,
) (pgx.Rows, error) {
	f.queries++
	if len(args) != 1 {
		return nil, errors.New("expected one named argument")
	}
	named, ok := args[0].(pgx.NamedArgs)
	if !ok {
		return nil, errors.New("expected pgx named arguments")
	}
	if got, _ := named["id"].(uuid.UUID); got != f.targetID {
		return nil, errors.New("unexpected deployment target id")
	}
	return &deploymentTargetRows{orgID: f.orgID, rowNum: -1}, nil
}

func (*deploymentTargetDBFixture) QueryRow(context.Context, string, ...any) pgx.Row {
	return failingDBRow{err: errors.New("unexpected QueryRow call")}
}

func (*deploymentTargetDBFixture) CopyFrom(
	context.Context,
	pgx.Identifier,
	[]string,
	pgx.CopyFromSource,
) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (*deploymentTargetDBFixture) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected Begin call")
}

type deploymentTargetRows struct {
	orgID  uuid.UUID
	rowNum int
	closed bool
}

func (r *deploymentTargetRows) Close() {
	r.closed = true
}

func (r *deploymentTargetRows) Err() error {
	return nil
}

func (*deploymentTargetRows) CommandTag() pgconn.CommandTag {
	return pgconn.CommandTag{}
}

func (*deploymentTargetRows) FieldDescriptions() []pgconn.FieldDescription {
	return make([]pgconn.FieldDescription, 3)
}

func (r *deploymentTargetRows) Next() bool {
	if r.closed || r.rowNum >= 0 {
		r.closed = true
		return false
	}
	r.rowNum = 0
	return true
}

func (r *deploymentTargetRows) Scan(dest ...any) error {
	if len(dest) != 3 {
		return errors.New("expected three scan targets")
	}
	customerTarget, ok := dest[0].(**types.CustomerOrganization)
	if !ok {
		return errors.New("unexpected customer organization scan target")
	}
	orgTarget, ok := dest[1].(*types.Organization)
	if !ok {
		return errors.New("unexpected organization scan target")
	}
	brandingTarget, ok := dest[2].(**types.OrganizationBranding)
	if !ok {
		return errors.New("unexpected organization branding scan target")
	}
	*customerTarget = nil
	*orgTarget = types.Organization{ID: r.orgID}
	*brandingTarget = nil
	return nil
}

func (r *deploymentTargetRows) Values() ([]any, error) {
	return []any{nil, types.Organization{ID: r.orgID}, nil}, nil
}

func (*deploymentTargetRows) RawValues() [][]byte {
	return make([][]byte, 3)
}

func (*deploymentTargetRows) Conn() *pgx.Conn {
	return nil
}

func (*deploymentTargetRows) TypeMap() *pgtype.Map {
	return pgtype.NewMap()
}

type failingDBRow struct {
	err error
}

func (r failingDBRow) Scan(...any) error {
	return r.err
}
