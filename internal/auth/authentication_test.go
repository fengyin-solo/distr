package auth_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/distr-sh/distr/internal/auth"
	"github.com/distr-sh/distr/internal/authjwt"
	"github.com/distr-sh/distr/internal/env"
	"github.com/distr-sh/distr/internal/types"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	. "github.com/onsi/gomega"
)

func TestMain(m *testing.M) {
	// These are the variables env.Initialize requires when no key management service is
	// configured; only JWT_SECRET is touched while authenticating these requests.
	os.Setenv("DATABASE_URL", "postgres://localhost")
	os.Setenv("DATABASE_ENCRYPTION_KEY", "not-used-in-tests")
	os.Setenv("JWT_SECRET", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	os.Setenv("DISTR_HOST", "localhost")
	os.Setenv("LOKI_URL", "http://localhost")
	env.Initialize()
	os.Exit(m.Run())
}

func userToken(t *testing.T) string {
	t.Helper()
	verifiedAt := time.Now()
	user := types.UserAccount{ID: uuid.New(), Email: "jane@example.com", EmailVerifiedAt: &verifiedAt}
	org := types.OrganizationWithUserRole{
		Organization: types.Organization{ID: uuid.New()},
		UserRole:     types.UserRoleAdmin,
	}
	_, token, err := authjwt.GenerateDefaultToken(user, org)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func controllerToken(t *testing.T) string {
	t.Helper()
	_, token, err := authjwt.GenerateControllerTokenValidFor(uuid.New(), uuid.New(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// otherAudienceToken is signed with the server's own HS256 secret, so signature and timing
// checks pass and the audience claim is the only thing a verifier can reject it on.
func otherAudienceToken(t *testing.T, audience string) string {
	t.Helper()
	key, err := jwk.Import[jwk.SymmetricKey](env.JWTSecret())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := jwt.NewBuilder().
		Subject(uuid.NewString()).
		Audience([]string{audience}).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestControllerAuthenticationAudience(t *testing.T) {
	serve := func(token string) *httptest.ResponseRecorder {
		served := false
		handler := auth.ControllerAuthentication.Middleware(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true }),
		)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if (w.Code == http.StatusOK) != served {
			t.Fatalf("served=%v but status=%v", served, w.Code)
		}
		return w
	}

	t.Run("a controller token authenticates", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(serve(controllerToken(t)).Code).To(Equal(http.StatusOK))
	})

	for _, tt := range []struct {
		name  string
		token string
	}{
		{name: "a user token is refused", token: userToken(t)},
		{name: "a license-key token is refused", token: otherAudienceToken(t, "license-key")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(serve(tt.token).Code).To(Equal(http.StatusUnauthorized))
		})
	}
}

func TestArtifactsAuthenticationAudience(t *testing.T) {
	serve := func(setAuth func(*http.Request)) *httptest.ResponseRecorder {
		handler := auth.ArtifactsAuthentication.Middleware(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		)
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		setAuth(req)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	t.Run("a user token presented as Basic credentials is refused before the database is read", func(t *testing.T) {
		g := NewWithT(t)
		token := userToken(t)
		w := serve(func(r *http.Request) { r.SetBasicAuth("-", token) })
		g.Expect(w.Code).To(Equal(http.StatusUnauthorized))
	})

	t.Run("a license-key token presented as Basic credentials is refused", func(t *testing.T) {
		g := NewWithT(t)
		token := otherAudienceToken(t, "license-key")
		w := serve(func(r *http.Request) { r.SetBasicAuth("-", token) })
		g.Expect(w.Code).To(Equal(http.StatusUnauthorized))
	})

	t.Run("a user token presented as a registry Bearer token is refused", func(t *testing.T) {
		g := NewWithT(t)
		token := userToken(t)
		w := serve(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) })
		g.Expect(w.Code).To(Equal(http.StatusUnauthorized))
	})
}
