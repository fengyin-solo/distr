package authjwt_test

import (
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/distr-sh/distr/internal/authjwt"
	"github.com/distr-sh/distr/internal/authn/authinfo"
	"github.com/distr-sh/distr/internal/env"
	"github.com/distr-sh/distr/internal/types"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	. "github.com/onsi/gomega"
)

func TestMain(m *testing.M) {
	// env.Initialize is what populates the JWT signing key; these are the variables it requires
	// when no key management service is configured, and none of them is used while parsing JWTs.
	os.Setenv("DATABASE_URL", "postgres://localhost")
	os.Setenv("DATABASE_ENCRYPTION_KEY", "not-used-in-tests")
	os.Setenv("JWT_SECRET", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	os.Setenv("DISTR_HOST", "localhost")
	os.Setenv("LOKI_URL", "http://localhost")
	env.Initialize()
	os.Exit(m.Run())
}

// signToken mints an HS256-signed token, unless alg is overridden to simulate another issuer,
// using the same secret the server signs its own tokens with. A valid signature is therefore
// never what a negative case is missing: the audience binding is.
func signToken(g *WithT, alg jwa.KeyAlgorithm, build func(*jwt.Builder)) string {
	key, err := jwk.Import[jwk.SymmetricKey](env.JWTSecret())
	g.Expect(err).ToNot(HaveOccurred())
	builder := jwt.NewBuilder().
		Subject(uuid.NewString()).
		IssuedAt(time.Now()).
		NotBefore(time.Now()).
		Expiration(time.Now().Add(time.Hour))
	build(builder)
	token, err := builder.Build()
	g.Expect(err).ToNot(HaveOccurred())
	signed, err := jwt.Sign(token, jwt.WithKey(alg, key))
	g.Expect(err).ToNot(HaveOccurred())
	return string(signed)
}

func withAudience(audience ...string) func(*jwt.Builder) {
	return func(b *jwt.Builder) { b.Audience(audience) }
}

func TestVerifyUserToken(t *testing.T) {
	g := NewWithT(t)

	userID := uuid.New()
	orgID := uuid.New()
	partnerOrgID := uuid.New()
	user := types.UserAccount{ID: userID, Name: "Jane", Email: "jane@example.com", EmailVerifiedAt: &time.Time{}}
	org := types.OrganizationWithUserRole{
		Organization:          types.Organization{ID: orgID},
		UserRole:              types.UserRoleAdmin,
		PartnerOrganizationID: &partnerOrgID,
	}

	_, userToken, err := authjwt.GenerateDefaultToken(user, org)
	g.Expect(err).ToNot(HaveOccurred())

	t.Run("a user token passes and keeps subject and organization claims", func(t *testing.T) {
		g := NewWithT(t)
		parsed, err := authjwt.VerifyUserToken(userToken)
		g.Expect(err).ToNot(HaveOccurred())

		info, err := authinfo.FromUserJWT(parsed)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(info.CurrentUserID()).To(Equal(userID))
		g.Expect(info.CurrentOrgID()).To(Equal(&orgID))
		g.Expect(info.CurrentPartnerOrgID()).To(Equal(&partnerOrgID))
		g.Expect(*info.CurrentUserRole()).To(Equal(types.UserRoleAdmin))
	})

	t.Run("scoped user tokens are still user audience", func(t *testing.T) {
		g := NewWithT(t)
		_, resetToken, err := authjwt.GenerateResetToken(user)
		g.Expect(err).ToNot(HaveOccurred())
		parsed, err := authjwt.VerifyUserToken(resetToken)
		g.Expect(err).ToNot(HaveOccurred())

		info, err := authinfo.FromUserJWT(parsed)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(info.CurrentUserID()).To(Equal(userID))
		g.Expect(info.TokenScope()).To(Equal(authjwt.TokenScopePasswordReset))
	})

	for _, tt := range []struct {
		name  string
		token string
	}{
		{
			name:  "a controller audience is refused on the user chain",
			token: signToken(g, jwa.HS256(), withAudience(authjwt.AudienceController)),
		},
		{
			name:  "a license-key audience is refused on the user chain",
			token: signToken(g, jwa.HS256(), withAudience("license-key")),
		},
		{
			name:  "a token without audience is refused on the user chain",
			token: signToken(g, jwa.HS256(), func(*jwt.Builder) {}),
		},
		{
			name:  "a token signed with another algorithm is refused on the user chain",
			token: signToken(g, jwa.HS384(), withAudience(authjwt.AudienceUser)),
		},
		{
			name: "an expired token is refused on the user chain",
			token: signToken(g, jwa.HS256(), func(b *jwt.Builder) {
				b.Audience([]string{authjwt.AudienceUser}).
					IssuedAt(time.Now().Add(-2 * time.Hour)).
					NotBefore(time.Now().Add(-2 * time.Hour)).
					Expiration(time.Now().Add(-time.Hour))
			}),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := authjwt.VerifyUserToken(tt.token)
			g.Expect(err).To(HaveOccurred())
		})
	}
}

func TestVerifyControllerToken(t *testing.T) {
	g := NewWithT(t)

	targetID := uuid.New()
	orgID := uuid.New()
	_, controllerToken, err := authjwt.GenerateControllerTokenValidFor(targetID, orgID, time.Hour)
	g.Expect(err).ToNot(HaveOccurred())

	t.Run("a controller token passes and keeps subject and organization claims", func(t *testing.T) {
		g := NewWithT(t)
		parsed, err := authjwt.VerifyControllerToken(controllerToken)
		g.Expect(err).ToNot(HaveOccurred())

		info, err := authinfo.FromControllerJWT(parsed)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(info.CurrentDeploymentTargetID()).To(Equal(targetID))
		g.Expect(info.CurrentOrgID()).To(Equal(orgID))
	})

	t.Run("an old controller token carrying the agent audience still passes", func(t *testing.T) {
		g := NewWithT(t)
		// Tokens issued before the rename to controller carry the literal "agent" audience, which
		// is the same value freshly issued tokens keep using.
		legacyToken := signToken(g, jwa.HS256(), func(b *jwt.Builder) {
			b.Subject(targetID.String()).
				Audience([]string{"agent"}).
				Claim(authjwt.OrgIdKey, orgID.String())
		})
		parsed, err := authjwt.VerifyControllerToken(legacyToken)
		g.Expect(err).ToNot(HaveOccurred())

		info, err := authinfo.FromControllerJWT(parsed)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(info.CurrentDeploymentTargetID()).To(Equal(targetID))
		g.Expect(info.CurrentOrgID()).To(Equal(orgID))
	})

	for _, tt := range []struct {
		name  string
		token string
	}{
		{
			name:  "a user audience is refused on the controller chain",
			token: signToken(g, jwa.HS256(), withAudience(authjwt.AudienceUser)),
		},
		{
			name:  "a license-key audience is refused on the controller chain",
			token: signToken(g, jwa.HS256(), withAudience("license-key")),
		},
		{
			name:  "a token without audience is refused on the controller chain",
			token: signToken(g, jwa.HS256(), func(*jwt.Builder) {}),
		},
		{
			name:  "a token signed with another algorithm is refused on the controller chain",
			token: signToken(g, jwa.HS384(), withAudience(authjwt.AudienceController)),
		},
		{
			name: "an expired token is refused on the controller chain",
			token: signToken(g, jwa.HS256(), func(b *jwt.Builder) {
				b.Audience([]string{authjwt.AudienceController}).
					IssuedAt(time.Now().Add(-2 * time.Hour)).
					NotBefore(time.Now().Add(-2 * time.Hour)).
					Expiration(time.Now().Add(-time.Hour))
			}),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := authjwt.VerifyControllerToken(tt.token)
			g.Expect(err).To(HaveOccurred())
		})
	}
}
