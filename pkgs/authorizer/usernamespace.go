package authorizer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"runtime"

	"go.aporeto.io/a3s/pkgs/api"
	"go.aporeto.io/elemental"
	"go.aporeto.io/manipulate"
	"go.aporeto.io/manipulate/maniphttp"
)

func createUserNamespaceIfNeeded(m manipulate.Manipulator, user string) error {

	mctx := manipulate.NewContext(context.Background(),
		manipulate.ContextOptionFilter(
			elemental.NewFilterComposer().
				WithKey("name").Equals("/users/"+user).
				Done(),
		),
	)

	c, err := m.Count(mctx, api.NamespaceIdentity)

	if err != nil {
		fmt.Println("reached 1")

		return fmt.Errorf("unable to check if user namespace exists: %w", err)
	}

	if c == 1 {
		fmt.Println("namespace already exists")

		return nil
	}

	if c > 1 {
		fmt.Println("reached 3")

		return errors.New("more than one namespace / found for user" + user)
	}

	ns := api.NewNamespace()
	ns.Name = user

	mctx = manipulate.NewContext(context.Background(), manipulate.ContextOptionNamespace("/users"))
	if err := m.Create(mctx, ns); err != nil {
		fmt.Println("reached 6")
		return fmt.Errorf("unable to create user %s namespace: %w", user, err)

	}

	return nil
}

// prepareAPICACertPool prepares the API cert pool if not empty.
func prepareAPICACertPool(capath string) (*x509.CertPool, error) {

	if capath == "" {
		if runtime.GOOS == "windows" {
			// use nil as RootCAs on Windows in order to call systemVerify,
			// which will work even if Windows has not cached all its root certs.
			return nil, nil
		}
		return x509.SystemCertPool()
	}

	capool := x509.NewCertPool()
	cadata, err := os.ReadFile(capath)
	if err != nil {
		return nil, err
	}

	capool.AppendCertsFromPEM(cadata)

	return capool, nil
}

func getManipulator() (manipulate.Manipulator, error) {

	api := "https://localhost:3443"
	token := "blah"
	namespace := "/users"
	capath := "../../dev/data/certificates/services-cert.pem" // services/ca-root
	skip := true
	enc := elemental.EncodingTypeJSON

	rootCAPool, err := prepareAPICACertPool(capath)
	if err != nil {
		return nil, fmt.Errorf("unable to load root ca pool: %s", err)
	}

	/* #nosec */
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skip,
		RootCAs:            rootCAPool,
	}

	opts := []maniphttp.Option{
		maniphttp.OptionNamespace(namespace),
		maniphttp.OptionTLSConfig(tlsConfig),
		maniphttp.OptionEncoding(enc),
		maniphttp.OptionToken(token),
	}

	return maniphttp.New(
		context.Background(),
		api,
		opts...,
	)
}

func getEmailClaim(claims []string) *string {
	// get email
	return nil
}

func checkAndCreateUserNamespaaceIfNeeded(claims []string) error {
	email := getEmailClaim(claims)
	if email == nil {
		return nil
	}
	m, err := getManipulator()
	if err != nil {
		return err
	}

	return createUserNamespaceIfNeeded(m, *email)
}
