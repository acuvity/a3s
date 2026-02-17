package netsafe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/karlseguin/ccache/v3"
)

// IANAPrivateNetworks represents the list of restricted subnets,
// per IANA definition.
var IANAPrivateNetworks = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"233.252.0.0/24",
	"240.0.0.0/4",
}

// ErrRestricted represents a restricted IP error.
// It it returned by a Checker function.
type ErrRestricted struct {
	Err error
}

// Error implements the error interface.
func (e ErrRestricted) Error() string {
	return fmt.Sprintf("restricted IP: %s", e.Err)
}

// Unwrap implements the error interface.
func (e ErrRestricted) Unwrap() error {
	return e.Err
}

// A Checker is a function that can be used to check if the given
// hostnames resolves to IPs in a restricted network.
type Checker func(hostname string) error

// A Checker is a function that can be used to check if the given
// hostnames resolves to IPs in a restricted network.
type RequestMaker func(context.Context, string, string, io.Reader) (*http.Request, error)

// MakeChecker returns a Checker function that will check
// against the given list of networks. If a subnet in the ignore list
// matches one of the networks, it is ignored.
func MakeChecker(networks []string, ignored []string) (Checker, error) {

	restrictedNetworks := make([]*net.IPNet, len(networks))
	ignoredNetworks := make([]*net.IPNet, len(ignored))

	for i, n := range networks {
		_, netw, err := net.ParseCIDR(n)
		if err != nil {
			return nil, fmt.Errorf("unable to parse network '%s': %w", n, err)
		}
		restrictedNetworks[i] = netw
	}

	for i, n := range ignored {
		_, netw, err := net.ParseCIDR(n)
		if err != nil {
			return nil, fmt.Errorf("unable to parse ignored network '%s': %w", n, err)
		}
		ignoredNetworks[i] = netw
	}

	cache := ccache.New(ccache.Configure[error]().MaxSize(1024))

	return func(host string) error {

		if item := cache.Get(host); item != nil && !item.Expired() {
			return item.Value()
		}

		hh := host
		if strings.Contains(host, ":") {
			hh, _, _ = net.SplitHostPort(host)
		}

		addrs, err := net.LookupHost(hh)
		if err != nil {
			return fmt.Errorf("unable to lookup host '%s': %w", hh, err)
		}

		ips := []net.IP{}
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil {
				return fmt.Errorf("unable to parse IP '%s' (from host '%s'): %w", a, hh, err)
			}
			ips = append(ips, ip)
		}

		for _, network := range restrictedNetworks {
		L:
			for _, ip := range ips {
				if network.Contains(ip) {

					// now we check if it's not in an ignored network
					for _, ign := range ignoredNetworks {
						if ign.Contains(ip) {
							continue L
						}
					}

					err := ErrRestricted{Err: fmt.Errorf("restricted IP '%s'", ip)}
					cache.Set(host, err, time.Hour)
					return err
				}
			}
		}

		cache.Set(host, nil, time.Hour)

		return nil
	}, nil
}

// NewRequestMaker returns a function that can be used to create *http.Request with URL that must conform with the given Checker.
// If checker is nil, a default one will be created and will forbid access to IANAPrivateNetworks.
func NewRequestMaker(checker Checker) RequestMaker {

	if checker == nil {

		ch, err := MakeChecker(IANAPrivateNetworks, nil)
		if err != nil {
			panic(err)
		}
		checker = ch
	}

	return func(ctx context.Context, method string, urlString string, body io.Reader) (*http.Request, error) {

		u, err := url.Parse(urlString)

		if err != nil {
			return nil, fmt.Errorf("unable to parse url: %w", err)
		}

		if err = checker(u.Hostname()); err != nil {
			return nil, fmt.Errorf("unacceptable url hostname: %w", err)
		}

		return http.NewRequestWithContext(ctx, method, urlString, body)
	}
}
