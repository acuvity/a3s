package mtlsissuer

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const certDataWithUPN = `-----BEGIN CERTIFICATE-----
MIIGpTCCBY2gAwIBAgITHAAAAE7qm80lUo3qPwAAAAAATjANBgkqhkiG9w0BAQsF
ADBPMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFzAVBgoJkiaJk/IsZAEZFgdhY3V2
aXR5MR0wGwYDVQQDExRhY3V2aXR5LUFDVS1XSU5EQy1DQTAeFw0yNTExMDUyMTU4
MTNaFw0yNjExMDUyMTU4MTNaMEUxEDAOBgNVBAMTB3BwdXNob3IxMTAvBgkqhkiG
9w0BCQEWInBhdHJpY2tAYWN1dml0eWluYy5vbm1pY3Jvc29mdC5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+kR1etSLxuLbKuSxUSw3mWYioTNPH
4oitGezaF6ZRXJi+aoH9cCIi9gJ6hPuxV8vpz5P8TvCiY6lIKJ3lKhyje1JSsH7Q
cMFFuBoGP1qGpZSq3MkuT3ApZ746BWow0dcvnGgj02pjRkyePF5GD6H6AErx/lid
MsDWPRz4z+vW7aOtn6xNPszTp0hVpBVaDWGp3//k89GOvmoYa2GTAwgVlvIMJiwe
DgYKkV7tLzOX/juvL6Cs2MZe4ToJaoSG64iQDVgZh1MAAaOOEj8wPQrOuvfvfU1h
Lz4FE2yebM7ZRwvFtOwV9svs5H64UvzmzDDRV0j1PV6FaWRy9qEYE41FAgMBAAGj
ggOCMIIDfjA6BgkrBgEEAYI3FQcELTArBiMrBgEEAYI3FQjY1WaC1Ic7jYcsg4Ku
PYGnvA539sAoh5SARgIBZAIBFzApBgNVHSUEIjAgBgorBgEEAYI3CgMEBggrBgEF
BQcDBAYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYw
DAYKKwYBBAGCNwoDBDAKBggrBgEFBQcDBDAKBggrBgEFBQcDAjBEBgkqhkiG9w0B
CQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcw
CgYIKoZIhvcNAwcwHQYDVR0OBBYEFHIfHG8p8VzcFi+51Rd1gk/+9m4vMB8GA1Ud
IwQYMBaAFHgxGbuSj7QrHiUiwxCQ3UTtOHMqMIHWBgNVHR8Egc4wgcswgciggcWg
gcKGgb9sZGFwOi8vL0NOPWFjdXZpdHktQUNVLVdJTkRDLUNBLENOPUFDVS1XSU5E
QyxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
Q049Q29uZmlndXJhdGlvbixEQz1hY3V2aXR5LERDPWxvY2FsP2NlcnRpZmljYXRl
UmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Q
b2ludDCByAYIKwYBBQUHAQEEgbswgbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9D
Tj1hY3V2aXR5LUFDVS1XSU5EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIw
U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1hY3V2aXR5
LERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZp
Y2F0aW9uQXV0aG9yaXR5MFQGA1UdEQRNMEugJQYKKwYBBAGCNxQCA6AXDBVwcHVz
aG9yQGFjdXZpdHkubG9jYWyBInBhdHJpY2tAYWN1dml0eWluYy5vbm1pY3Jvc29m
dC5jb20wTgYJKwYBBAGCNxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIx
LTM3Njg2NjUxNTYtMTg5MjkwOTkxNS0xNzkwNjI3OTAzLTUwMDANBgkqhkiG9w0B
AQsFAAOCAQEAPxX6oUtxFPsZgQQRFpHLytJw+W20mT2xNGl4wiqYvpydJGwAKCfU
9EPFI53Iw87pUlOKLZI0DMW2GVtpcRuXlGD0bZde5rTzaQ85DrpMw/ddiLbkHXin
/+qfwOabILjPsVZa6A17x8l54Rzs/RToGcDVkdPd5LCWuCebTdPnjy2lgPExX05Q
SrYo1UcUfgujrDBNOBn2b9UZQm+tWsU85zI/ynw9SAOhfrlP2Q3y04wV/2FXZHP8
hDDihCrMug7Dy2KhXFzQhwpxWlmnyxR8KYoslTEl/MB51+yk1i0Oi408dWUKvLpb
VW1mExAiXhDtxpaLUZ8HsRIWFqZtSV/psg==
-----END CERTIFICATE-----`

const certDataWithoutUPN = `-----BEGIN CERTIFICATE-----
MIIBrzCCAVWgAwIBAgIQF4fwPIw54/5NZudYHnImiDAKBggqhkjOPQQDAjATMREw
DwYDVQQDEwhjYS1lbnRyYTAeFw0yNTEwMTUxODAzMTBaFw0yNjEwMTAxODAzMTBa
MBkxFzAVBgNVBAMTDkNocmlzIG9uIEVudHJhMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEb4nw8/SjYzXPNJBvmCLUi1WwJprxGKUQyv7F1pKZKnDDNX2lx08olDdj
i026OViKhfBgyN9/YGp/g+j8VUGNiqOBhDCBgTAOBgNVHQ8BAf8EBAMCBaAwEwYD
VR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSGWQQy
7wCtIjpnnNPED+G4/5GZfTArBgNVHREEJDAigSBjaHJpc0BhY3V2aXR5aW5jLm9u
bWljcm9zb2Z0LmNvbTAKBggqhkjOPQQDAgNIADBFAiEA9Sv9bnT2x5cwS8SRl8GP
hJX7AxVrt+AyjuCM8DOPJoYCIDYX+WUkSjJvV6kTZpgELNKm8wfx+xxLkZSYFK3v
unfK
-----END CERTIFICATE-----`

func parse(data []byte) *x509.Certificate {
	block, _ := pem.Decode(data)
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert
}

func Test_getUPNFromCert(t *testing.T) {

	certWithoutUPN := parse([]byte(certDataWithoutUPN))
	certWithUPN := parse([]byte(certDataWithUPN))

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"certificate without UPN should return empty string",
			args{
				certWithoutUPN,
			},
			"",
			false,
		},
		{
			"certificate with UPN should return the correct UPN",
			args{
				certWithUPN,
			},
			"ppushor@acuvity.local",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getUPNFromCert(tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("getUPNFromCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getUPNFromCert() = %v, want %v", got, tt.want)
			}
		})
	}
}
