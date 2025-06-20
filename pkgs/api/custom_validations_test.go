package api

import (
	"fmt"
	"testing"
)

func TestValidateCIDR(t *testing.T) {
	type args struct {
		attribute string
		network   string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"valid cidr",
			func(*testing.T) args {
				return args{
					"attr",
					"10.0.1.0/24",
				}
			},
			false,
			nil,
		},
		{
			"invalid cidr",
			func(*testing.T) args {
				return args{
					"attr",
					"10.0.1.024",
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: Attribute 'attr' must be a CIDR"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err)
					t.Fail()
				}
			},
		},
		{
			"empty cidr",
			func(*testing.T) args {
				return args{
					"attr",
					"",
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: Attribute 'attr' must be a CIDR"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err)
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateCIDR(tArgs.attribute, tArgs.network)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCIDR error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateCIDROptional(t *testing.T) {
	type args struct {
		attribute string
		network   string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"valid cidr",
			func(*testing.T) args {
				return args{
					"attr",
					"10.0.1.0/24",
				}
			},
			false,
			nil,
		},
		{
			"invalid cidr",
			func(*testing.T) args {
				return args{
					"attr",
					"10.0.1.024",
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: Attribute 'attr' must be a CIDR"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err)
					t.Fail()
				}
			},
		},
		{
			"empty cidr",
			func(*testing.T) args {
				return args{
					"attr",
					"",
				}
			},
			false,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateCIDROptional(tArgs.attribute, tArgs.network)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCIDROptional error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateCIDRList(t *testing.T) {
	type args struct {
		attribute string
		networks  []string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"valid cidr",
			func(*testing.T) args {
				return args{
					"attr",
					[]string{"10.0.1.0/24", "11.0.1.0/24"},
				}
			},
			false,
			nil,
		},
		{
			"invalid cidr",
			func(*testing.T) args {
				return args{
					"attr",
					[]string{"10.0.1.0/24", "11.0.1.024"},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: Attribute 'attr' must be a CIDR"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err)
					t.Fail()
				}
			},
		},
		{
			"empty cidr",
			func(*testing.T) args {
				return args{
					"attr",
					nil,
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: Attribute 'attr' must not be empty"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err)
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateCIDRList(tArgs.attribute, tArgs.networks)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCIDRList error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateCIDRListOptional(t *testing.T) {
	type args struct {
		attribute string
		networks  []string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"valid cidr",
			func(*testing.T) args {
				return args{
					"attr",
					[]string{"10.0.1.0/24", "11.0.1.0/24"},
				}
			},
			false,
			nil,
		},
		{
			"invalid cidr",
			func(*testing.T) args {
				return args{
					"attr",
					[]string{"10.0.1.0/24", "11.0.1.024"},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: Attribute 'attr' must be a CIDR"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err)
					t.Fail()
				}
			},
		},
		{
			"empty cidr",
			func(*testing.T) args {
				return args{
					"attr",
					nil,
				}
			},
			false,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateCIDRListOptional(tArgs.attribute, tArgs.networks)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCIDRListOptional error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateTagsExpression(t *testing.T) {
	type args struct {
		attribute  string
		expression [][]string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"empty tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{},
				}
			},
			false,
			nil,
		},
		{
			"half empty tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{nil, nil},
				}
			},
			false,
			nil,
		},
		{
			"nil tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					nil,
				}
			},
			false,
			nil,
		},
		{
			"valid tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"a=a", "b=b"}, {"c=c"}},
				}
			},
			false,
			nil,
		},
		{
			"too long tag expression",
			func(*testing.T) args {
				long := make([]byte, 1025)
				return args{
					"attr",
					[][]string{{string(long), "b=b"}, {"c=c"}},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := fmt.Sprintf("error 422 (a3s): Validation Error: '%s' must be less than 1024 bytes", make([]byte, 1025))
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"invalid tag expression",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"aa", "b=b"}, {"c=c"}},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'aa' must contain at least one '=' symbol separating two valid words"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"double equal",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"a=b=c"}},
				}
			},
			false,
			nil,
		},
		{
			"space before first equal",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"a =b=c"}},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'a =b=c' must contain at least one '=' symbol separating two valid words"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"space after first equal",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"a= b=c"}},
				}
			},
			false,
			nil,
		},
		{
			"missing key",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"=c"}},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: '=c' must contain at least one '=' symbol separating two valid words"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"missing value",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"a="}},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'a=' must contain at least one '=' symbol separating two valid words"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"only equal",
			func(*testing.T) args {
				return args{
					"attr",
					[][]string{{"="}},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: '=' must contain at least one '=' symbol separating two valid words"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},

		{
			"valid subject",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{"@auth:realm=certificate", "@auth:claim=a"},
						{"@auth:realm=vince", "@auth:claim=a", "@auth:claim=b"},
					},
				}
			},
			false,
			nil,
		},
		{
			"broken tag with no equal",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{"@auth:realm=saml", "@auth:claim"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: '@auth:claim' must contain at least one '=' symbol separating two valid words"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"broken tag with no value",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{"@auth:realm=saml", "@auth:claim="},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: '@auth:claim=' must contain at least one '=' symbol separating two valid words"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"tag with leading spaces",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{" leading=space"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: ' leading=space' must not contain any leading or trailing spaces"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"tag with trailing spaces",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{"trailing=space "},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'trailing=space ' must not contain any leading or trailing spaces"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"tag with leading tab",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{"\tleading=space"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: '\tleading=space' must not contain any leading or trailing spaces"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"tag with trailing spaces",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{"trailing=space\t"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'trailing=space\t' must not contain any leading or trailing spaces"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"tag with leading CR",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{"\nleading=space"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: '\nleading=space' must not contain any leading or trailing spaces"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
		{
			"tag with trailing CR",
			func(*testing.T) args {
				return args{
					"subject",
					[][]string{
						{"trailing=space\r"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				wanted := "error 422 (a3s): Validation Error: 'trailing=space\r' must not contain any leading or trailing spaces"
				if err.Error() != wanted {
					t.Logf("wanted %s but got %s", wanted, err.Error())
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateTagsExpression(tArgs.attribute, tArgs.expression)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTagsExpression error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidatePEM(t *testing.T) {
	type args struct {
		attribute string
		pemdata   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"nothing set",
			args{
				"pem",
				``,
			},
			false,
		},
		{
			"valid single PEM",
			args{
				"pem",
				`-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5loNahC19hQtExCi64fmI3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----`,
			},
			false,
		},
		{
			"valid single PEM",
			args{
				"pem",
				`-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5loNahC19hQtExCi64fmI3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5loNahC19hQtExCi64fmI3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----
`,
			},
			false,
		},
		{
			"invalid single PEM",
			args{
				"pem",
				`-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoT ----NOT PEM---- I3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----`,
			},
			true,
		},
		{
			"valid single PEM",
			args{
				"pem",
				`-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5loNahC19hQtExCi64fmI3QCcrEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIQDbXKAZzk9RjcNSGMsWke1zAKBggqhkjOPQQDAjBGMRAw
DgYDVQQKEwdBcG9yZXRvMQ8wDQYDVQQLEwZhcG9tdXgxITAfBgNVBAMTGEFwb211
eCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xOTAxMjQyMjQ3MjlaFw0yODEyMDIyMjQ3
MjlaMCoxEjAQBgNVBAoTCXNlcGhpcm90aDEUMBIGA1UEAxMLYXV0b21hdGlvbnMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxKA9vbyk7FXXlOCi0kTKLVne/mK8o
ZQDPRcehze0EMwTAR5     ----NOT PEM----   crEGH9ycUoITYPgozUwMzAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIw
ADAKBggqhkjOPQQDAgNJADBGAiEAm1u2T1vRooIy3rd0BmBSAa6WR6BtHl9nDbGN
1ZM+SgsCIQDu4R6OziiWbRdn50bneZT5qPO+07ALY5m4DG96VyCaQw==
-----END CERTIFICATE-----
`,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePEM(tt.args.attribute, tt.args.pemdata); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePEM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIssue(t *testing.T) {
	type args struct {
		iss *Issue
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"test token missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeA3S,
						InputA3S:   nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test token present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeA3S,
						InputA3S:   &IssueA3S{},
					},
				}
			},
			false,
			nil,
		},
		{
			"test remote token missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType:     IssueSourceTypeRemoteA3S,
						InputRemoteA3S: nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test refresh token with a3s source",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeA3S,
						InputA3S:   &IssueA3S{},
						TokenType:  IssueTokenTypeRefresh,
					},
				}
			},
			true,
			nil,
		},
		{
			"test remote token present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType:     IssueSourceTypeRemoteA3S,
						InputRemoteA3S: &IssueRemoteA3S{},
					},
				}
			},
			false,
			nil,
		},
		{
			"test aws missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeAWS,
						InputAWS:   nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test aws present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeAWS,
						InputAWS:   &IssueAWS{},
					},
				}
			},
			false,
			nil,
		},
		{
			"test ldap missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeLDAP,
						InputLDAP:  nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test ldap present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeLDAP,
						InputLDAP:  &IssueLDAP{},
					},
				}
			},
			false,
			nil,
		},
		{
			"test gcp missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeGCP,
						InputGCP:   nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test gcp present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeGCP,
						InputGCP:   &IssueGCP{},
					},
				}
			},
			false,
			nil,
		},
		{
			"test azure missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeAzure,
						InputAzure: nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test azure present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeAzure,
						InputAzure: &IssueAzure{},
					},
				}
			},
			false,
			nil,
		},
		{
			"test oidc missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeOIDC,
						InputOIDC:  nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test oidc present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeOIDC,
						InputOIDC:  &IssueOIDC{},
					},
				}
			},
			false,
			nil,
		},
		{
			"test http missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeHTTP,
						InputHTTP:  nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test http present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeHTTP,
						InputHTTP:  &IssueHTTP{},
					},
				}
			},
			false,
			nil,
		},
		{
			"test saml missing",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeSAML,
						InputHTTP:  nil,
					},
				}
			},
			true,
			nil,
		},
		{
			"test saml present",
			func(*testing.T) args {
				return args{
					&Issue{
						SourceType: IssueSourceTypeSAML,
						InputSAML:  &IssueSAML{},
					},
				}
			},
			false,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateIssue(tArgs.iss)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateIssue error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateDuration(t *testing.T) {
	type args struct {
		attribute string
		duration  string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"valid",
			func(*testing.T) args {
				return args{
					"attr",
					"10s",
				}
			},
			false,
			nil,
		},
		{
			"invalid",
			func(*testing.T) args {
				return args{
					"attr",
					"dog",
				}
			},
			true,
			nil,
		},
		{
			"empty",
			func(*testing.T) args {
				return args{
					"attr",
					"",
				}
			},
			false,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateDuration(tArgs.attribute, tArgs.duration)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateDuration error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	type args struct {
		attribute string
		u         string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"valid url",
			func(t *testing.T) args {
				return args{
					"attr",
					"https://toto.com",
				}
			},
			false,
			nil,
		},
		{
			"invalid url",
			func(t *testing.T) args {
				return args{
					"attr",
					"wesh",
				}
			},
			true,
			nil,
		},
		{
			"invalid url 2",
			func(t *testing.T) args {
				return args{
					"attr",
					"",
				}
			},
			true,
			nil,
		},
		{
			"invalid url 3",
			func(t *testing.T) args {
				return args{
					"attr",
					"http##dd%",
				}
			},
			true,
			nil,
		},
		{
			"invalid scheme",
			func(t *testing.T) args {
				return args{
					"attr",
					"ftp://what.com",
				}
			},
			true,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateURL(tArgs.attribute, tArgs.u)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateURL error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateSAMLSource(t *testing.T) {
	type args struct {
		source *SAMLSource
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"nothing is set",
			func(*testing.T) args {
				return args{
					&SAMLSource{},
				}
			},
			true,
			nil,
		},

		{
			"metadata URL is set",
			func(*testing.T) args {
				return args{
					&SAMLSource{
						IDPMetadataURL: "https://coucou.com",
					},
				}
			},
			false,
			nil,
		},
		{
			"metadata URL is set",
			func(*testing.T) args {
				return args{
					&SAMLSource{
						IDPMetadataURL: "https://coucou.com",
						IDPMetadata:    "coucou",
					},
				}
			},
			true,
			nil,
		},
		{
			"metadata is set",
			func(*testing.T) args {
				return args{
					&SAMLSource{
						IDPMetadata: "hello",
					},
				}
			},
			false,
			nil,
		},

		{
			"metadata is not set but all other fields are",
			func(*testing.T) args {
				return args{
					&SAMLSource{
						IDPURL:         "https://url.com",
						IDPIssuer:      "issuer",
						IDPCertificate: "this is a cert, trust me",
					},
				}
			},
			false,
			nil,
		},
		{
			"metadata is not set and we miss IDPURL",
			func(*testing.T) args {
				return args{
					&SAMLSource{
						IDPIssuer:      "issuer",
						IDPCertificate: "this is a cert, trust me",
					},
				}
			},
			true,
			nil,
		},
		{
			"metadata is not set and we miss IDPIssuer",
			func(*testing.T) args {
				return args{
					&SAMLSource{
						IDPURL:         "https://url.com",
						IDPCertificate: "this is a cert, trust me",
					},
				}
			},
			true,
			nil,
		},
		{
			"metadata is not set and we miss IDPCertificate",
			func(*testing.T) args {
				return args{
					&SAMLSource{
						IDPURL:    "https://url.com",
						IDPIssuer: "issuer",
					},
				}
			},
			true,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateSAMLSource(tArgs.source)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSAMLSource error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestValidateKeys(t *testing.T) {
	type args struct {
		attribute string
		keys      []string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"ok",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					keys:      []string{"a", "b"},
				}
			},
			false,
			nil,
		},
		{
			"empty",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					keys:      []string{},
				}
			},
			false,
			nil,
		},
		{
			"nil",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					keys:      nil,
				}
			},
			false,
			nil,
		},
		{
			"leading",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					keys:      []string{"ok", " ba"},
				}
			},
			true,
			nil,
		},
		{
			"trailing",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					keys:      []string{"ok", "ba "},
				}
			},
			true,
			nil,
		},
		{
			"leading & trailing",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					keys:      []string{"ok", " ba "},
				}
			},
			true,
			nil,
		},
		{
			"middle",
			func(*testing.T) args {
				return args{
					attribute: "attr",
					keys:      []string{"ok", "b a"},
				}
			},
			false,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			err := ValidateKeys(tArgs.attribute, tArgs.keys)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateKeys error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}
