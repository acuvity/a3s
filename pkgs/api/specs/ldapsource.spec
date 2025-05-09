# Model
model:
  rest_name: ldapsource
  resource_name: ldapsources
  entity_name: LDAPSource
  friendly_name: LDAPSource
  package: a3s
  group: authn/source
  description: Defines a remote LDAP to use as an authentication source.
  get:
    description: Retrieves the ldap source with the given ID.
  update:
    description: Updates the ldap source with the given ID.
  delete:
    description: Deletes the ldap source with the given ID.
  extends:
  - '@sharded'
  - '@identifiable'
  - '@importable'
  - '@timed'
  - '@claimfilter'

# Indexes
indexes:
- - namespace
  - name

# Attributes
attributes:
  v1:
  - name: CA
    friendly_name: CA
    description: |-
      Can be left empty if the LDAP server's certificate is signed by a public,
      trusted certificate authority. Otherwise, include the public key of the
      certificate authority that signed the LDAP server's certificate.
    type: string
    exposed: true
    stored: true
    example_value: |-
      -----BEGIN CERTIFICATE-----
      MIIBPzCB5qADAgECAhEAwbx3c+QW24ePXyD94geytzAKBggqhkjOPQQDAjAPMQ0w
      CwYDVQQDEwR0b3RvMB4XDTE5MDIyMjIzNDA1MFoXDTI4MTIzMTIzNDA1MFowDzEN
      MAsGA1UEAxMEdG90bzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJi6CwRDeKks
      Xb3pDEslmFGR7k9Aeh5RK+XmdqKKPGb3NQWEFPGolnqOR34iVuf7KSxTuzaaVWfu
      XEa94faUQEqjIzAhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAoG
      CCqGSM49BAMCA0gAMEUCIQD+nL9RF9EvQXHyYuJ31Lz9yWd9hsK91stnpAs890gS
      /AIgQIKjBBpiyQNZZWso5H04qke9QYMVPegiQQufFFBj32c=
      -----END CERTIFICATE-----
    omit_empty: true

  - name: address
    friendly_name: Address
    description: IP address or FQDN of the LDAP server.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: ldap.company.com

  - name: baseDN
    friendly_name: BaseDN
    description: The base distinguished name (DN) to use for LDAP queries.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: dc=universe,dc=io

  - name: bindDN
    friendly_name: BindDN
    description: The DN to use to bind to the LDAP server.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: cn=readonly,dc=universe,dc=io

  - name: bindPassword
    friendly_name: BindPassword
    description: Password to be used with the `bindDN` to authenticate to the LDAP
      server.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: s3cr3t
    secret: true
    transient: true
    encrypted: true

  - name: bindSearchFilter
    friendly_name: BindSearchFilter
    description: |-
      The filter to use to locate the relevant user accounts. For Windows-based
      systems, the value may be `sAMAccountName={USERNAME}`. For Linux and other
      systems, the value may be `uid={USERNAME}`.
    type: string
    exposed: true
    stored: true
    default_value: uid={USERNAME}
    orderable: true

  - name: description
    friendly_name: Description
    description: The description of the object.
    type: string
    exposed: true
    stored: true

  - name: modifier
    friendly_name: Modifier
    description: |-
      Contains optional information about a remote service that can be used to modify
      the claims that are about to be delivered using this authentication source.
    type: ref
    exposed: true
    subtype: identitymodifier
    stored: true
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: name
    friendly_name: Name
    description: The name of the source.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: mypki

  - name: securityProtocol
    friendly_name: SecurityProtocol
    description: Specifies the connection type for the LDAP provider.
    type: enum
    exposed: true
    stored: true
    allowed_choices:
    - TLS
    - InbandTLS
    - None
    default_value: TLS
