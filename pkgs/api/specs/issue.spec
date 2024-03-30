# Model
model:
  rest_name: issue
  resource_name: issue
  entity_name: Issue
  friendly_name: Issue
  package: authn
  group: authn/issue
  description: Issues a new a normalized token using various authentication sources.
  validations:
  - $issue

# Attributes
attributes:
  v1:
  - name: audience
    friendly_name: Audience
    description: Requested audience for the delivered token.
    type: list
    exposed: true
    subtype: string
    example_value:
    - https://myfirstapp
    - https://mysecondapp
    omit_empty: true

  - name: claims
    friendly_name: Claims
    description: |-
      The list of claims delivered in the token. This can be useful when the caller
      needs to have information about the user when token is delivered as a secure
      httpOnly cookie.
    type: list
    exposed: true
    subtype: string
    read_only: true
    autogenerated: true
    omit_empty: true

  - name: cloak
    friendly_name: Cloak
    description: |-
      Sets a list of identity claim prefix to allow in the final token. This can be
      used to hide some information when asking for a token as not all systems need to
      know all of the claims.
    type: list
    exposed: true
    subtype: string
    example_value:
    - org=
    - age=
    omit_empty: true

  - name: cookie
    friendly_name: Cookie
    description: If set, return the token as a secure cookie.
    type: boolean
    exposed: true
    omit_empty: true

  - name: cookieDomain
    friendly_name: CookieDomain
    description: If set, use the provided domain for the delivered cookie.
    type: string
    exposed: true
    omit_empty: true

  - name: inputA3S
    friendly_name: InputA3S
    description: Contains additional information for an A3S token source.
    type: ref
    exposed: true
    subtype: issuea3s
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: inputAWS
    friendly_name: InputAWS
    description: Contains additional information for an AWS STS token source.
    type: ref
    exposed: true
    subtype: issueaws
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: inputAzure
    friendly_name: InputAzure
    description: Contains additional information for an Azure token source.
    type: ref
    exposed: true
    subtype: issueazure
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: inputGCP
    friendly_name: InputGCP
    description: Contains additional information for an GCP token source.
    type: ref
    exposed: true
    subtype: issuegcp
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: inputHTTP
    friendly_name: InputHTTP
    description: Contains additional information for an HTTP source.
    type: ref
    exposed: true
    subtype: issuehttp
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: inputLDAP
    friendly_name: InputLDAP
    description: Contains additional information for an LDAP source.
    type: ref
    exposed: true
    subtype: issueldap
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: inputOIDC
    friendly_name: InputOIDC
    description: Contains additional information for an OIDC source.
    type: ref
    exposed: true
    subtype: issueoidc
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: inputRemoteA3S
    friendly_name: InputRemoteA3S
    description: Contains additional information for a remote A3S token source.
    type: ref
    exposed: true
    subtype: issueremotea3s
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: opaque
    friendly_name: Opaque
    description: Opaque data that will be included in the issued token.
    type: external
    exposed: true
    subtype: map[string]string
    omit_empty: true

  - name: restrictedNamespace
    friendly_name: RestrictedNamespace
    description: |-
      Restricts the namespace where the token can be used.

      For instance, if you have have access to `/namespace` and below, you can
      tell the policy engine that it should restrict further more to
      `/namespace/child`.

      Restricting to a namespace you don't have initially access according to the
      policy engine has no effect and may end up making the token unusable.
    type: string
    exposed: true
    example_value: /namespace
    omit_empty: true

  - name: restrictedNetworks
    friendly_name: RestrictedNetworks
    description: |-
      Restricts the networks from where the token can be used. This will reduce the
      existing set of authorized networks that normally apply to the token according
      to the policy engine.

      For instance, If you have authorized access from `0.0.0.0/0` (by default) or
      from
      `10.0.0.0/8`, you can ask for a token that will only be valid if used from
      `10.1.0.0/16`.

      Restricting to a network that is not initially authorized by the policy
      engine has no effect and may end up making the token unusable.
    type: list
    exposed: true
    subtype: string
    example_value:
    - 10.0.0.0/8
    - 127.0.0.1/32
    omit_empty: true
    validations:
    - $cidr_list_optional

  - name: restrictedPermissions
    friendly_name: RestrictedPermissions
    description: |-
      Restricts the permissions of token. This will reduce the existing permissions
      that normally apply to the token according to the policy engine.

      For instance, if you have administrative role, you can ask for a token that will
      tell the policy engine to reduce the permission it would have granted to what is
      given defined in the token.

      Restricting to some permissions you don't initially have according to the policy
      engine has no effect and may end up making the token unusable.
    type: list
    exposed: true
    subtype: string
    example_value:
    - dogs,post
    omit_empty: true

  - name: sourceName
    friendly_name: SourceName
    description: The name of the source to use.
    type: string
    exposed: true
    example_value: /my/ns
    omit_empty: true

  - name: sourceNamespace
    friendly_name: SourceNamespace
    description: The namespace of the source to use.
    type: string
    exposed: true
    example_value: /my/ns
    omit_empty: true

  - name: sourceType
    friendly_name: SourceType
    description: |-
      The authentication source. This will define how to verify
      credentials from internal or external source of authentication.
    type: enum
    exposed: true
    required: true
    allowed_choices:
    - A3S
    - AWS
    - Azure
    - GCP
    - HTTP
    - LDAP
    - MTLS
    - OIDC
    - RemoteA3S
    - SAML
    example_value: OIDC

  - name: token
    friendly_name: Token
    description: Issued token.
    type: string
    exposed: true
    read_only: true
    autogenerated: true
    omit_empty: true

  - name: tokenType
    friendly_name: TokenType
    description: The type of token to issue.
    type: enum
    exposed: true
    allowed_choices:
    - Identity
    - Refresh
    default_value: Identity
    omit_empty: true

  - name: validity
    friendly_name: Validity
    description: |-
      Configures the maximum length of validity for a token, using
      [Golang duration syntax](https://golang.org/pkg/time/#example_Duration).
    type: string
    exposed: true
    omit_empty: true
    validations:
    - $duration

  - name: waiveValiditySecret
    friendly_name: Waive Validity Secret
    description: |-
      If A3S has been started --jwt-waive-validity-secret and this propery matches it,
      no validity limit will be enforced.
    type: string
    exposed: true
    secret: true
    omit_empty: true
