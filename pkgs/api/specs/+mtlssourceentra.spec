# Model
model:
  rest_name: mtlssourceentra
  resource_name: mtlssourceentra
  entity_name: MTLSSourceEntra
  friendly_name: MTLS Source Entra
  package: a3s
  group: authn/issue
  description: |-
    Additional authentication information for MTLS source getting information from
    Entra.

    You will need to set clientTenantID, clientID and clientSecret.

    You will also need an Entra application that has the following permissions:
    Directory.Read.All and User.Read.
  detached: true

# Attributes
attributes:
  v1:
  - name: clientID
    friendly_name: Client ID
    description: |-
      The oauth clientID if any. This may be required for autologin, depending on the
      mode.
    type: string
    exposed: true
    stored: true
    example_value: a83e57d8-24af-4aec-bc8f-822db8d165b0
    omit_empty: true

  - name: clientSecret
    friendly_name: Client Secret
    description: |-
      Client secret associated with the client ID. This may be required for autologin,
      depending on the mode.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: Ytgbfjtj4652jHDFGls99jF
    secret: true
    transient: true
    encrypted: true

  - name: clientTenantID
    friendly_name: Client Tenant ID
    description: |-
      ID of the tenant for the identity provider, if any. This may be required for
      autologin, depending on the mode.
    type: string
    exposed: true
    stored: true
    example_value: a83e57d8-24af-4aec-bc8f-822db8d165b0
    omit_empty: true
