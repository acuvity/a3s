# Model
model:
  rest_name: mtlssourceokta
  resource_name: mtlssourceokta
  entity_name: MTLSSourceOkta
  friendly_name: MTLS Source Okta
  package: a3s
  group: authn/issue
  description: |-
    Additional authentication information for MTLS source getting information from
    Okta.
  detached: true

# Attributes
attributes:
  v1:
  - name: KID
    friendly_name: KID
    description: The Key ID associated to the private key.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: RuxZhjjgWRnJGxGruqg4UpS821E7RtfY9cXbyfKwafo

  - name: clientID
    friendly_name: Client ID
    description: The application client id.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: 0oaqqm0r0sYY2OuHT5d7

  - name: domain
    friendly_name: Domain
    description: Your custom okta domain.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: my-org.okta.com

  - name: privateKey
    friendly_name: PrivateKey
    description: The Application private key.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: |-
      -----BEGIN PRIVATE KEY-----
      ...
      -----END PRIVATE KEY-----
    secret: true
    transient: true
    encrypted: true
    validations:
    - $pem
