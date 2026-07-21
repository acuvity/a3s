# Model
model:
  rest_name: mtlssourcegoogle
  resource_name: mtlssourcegoogle
  entity_name: MTLSSourceGoogle
  friendly_name: MTLS Source Google Workspace
  package: a3s
  group: authn/issue
  description: |-
    Additional authentication information for MTLS source getting information from
    Google Workspace.

    You will need a Google Cloud service account with domain-wide delegation
    enabled in the Google Workspace Admin console, granted the
    admin.directory.user.readonly and admin.directory.group.readonly scopes.
  detached: true

# Attributes
attributes:
  v1:
  - name: clientEmail
    friendly_name: Client Email
    description: The email of the service account used to call the Directory API.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: a3s@my-project.iam.gserviceaccount.com

  - name: privateKey
    friendly_name: PrivateKey
    description: The service account private key.
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

  - name: privateKeyID
    friendly_name: Private Key ID
    description: The identifier of the service account private key.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: 3cb0a1d5f7e9b2c4a6d8e0f1234567890abcdef1

  - name: subject
    friendly_name: Subject
    description: |-
      The email of the Google Workspace administrator to impersonate when calling
      the Directory API. This is required for domain-wide delegation.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: admin@my-org.com
