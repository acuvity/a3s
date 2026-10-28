# Model
model:
  rest_name: mtlssourceciscoduo
  resource_name: mtlssourceciscoduo
  entity_name: MTLSSourceCiscoDuo
  friendly_name: MTLS Source Cisco Duo
  package: a3s
  group: authn/issue
  description: |-
    Additional authentication information for MTLS source getting information from
    Cisco Duo.

    You will need a Duo Admin API application with the Grant resource - Read
    permission.
  detached: true

# Attributes
attributes:
  v1:
  - name: APIHostname
    friendly_name: API Hostname
    description: The API hostname of the Duo Admin API application.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: api-xxxxxxxx.duosecurity.com
    validations:
    - $hostname

  - name: integrationKey
    friendly_name: Integration Key
    description: The integration key of the Duo Admin API application.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: DIWJ8X6AEYOR5OMC6TQ1

  - name: secretKey
    friendly_name: Secret Key
    description: The secret key of the Duo Admin API application.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep
    secret: true
    transient: true
    encrypted: true
