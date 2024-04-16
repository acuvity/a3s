# Model
model:
  rest_name: a3ssource
  resource_name: a3ssources
  entity_name: A3SSource
  friendly_name: A3SSource
  package: a3s
  group: authn/source
  description: A source allowing to trust a remote instance of A3S.
  get:
    description: Get a particular a3ssource object.
  update:
    description: Update a particular a3ssource object.
  delete:
    description: Delete a particular a3ssource object.
  extends:
  - '@sharded'
  - '@identifiable'
  - '@importable'
  - '@timed'

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
      The Certificate authority to use to validate the authenticity of the A3S
      server. If left empty, the system trust stroe will be used.
    type: string
    exposed: true
    stored: true
    validations:
    - $pem

  - name: audience
    friendly_name: Audience
    description: The audience that must be present in the remote a3s token.
    type: string
    exposed: true
    stored: true

  - name: description
    friendly_name: Description
    description: The description of the object.
    type: string
    exposed: true
    stored: true

  - name: endpoint
    friendly_name: Endpoint
    description: |-
      Endpoint of the remote a3s server, in case it is different from the issuer. If
      left empty, the issuer value will be used.
    type: string
    exposed: true
    stored: true

  - name: issuer
    friendly_name: Issuer
    description: The issuer that represents the remote a3s server.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: https://remote-a3s.com

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
    example_value: myoidc
