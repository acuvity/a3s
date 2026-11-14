# Model
model:
  rest_name: entrasource
  resource_name: entrasources
  entity_name: EntraSource
  friendly_name: EntraSource
  package: a3s
  group: authn/source
  description: |-
    A source that issues tokens from Microsoft Entra ID access tokens obtained by
    users of a given Entra tenant for the A3S Entra API application.
  get:
    description: Get a particular entrasource object.
  update:
    description: Update a particular entrasource object.
  delete:
    description: Delete a particular entrasource object.
  extends:
  - '@sharded'
  - '@identifiable'
  - '@importable'
  - '@timed'
  - '@claimfilter'
  - '@openidsource'

# Indexes
indexes:
- - namespace
  - name

# Attributes
attributes:
  v1:
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
    example_value: my-entra-source

  - name: tenantID
    friendly_name: TenantID
    description: |-
      The ID of the Entra tenant whose users can authenticate with this source.
      Tokens issued by any other tenant are rejected.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: 1ec8ce6a-2b6d-4828-b298-be4d2eeb573b
    allowed_chars: ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$
    allowed_chars_message: must be a tenant ID (GUID)
