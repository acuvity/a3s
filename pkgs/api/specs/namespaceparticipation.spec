# Model
model:
  rest_name: namespaceparticipation
  resource_name: namespaceparticipations
  entity_name: NamespaceParticipation
  friendly_name: NamespaceParticipation
  package: a3s
  group: core
  description: |-
    Explicit development-only namespace enrollment command. No normal processor
    registration enables this resource. All actions require current Create permission.

# Attributes
attributes:
  v1:
  - name: action
    friendly_name: Action
    description: Inspect retained metadata, claim enrollment, or capture current owner scope without writer authority.
    type: enum
    allowed_choices:
    - Inspect
    - ClaimEnrollment
    - InspectDeletion
    - CaptureScope
    exposed: true
    required: true
    example_value: Inspect

  - name: deletionIntentID
    friendly_name: DeletionIntentID
    description: Exact retained deletion intent for InspectDeletion only.
    type: string
    exposed: true
    omit_empty: true

  - name: namespaceID
    friendly_name: NamespaceID
    description: Exact native namespace incarnation. Required except for CaptureScope, which forbids this field.
    type: string
    exposed: true
    omit_empty: true
    example_value: '111111111111111111111111'

  - name: operationID
    friendly_name: OperationID
    description: Exact source-owned creation operation. Required except for CaptureScope, which forbids this field.
    type: string
    exposed: true
    omit_empty: true
    example_value: owner-operation

  - name: participant
    friendly_name: Participant
    description: Trusted participant identifier, currently hanni.
    type: string
    exposed: true
    required: true
    example_value: hanni

  - name: registryID
    friendly_name: RegistryID
    description: Exact participant registry ID, equal to namespaceID. Required except for CaptureScope, which forbids this field.
    type: string
    exposed: true
    omit_empty: true
    example_value: '111111111111111111111111'

  - name: granted
    friendly_name: Granted
    description: True only for an acknowledged live attempted-to-claimed CAS.
    type: boolean
    exposed: true
    read_only: true

  - name: snapshot
    friendly_name: Snapshot
    description: Validated source-owned namespace-enrollment.v1 metadata, never caller authority.
    type: external
    subtype: map[string]any
    exposed: true
    read_only: true
