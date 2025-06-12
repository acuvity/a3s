# Model
model:
  rest_name: authorization
  resource_name: authorizations
  entity_name: Authorization
  friendly_name: Authorization
  package: a3s
  group: authz
  description: TODO.
  get:
    description: Retrieves the authorization with the given ID.
    global_parameters:
    - $queryable
  update:
    description: Updates the authorization with the given ID.
    global_parameters:
    - $queryable
  delete:
    description: Deletes the authorization with the given ID.
    global_parameters:
    - $queryable
  extends:
  - '@sharded'
  - '@identifiable'
  - '@importable'
  - '@timed'

# Indexes
indexes:
- - namespace
  - flattenedSubject
  - disabled
- - namespace
  - flattenedSubject
  - propagate
- - namespace
  - trustedIssuers
- - namespace
  - label

# Attributes
attributes:
  v1:
  - name: description
    friendly_name: Description
    description: Description of the Authorization.
    type: string
    exposed: true
    stored: true

  - name: disabled
    friendly_name: Disabled
    description: Set the authorization to be disabled.
    type: boolean
    exposed: true
    stored: true

  - name: flattenedSubject
    friendly_name: FlattenedSubject
    description: This is a set of all subject tags for matching in the DB.
    type: list
    subtype: string
    stored: true

  - name: hidden
    friendly_name: Hidden
    description: Hides the policies in children namespaces.
    type: boolean
    exposed: true
    stored: true

  - name: label
    friendly_name: Label
    description: Allows users to set a label to categorize authorization policies.
    type: string
    exposed: true
    subtype: string
    stored: true

  - name: name
    friendly_name: Name
    description: The name of the Authorization.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: my authorization

  - name: opaque
    friendly_name: Opaque
    description: Opaque allows to store abitrary data into the authorization.
    type: external
    exposed: true
    subtype: map[string]any
    stored: true
    omit_empty: true
    extensions:
      noInit: true

  - name: permissions
    friendly_name: Permissions
    description: A list of permissions.
    type: list
    exposed: true
    subtype: string
    stored: true
    required: true
    example_value:
    - '@auth:role=namespace.administrator'
    - namespace,get,post,put
    - authorization,get:1234567890

  - name: propagate
    friendly_name: Propagate
    description: Propagates the api authorization to all of its children. This is
      always true.
    type: boolean
    stored: true
    default_value: true
    getter: true
    setter: true

  - name: subject
    friendly_name: Subject
    description: A tag expression that identifies the authorized user(s).
    type: external
    exposed: true
    subtype: '[][]string'
    stored: true
    orderable: true
    validations:
    - $tags_expression

  - name: subnets
    friendly_name: Subnets
    description: |-
      If set, the API authorization will only be valid if the request comes from one
      the declared subnets.
    type: list
    exposed: true
    subtype: string
    stored: true
    validations:
    - $cidr_list_optional

  - name: targetNamespaces
    friendly_name: TargetNamespaces
    description: |-
      Defines the namespace or namespaces in which the permission for subject should
      apply. If empty, the object's namespace will be used.
    type: list
    exposed: true
    subtype: string
    stored: true
    example_value: /my/namespace

  - name: trustedIssuers
    friendly_name: TrustedIssuers
    description: List of issuers to consider before using the policy for a given set
      of claims.
    type: list
    exposed: true
    subtype: string
    stored: true
