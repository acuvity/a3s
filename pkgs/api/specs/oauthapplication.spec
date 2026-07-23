# Model
model:
  rest_name: oauthapplication
  resource_name: oauthapplications
  entity_name: OAuthApplication
  friendly_name: OAuth Application
  package: a3s
  group: authn/app
  description: |-
    An OAuth Application defines namespace-scoped OAuth behavior and policy used
    by client registrations.
  get:
    description: Get a particular oauthapplication object.
  update:
    description: Update a particular oauthapplication object.
  delete:
    description: Delete a particular oauthapplication object.
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
  - name: allowedSources
    friendly_name: Allowed Sources
    description: |-
      Optional list of allowed interactive authentication sources. If omitted or
      empty, any supported interactive source in the namespace is allowed. Each
      entry is an Elemental filter expression evaluated against the resolved
      source object, such as its `name` and `namespace`.
    type: list
    exposed: true
    subtype: string
    stored: true
    example_value:
    - namespace == /my/ns and name == corp
    - namespace == /partner and name == login
    validations:
    - $filters

  - name: audience
    friendly_name: Audience
    description: Audience to use for resulting a3s access tokens.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: my-app

  - name: defaultScopes
    friendly_name: Default Scopes
    description: Default scopes to use when a client does not request any scope.
    type: list
    exposed: true
    subtype: string
    stored: true
    example_value:
    - openid
    - profile

  - name: description
    friendly_name: Description
    description: The description of the object.
    type: string
    exposed: true
    stored: true

  - name: disabled
    friendly_name: Disabled
    description: If true, the OAuth application cannot be used.
    type: boolean
    exposed: true
    stored: true

  - name: name
    friendly_name: Name
    description: The name of the OAuth application.
    type: string
    exposed: true
    stored: true
    required: true
    creation_only: true
    example_value: my-app
