# Model
model:
  rest_name: namespace
  resource_name: namespaces
  entity_name: Namespace
  friendly_name: Namespace
  package: a3s
  group: core
  description: |-
    A namespace is grouping object. Every object is part of a namespace, and every
    request is made against a namespace. Namespaces form a tree hierarchy.
  get:
    description: Get a particular namespace object.
    global_parameters:
    - $queryable
  update:
    description: Update a particular namespace object.
    global_parameters:
    - $queryable
  delete:
    description: Delete a particular namespace object.
    global_parameters:
    - $queryable
  extends:
  - '@importable'
  - '@sharded'
  - '@identifiable'
  - '@timed'

# Indexes
indexes:
- - namespace
  - name
- - name
- - namespace
  - label

# Attributes
attributes:
  v1:
  - name: description
    friendly_name: Description
    description: The description of the object.
    type: string
    exposed: true
    stored: true

  - name: label
    friendly_name: Label
    description: Allows users to set a label to categorize the namespace.
    type: string
    exposed: true
    subtype: string
    stored: true
    omit_empty: true

  - name: name
    friendly_name: Name
    description: |-
      The name of the namespace. When you create a namespace, only put its bare name,
      not its full path.
    type: string
    exposed: true
    stored: true
    required: true
    creation_only: true
    allowed_chars: ^[a-zA-Z0-9-_/@.]+$
    allowed_chars_message: must only contain alpha numerical characters, '-' or '_'
      or '@' or '.'
    example_value: mycompany
    getter: true
    setter: true

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
