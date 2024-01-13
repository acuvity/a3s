# Model
model:
  rest_name: group
  resource_name: groups
  entity_name: Group
  package: a3s
  group: authz
  description: TODO.
  get:
    description: Retrieves the group with the given ID.
    global_parameters:
    - $queryable
  update:
    description: Updates the group with the given ID.
    global_parameters:
    - $queryable
  delete:
    description: Deletes the group with the given ID.
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
  - label

# Attributes
attributes:
  v1:
  - name: description
    description: Description of the group.
    type: string
    exposed: true
    stored: true

  - name: disabled
    description: Set the group to be disabled.
    type: boolean
    exposed: true
    stored: true

  - name: flattenedSubject
    description: This is a set of all subject tags for matching in the DB.
    type: list
    subtype: string
    stored: true

  - name: label
    description: Allows users to set a label to categorize group policies.
    type: string
    exposed: true
    subtype: string
    stored: true

  - name: name
    description: The name of the group.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: my group

  - name: opaque
    description: Opaque allows to store abitrary data into the group.
    type: external
    exposed: true
    subtype: map[string]any
    stored: true
    omit_empty: true
    extensions:
      noInit: true

  - name: propagate
    description: Propagates the group to all of its children. This is always true.
    type: boolean
    stored: true
    default_value: true
    getter: true
    setter: true

  - name: subject
    description: A tag expression that identifies the authorized user(s).
    type: external
    exposed: true
    subtype: '[][]string'
    stored: true
    orderable: true
    validations:
    - $tags_expression
    - $authorization_subject
