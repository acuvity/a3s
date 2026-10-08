# Model
model:
  rest_name: namespacelifecycle
  resource_name: namespacelifecycles
  entity_name: NamespaceLifecycle
  friendly_name: NamespaceLifecycle
  package: a3s
  group: core
  private: true
  description: |-
    Private non-expiring namespace lifecycle coordination. This model has no public
    CRUD route. Its identifier binds the native namespace incarnation, not its name.
  extends:
  - '@sharded'
  - '@identifiable'

# Indexes
indexes:
- - namespaceName

# Attributes
attributes:
  v1:
  - name: namespaceName
    friendly_name: NamespaceName
    description: Immutable canonical name retained across deletion to forbid unsafe reuse.
    type: string
    stored: true
    read_only: true

  - name: revision
    friendly_name: Revision
    description: Monotonic conditional-write revision.
    type: integer
    stored: true
    read_only: true

  - name: data
    friendly_name: Data
    description: Bounded canonical lifecycle state owned by the namespace owner.
    type: string
    stored: true
    read_only: true
