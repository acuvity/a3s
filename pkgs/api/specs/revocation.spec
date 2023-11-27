# Model
model:
  rest_name: revocation
  resource_name: revocations
  entity_name: Revocation
  package: a3s
  group: core
  description: A Revocation allows to mark a token as revoked based on its ID (jti).
  get:
    description: Get a particular revocation object.
  delete:
    description: Deletes a particular revocation.
  extends:
  - '@sharded'
  - '@identifiable'
  - '@timed'

# Indexes
indexes:
- - namespace
  - tokenid
- - tokenid

# Attributes
attributes:
  v1:
  - name: expiration
    description: The expiration date of the token.
    type: time
    exposed: true
    stored: true
    example_value: "2023-11-08T18:38:04.51Z"

  - name: propagate
    description: Propagates the api authorization to all of its children. This is
      always true.
    type: boolean
    stored: true
    default_value: true
    getter: true
    setter: true

  - name: tokenID
    description: The ID of the revoked token.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: ff199ae8-8e15-4daf-9c90-155d9cba90c2
