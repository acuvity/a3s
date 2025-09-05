# Model
model:
  rest_name: revocation
  resource_name: revocations
  entity_name: Revocation
  friendly_name: Revocation
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
  validations:
  - $revocation

# Indexes
indexes:
- - namespace
  - tokenid
- - tokenid
- - namespace
  - flattenedSubject
- - flattenedSubject

# Attributes
attributes:
  v1:
  - name: expiration
    friendly_name: Expiration
    description: The expiration date of the token.
    type: time
    exposed: true
    stored: true
    example_value: "2023-11-08T18:38:04.51Z"

  - name: flattenedSubject
    friendly_name: FlattenedSubject
    description: This is a set of all subject tags for matching in the DB.
    type: list
    subtype: string
    stored: true

  - name: issuedBefore
    friendly_name: Issued Before
    description: |-
      Only apply the revocation if the token has been issued before the given date, if
      non zero. Cannot be set if issuedBeforeRel is set.
    type: time
    exposed: true
    stored: true
    omit_empty: true

  - name: issuedBeforeRel
    friendly_name: Issued Before Relative
    description: |-
      Only apply the revocation if the token has been issued before the given relative
      date, if non zero. Cannot be set if issuedBefore is set.
    type: string
    exposed: true
    omit_empty: true
    validations:
    - $duration

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

  - name: tokenID
    friendly_name: TokenID
    description: The ID of the revoked token.
    type: string
    exposed: true
    stored: true
    example_value: ff199ae8-8e15-4daf-9c90-155d9cba90c2
