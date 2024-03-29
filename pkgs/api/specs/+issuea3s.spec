# Model
model:
  rest_name: issuea3s
  resource_name: issuea3s
  entity_name: IssueA3S
  friendly_name: IssueA3S
  package: a3s
  group: authn/issue
  description: Additional issuing information for A3S token source.
  detached: true

# Attributes
attributes:
  v1:
  - name: token
    friendly_name: Token
    description: The original token.
    type: string
    exposed: true
    required: true
    example_value: valid.jwt.token

  - name: waiveValiditySecret
    friendly_name: Waive Validity Secret
    description: |-
      If A3S has been started --jwt-waive-validity-secret and this propery matches it,
      no validity limit will be enforced.
    type: string
    exposed: true
    secret: true
    omit_empty: true
