# Model
model:
  rest_name: issueentra
  resource_name: issueentra
  entity_name: IssueEntra
  friendly_name: IssueEntra
  package: a3s
  group: authn/issue
  description: Additional issuing information for the Entra source.
  detached: true

# Attributes
attributes:
  v1:
  - name: token
    friendly_name: Token
    description: The Entra access token issued for the A3S Entra API application.
    type: string
    exposed: true
    required: true
    example_value: valid.jwt.token
