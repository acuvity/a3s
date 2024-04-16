# Model
model:
  rest_name: issuegcp
  resource_name: issuegcp
  entity_name: IssueGCP
  friendly_name: IssueGCP
  package: a3s
  group: authn/issue
  description: Additional issuing information for GCP identity token source.
  detached: true

# Attributes
attributes:
  v1:
  - name: audience
    friendly_name: Audience
    description: The required audience.
    type: string
    exposed: true

  - name: token
    friendly_name: Token
    description: The original token.
    type: string
    exposed: true
    required: true
    example_value: valid.jwt.token
