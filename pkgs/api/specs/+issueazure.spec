# Model
model:
  rest_name: issueazure
  resource_name: issueazure
  entity_name: IssueAzure
  friendly_name: IssueAzure
  package: a3s
  group: authn/issue
  description: Additional issuing information for Azure identity token source.
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
