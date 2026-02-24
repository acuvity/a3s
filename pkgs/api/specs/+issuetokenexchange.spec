# Model
model:
  rest_name: issuetokenexchange
  resource_name: issuetokenexchange
  entity_name: IssueTokenExchange
  friendly_name: IssueTokenExchange
  package: a3s
  group: authn/issue
  description: Additional issuing information for DSG token exchange source.
  detached: true

# Attributes
attributes:
  v1:
  - name: accessToken
    friendly_name: AccessToken
    description: The access token to validate with DSG auth.
    type: string
    exposed: true
    required: true
    example_value: valid.jwt.access.token
