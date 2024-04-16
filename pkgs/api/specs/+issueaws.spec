# Model
model:
  rest_name: issueaws
  resource_name: issueaws
  entity_name: IssueAWS
  friendly_name: IssueAWS
  package: a3s
  group: authn/issue
  description: Additional issuing information for AWS STS token source.
  detached: true

# Attributes
attributes:
  v1:
  - name: ID
    friendly_name: ID
    description: The ID of the AWS STS token.
    type: string
    exposed: true
    required: true
    example_value: xxxxx

  - name: secret
    friendly_name: Secret
    description: The secret associated to the AWS STS token.
    type: string
    exposed: true
    required: true
    example_value: yyyyy

  - name: token
    friendly_name: Token
    description: The original token.
    type: string
    exposed: true
    required: true
    example_value: valid.jwt.token
