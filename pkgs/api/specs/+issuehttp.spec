# Model
model:
  rest_name: issuehttp
  resource_name: issuehttp
  entity_name: IssueHTTP
  friendly_name: IssueHTTP
  package: a3s
  group: authn/issue
  description: Additional issuing information for the HTTP source.
  detached: true

# Attributes
attributes:
  v1:
  - name: TOTP
    friendly_name: TOTP
    description: Time based one time password, if needed.
    type: string
    exposed: true
    example_value: "12345"
    omit_empty: true

  - name: password
    friendly_name: Password
    description: The password for the user.
    type: string
    exposed: true
    required: true
    example_value: secret

  - name: username
    friendly_name: Username
    description: The username.
    type: string
    exposed: true
    required: true
    example_value: joe
