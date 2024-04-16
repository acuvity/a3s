# Model
model:
  rest_name: issueldap
  resource_name: issueldap
  entity_name: IssueLDAP
  friendly_name: IssueLDAP
  package: a3s
  group: authn/issue
  description: Additional issuing information for the LDAP source.
  detached: true

# Attributes
attributes:
  v1:
  - name: password
    friendly_name: Password
    description: The password for the user.
    type: string
    exposed: true
    required: true
    example_value: secret

  - name: username
    friendly_name: Username
    description: The LDAP username.
    type: string
    exposed: true
    required: true
    example_value: joe
