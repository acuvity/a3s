# Model
model:
  rest_name: samlsource
  resource_name: samlsources
  entity_name: SAMLSource
  friendly_name: SAMLSource
  package: a3s
  group: authn/source
  description: Defines a remote SAML to use as an authentication source.
  get:
    description: Retrieves the SAML source with the given ID.
  update:
    description: Updates the SAML source with the given ID.
  delete:
    description: Deletes the SAML source with the given ID.
  extends:
  - '@sharded'
  - '@identifiable'
  - '@importable'
  - '@timed'
  validations:
  - $samlsource

# Indexes
indexes:
- - namespace
  - name

# Attributes
attributes:
  v1:
  - name: IDPCertificate
    friendly_name: IDP Certificate
    description: Identity Provider Certificate in PEM format.
    type: string
    exposed: true
    stored: true
    example_value: |-
      -----BEGIN CERTIFICATE REQUEST-----
      MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxDzANBgNV
      ...
      97Ob1alpHPoZ7mWiEuJwjBPii6a9M9G30nUo39lBi1w=
      -----END CERTIFICATE REQUEST-----

  - name: IDPIssuer
    friendly_name: IDPIssuer
    description: Identity Provider Issuer (also called Entity ID).
    type: string
    exposed: true
    stored: true
    example_value: https://accounts.google.com/o/saml2/idp?idpid=AbDcef123

  - name: IDPMetadata
    friendly_name: IDPMetadata
    description: |-
      Pass some XML data containing the IDP metadata that can be used for automatic
      configuration. If you pass this attribute, every other one will be overwritten
      with the data contained in the metadata file.
    type: string
    exposed: true
    omit_empty: true

  - name: IDPURL
    friendly_name: IDPURL
    description: URL of the identity provider.
    type: string
    exposed: true
    stored: true
    example_value: https://accounts.google.com/o/saml2/idp?idpid=AbDcef123

  - name: description
    friendly_name: Description
    description: The description of the object.
    type: string
    exposed: true
    stored: true

  - name: modifier
    friendly_name: Modifier
    description: |-
      Contains optional information about a remote service that can be used to modify
      the claims that are about to be delivered using this authentication source.
    type: ref
    exposed: true
    subtype: identitymodifier
    stored: true
    omit_empty: true
    extensions:
      noInit: true
      refMode: pointer

  - name: name
    friendly_name: Name
    description: The name of the source.
    type: string
    exposed: true
    stored: true
    required: true
    example_value: mypki

  - name: subjects
    friendly_name: Subjects
    description: List of claims that will provide the subject.
    type: list
    exposed: true
    subtype: string
    stored: true
    example_value:
    - email
    - profile
