# Model
model:
  rest_name: root
  resource_name: root
  entity_name: Root
  friendly_name: Root
  package: root
  group: core
  description: root object.
  root: true

# Relations
relations:
- rest_name: a3ssource
  get:
    description: Retrieves the list of a3ssources.
    global_parameters:
    - $queryable
  create:
    description: Creates a new a3ssource.

- rest_name: authorization
  get:
    description: Retrieves the list of authorization.
    global_parameters:
    - $queryable
  create:
    description: Creates a new authorization.

- rest_name: authz
  create:
    description: Sends a authz request.

- rest_name: group
  get:
    description: Retrieves the list of groups.
    global_parameters:
    - $queryable
  create:
    description: Creates a new groups.

- rest_name: httpsource
  get:
    description: Retrieves the list of httpsources.
    global_parameters:
    - $queryable
  create:
    description: Creates a new httpsource.

- rest_name: import
  create:
    description: Sends an import request.
    parameters:
      entries:
      - name: delete
        description: If set, delete the current imported data.
        type: boolean

- rest_name: issue
  create:
    description: Ask to issue a new authentication token.

- rest_name: ldapsource
  get:
    description: Retrieves the list of ldapsources.
    global_parameters:
    - $queryable
  create:
    description: Creates a new ldapsource.

- rest_name: logout
  create:
    description: Makes browser delete the secure cookie.

- rest_name: mtlssource
  get:
    description: Retrieves the list of mtlssources.
    global_parameters:
    - $queryable
  create:
    description: Creates a new mtlssource.

- rest_name: namespace
  get:
    description: Retrieves the list of namespaces.
    global_parameters:
    - $queryable
  create:
    description: Creates a new namespace.

- rest_name: namespacedeletionrecord
  get:
    description: Retrieves the list of namespace deletion records.
    global_parameters:
    - $queryable

- rest_name: oauth2source
  get:
    description: Retrieves the list of oauth2sources.
    global_parameters:
    - $queryable
  create:
    description: Creates a new oauthpsource.

- rest_name: oidcsource
  get:
    description: Retrieves the list of oidcsources.
    global_parameters:
    - $queryable
  create:
    description: Creates a new oidcsource.

- rest_name: permissions
  create:
    description: Sends a permissions request.

- rest_name: revocation
  get:
    description: Retrieves the list of revoked tokens.
    global_parameters:
    - $queryable
  create:
    description: Mark a token as revoked based on its ID.

- rest_name: samlsource
  get:
    description: Retrieves the list of samlsources.
    global_parameters:
    - $queryable
  create:
    description: Creates a new samlsource.
