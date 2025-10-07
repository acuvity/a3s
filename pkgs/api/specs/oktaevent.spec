# Model
model:
  rest_name: oktaevent
  resource_name: oktaevents
  entity_name: OktaEvent
  friendly_name: OKta Event
  package: a3s
  group: authz/check
  description: API to handle okta event hooks.

# Attributes
attributes:
  v1:
  - name: payload
    friendly_name: Payload
    description: The raw content of the event event.
    type: string
    exposed: true
