# Model
model:
  rest_name: entraevent
  resource_name: entraevents
  entity_name: EntraEvent
  friendly_name: Entra Event
  package: a3s
  group: authz/check
  description: API to handle entra subscription events.

# Attributes
attributes:
  v1:
  - name: payload
    friendly_name: Payload
    description: The raw content of the notification event.
    type: string
    exposed: true
