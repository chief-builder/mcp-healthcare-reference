local typedefs = require "kong.db.schema.typedefs"

return {
  name = "vendor-token",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { broker_url = { type = "string", required = true } },
          { vendor = { type = "string", required = true } },
          { min_ttl_s = { type = "integer", default = 120 } },
          { timeout_ms = { type = "integer", default = 10000 } },
          -- Scopes the tools on this egress route require; the broker caps
          -- them at the registry ceiling and consents for the minimum (§4.2/§6).
          { required_scopes = { type = "array", elements = { type = "string" },
                                default = {} } },
        },
      },
    },
  },
}
