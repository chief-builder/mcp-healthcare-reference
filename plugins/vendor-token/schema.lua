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
        },
      },
    },
  },
}
