local typedefs = require "kong.db.schema.typedefs"

return {
  name = "dpop-check",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {},
      },
    },
  },
}
