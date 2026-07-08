local typedefs = require "kong.db.schema.typedefs"

return {
  name = "cnf-check",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {},
      },
    },
  },
}
