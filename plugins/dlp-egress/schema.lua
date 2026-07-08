local typedefs = require "kong.db.schema.typedefs"

return {
  name = "dlp-egress",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { patterns = {
              type = "array",
              required = true,
              elements = {
                type = "record",
                fields = {
                  { name = { type = "string", required = true } },
                  { regex = { type = "string", required = true } },
                },
              },
            },
          },
        },
      },
    },
  },
}
