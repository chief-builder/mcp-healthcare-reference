-- luacheck config for the bespoke Kong plugins (run by plugins/tests/run.sh).
std = "ngx_lua"
globals = { "kong" }
max_line_length = false
-- Kong calls handlers as Plugin:phase(conf); unused self/conf is the norm.
unused_args = false
