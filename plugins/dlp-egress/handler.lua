-- dlp-egress: outbound DLP at the egress route (plan §3 phase 5; arch §5.3).
--
-- Screens the raw request body (MCP tool arguments) against PCRE patterns
-- before anything leaves for the vendor. A match blocks the request and
-- emits an audit record carrying the PATTERN NAME and token ids — never the
-- matched text (the audit trail must not become the leak).
--
-- Fail closed: a body that cannot be read/scanned does not leave.
--
-- Runs AFTER auth (openid-connect 1050) so audit records carry a validated
-- caller, and BEFORE vendor-token (900) so blocked calls never consume a
-- broker resolve.

local cjson = require "cjson.safe"

local Dlp = {
  PRIORITY = 950,
  VERSION = "0.1.0",
}

local function token_claims()
  local auth = kong.request.get_header("authorization") or ""
  local token = auth:match("^[Bb]earer%s+(.+)$")
  local payload = token and token:match("^[^.]+%.([^.]+)%.")
  if not payload then return {} end
  payload = payload:gsub("-", "+"):gsub("_", "/")
  payload = payload .. string.rep("=", (4 - #payload % 4) % 4)
  local raw = ngx.decode_base64(payload)
  local claims = raw and cjson.decode(raw)
  return type(claims) == "table" and claims or {}
end

local function audit(level, decision, reason, pattern_name)
  local claims = token_claims()
  local route = kong.router.get_route()
  kong.log[level](cjson.encode({
    audit = "dlp-egress",
    decision = decision,
    reason = reason,
    pattern = pattern_name or ngx.null,
    token_id = claims.jti,
    principal = claims.sub,
    client = claims.azp,
    route = route and route.name or ngx.null,
    ts = ngx.now(),
  }))
end

local function deny(reason, pattern_name)
  audit("warn", "deny", reason, pattern_name)
  return kong.response.exit(403, {
    error = "dlp_blocked",
    reason = reason,
    pattern = pattern_name,
  })
end

function Dlp:access(conf)
  local body = kong.request.get_raw_body()
  if body == nil then
    local method = kong.request.get_method()
    if method == "GET" or method == "HEAD" then return end
    return deny("unscannable_body", nil)
  end
  for _, p in ipairs(conf.patterns or {}) do
    local from, _, err = ngx.re.find(body, p.regex, "jo")
    if err then
      return deny("pattern_error", p.name)
    end
    if from then
      return deny("pattern_match", p.name)
    end
  end
  -- Clean pass gets a verdict too: the phase 6 tuple must show that outbound
  -- content WAS screened, not merely that nothing blocked it.
  audit("notice", "allow", "screened", nil)
end

return Dlp
