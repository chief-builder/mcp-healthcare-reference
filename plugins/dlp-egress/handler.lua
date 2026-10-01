-- dlp-egress: outbound DLP at the egress route (plan §3 phase 5; arch §5.3).
--
-- Screens the request body (MCP tool arguments) against PCRE patterns
-- before anything leaves for the vendor — the raw bytes, and for JSON every
-- decoded string (so escapes like - cannot hide a match). A match blocks the request and
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

-- Max JSON nesting walked; anything deeper is refused rather than skipped.
local MAX_DEPTH = 64

-- First pattern (by config order) matching `text`, or nil. A regex error is
-- reported as its own outcome so the caller can fail closed on it.
local function first_match(conf, text)
  for _, p in ipairs(conf.patterns or {}) do
    local from, _, err = ngx.re.find(text, p.regex, "jo")
    if err then return "pattern_error", p.name end
    if from then return "pattern_match", p.name end
  end
end

-- Walk a decoded JSON value and screen every string, keys included. JSON
-- escapes (e.g. "MRN\u002d1234567") are already resolved by the decoder, so
-- this sees the text the vendor will see — the raw-body scan alone does not.
local function scan_value(conf, value, depth)
  if depth > MAX_DEPTH then return "too_deep", nil end
  local t = type(value)
  if t == "string" then
    return first_match(conf, value)
  end
  if t == "table" then
    for k, v in pairs(value) do
      if type(k) == "string" then
        local reason, name = first_match(conf, k)
        if reason then return reason, name end
      end
      local reason, name = scan_value(conf, v, depth + 1)
      if reason then return reason, name end
    end
  end
end

local function is_json_content_type()
  local ct = kong.request.get_header("content-type")
  if type(ct) == "table" then ct = ct[1] end
  if type(ct) ~= "string" then return false end
  ct = ct:lower()
  return ct:find("application/json", 1, true) ~= nil or ct:find("+json", 1, true) ~= nil
end

function Dlp:access(conf)
  local body = kong.request.get_raw_body()
  if body == nil then
    local method = kong.request.get_method()
    if method == "GET" or method == "HEAD" then return end
    return deny("unscannable_body", nil)
  end

  -- 1. Raw scan: catches plain-text bodies and anything outside JSON strings.
  local reason, name = first_match(conf, body)
  if reason then return deny(reason, name) end

  -- 2. Decoded scan: a JSON body (by content type, or by shape) is decoded
  -- and every string screened. A declared-JSON body that does not decode is
  -- refused — the vendor might still parse what we could not (fail closed).
  local declared_json = is_json_content_type()
  if declared_json or body:find("^%s*[%[{]") then
    local decoded = cjson.decode(body)
    if decoded == nil then
      if declared_json then return deny("unparseable_body", nil) end
    else
      reason, name = scan_value(conf, decoded, 1)
      if reason == "too_deep" then return deny("body_too_deep", nil) end
      if reason then return deny(reason, name) end
    end
  end

  -- Clean pass gets a verdict too: the phase 6 tuple must show that outbound
  -- content WAS screened, not merely that nothing blocked it.
  audit("notice", "allow", "screened", nil)
end

return Dlp
