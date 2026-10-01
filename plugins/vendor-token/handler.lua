-- vendor-token: per-sub vendor credential injection at the egress route
-- (plan §3 phase 5; broker design §4.1/§6).
--
-- Calls the broker's resolve endpoint with the caller's hub JWT (which the
-- broker independently re-validates), then swaps the upstream Authorization
-- header for the vendor token — the hub JWT stops here and never transits
-- to the vendor (arch §6 token-isolation MUST). A 404 needs-consent from
-- the broker becomes the MCP authorization-required challenge with the
-- broker's authorize_uri.

local cjson = require "cjson.safe"

local VendorToken = {
  PRIORITY = 900, -- after openid-connect (1050) and dlp-egress (950)
  VERSION = "0.1.0",
}

local function claims_of(token)
  local payload = token:match("^[^.]+%.([^.]+)%.")
  if not payload then return {} end
  payload = payload:gsub("-", "+"):gsub("_", "/")
  payload = payload .. string.rep("=", (4 - #payload % 4) % 4)
  local raw = ngx.decode_base64(payload)
  local claims = raw and cjson.decode(raw)
  return type(claims) == "table" and claims or {}
end

local function audit(decision, conf, claims, extra)
  local record = {
    audit = "vendor-token",
    decision = decision,
    vendor = conf.vendor,
    token_id = claims.jti,
    principal = claims.sub,
    client = claims.azp,
    ts = ngx.now(),
  }
  for k, v in pairs(extra or {}) do record[k] = v end
  kong.log.notice(cjson.encode(record))
end

function VendorToken:access(conf)
  local auth = kong.request.get_header("authorization") or ""
  local token = auth:match("^[Bb]earer%s+(.+)$")
  -- Egress routes are bearer-only (openid-connect auth_methods: bearer) and
  -- the broker re-validates bearer hub JWTs without checking DPoP proofs, so
  -- a DPoP-bound token is refused explicitly rather than forwarded — passing
  -- it on would silently downgrade a sender-constrained token to bearer use.
  local dpop_token = not token and auth:match("^[Dd][Pp][Oo][Pp]%s+(.+)$")
  if dpop_token then
    audit("deny", conf, claims_of(dpop_token), { reason = "dpop_scheme_on_egress" })
    return kong.response.exit(401, {
      error = "invalid_request",
      error_description = "egress routes accept Bearer tokens only; DPoP-bound tokens are not brokered",
    }, { ["WWW-Authenticate"] = 'Bearer realm="mcp-egress", error="invalid_request"' })
  end
  if not token then
    return kong.response.exit(401, { error = "unauthorized" },
      { ["WWW-Authenticate"] = 'Bearer realm="mcp-egress"' })
  end
  local claims = claims_of(token)

  local httpc = require("resty.http").new()
  httpc:set_timeout(conf.timeout_ms)
  local res, err = httpc:request_uri(conf.broker_url .. "/v1/tokens/resolve", {
    method = "POST",
    body = cjson.encode({
      vendor = conf.vendor,
      sub = claims.sub,
      hub_jti = claims.jti,
      min_ttl_s = conf.min_ttl_s,
      required_scopes = conf.required_scopes,
    }),
    headers = {
      ["Content-Type"] = "application/json",
      ["Authorization"] = auth,
    },
  })
  if not res then
    audit("deny", conf, claims, { reason = "broker_unreachable", error = err })
    return kong.response.exit(502, { error = "broker_unreachable" })
  end

  local body = cjson.decode(res.body) or {}
  if res.status == 200 then
    if type(body.access_token) ~= "string" or body.access_token == "" then
      audit("deny", conf, claims, { reason = "broker_malformed_response" })
      return kong.response.exit(502, { error = "broker_malformed_response" })
    end
    -- Vendor token upstream; the hub JWT is stripped by replacement.
    kong.service.request.set_header("Authorization", "Bearer " .. body.access_token)
    audit("allow", conf, claims, {})
    return
  end
  if res.status == 404 and body.authorize_uri then
    audit("deny", conf, claims, { reason = "needs_consent" })
    return kong.response.exit(401, {
      error = "authorization_required",
      authorize_uri = body.authorize_uri,
    }, { ["WWW-Authenticate"] =
           'Bearer realm="mcp-egress", error="invalid_token", error_description="vendor consent required"' })
  end
  -- Grant exists but lacks the tool's scopes: step-up re-consent (§4.1).
  if res.status == 409 and body.authorize_uri then
    audit("deny", conf, claims, { reason = "needs_reconsent_scope" })
    return kong.response.exit(401, {
      error = "authorization_required",
      authorize_uri = body.authorize_uri,
    }, { ["WWW-Authenticate"] =
           'Bearer realm="mcp-egress", error="insufficient_scope", error_description="vendor re-consent required"' })
  end
  if res.status == 409 then
    audit("deny", conf, claims, { reason = body.title or "conflict" })
    return kong.response.exit(403, { error = body.title or "conflict" })
  end
  audit("deny", conf, claims, { reason = "broker_status_" .. res.status })
  return kong.response.exit(503, { error = "vendor_unavailable" })
end

return VendorToken
