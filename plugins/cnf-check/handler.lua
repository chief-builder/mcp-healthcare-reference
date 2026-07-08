-- cnf-check: RFC 8705 certificate-bound token enforcement at the DP.
--
-- Claims contract §8: "if cnf present, mTLS client cert thumbprint MUST
-- match, and absence of a client cert is a hard failure." A cnf-bearing
-- token on a plaintext listener is therefore also a hard failure — the DP
-- cannot verify what it cannot see.
--
-- Signature/exp/aud validation is NOT this plugin's job (openid-connect at
-- the DP and the MCP servers own that); this plugin binds the token to the
-- TLS channel and nothing else, so a stolen cnf token is useless without
-- the workload's private key.
--
-- Runs globally (certificate phase must execute before a route is matched).
-- Rejections emit a single-line JSON audit record (contract §9 fields) on
-- the proxy error log, picked up by the Phase 6 audit spine.

local cjson = require "cjson.safe"
local sha256 = require "resty.sha256"

local CnfCheck = {
  PRIORITY = 1100, -- before openid-connect (1050): channel binding first
  VERSION = "0.1.0",
}

local function b64url(raw)
  return (ngx.encode_base64(raw):gsub("+", "-"):gsub("/", "_"):gsub("=", ""))
end

-- x5t#S256 of the leaf certificate in a PEM chain (RFC 8705 §3.1:
-- base64url(SHA-256(DER)) — no padding).
local function leaf_thumbprint(pem_chain)
  local body = pem_chain:match("%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-(.-)%-%-%-%-%-END CERTIFICATE%-%-%-%-%-")
  if not body then return nil end
  local der = ngx.decode_base64((body:gsub("%s", "")))
  if not der then return nil end
  local digest = sha256:new()
  digest:update(der)
  return b64url(digest:final())
end

-- Unverified payload decode: enough to read cnf/jti; authenticity is the
-- signature validators' job downstream.
local function token_claims(token)
  local payload = token:match("^[^.]+%.([^.]+)%.")
  if not payload then return nil end
  payload = payload:gsub("-", "+"):gsub("_", "/")
  payload = payload .. string.rep("=", (4 - #payload % 4) % 4)
  local raw = ngx.decode_base64(payload)
  local claims = raw and cjson.decode(raw)
  if type(claims) ~= "table" then return nil end
  return claims
end

local function deny(reason, claims)
  local route = kong.router.get_route()
  kong.log.warn(cjson.encode({
    audit = "cnf-check",
    decision = "deny",
    reason = reason,
    token_id = claims.jti,
    principal = claims.sub,
    client = claims.azp,
    origin_idp = claims.idp_origin,
    tier = claims.mcp_tier,
    route = route and route.name or ngx.null,
    ts = ngx.now(),
  }))
  return kong.response.exit(401, { message = "certificate-bound token: " .. reason }, {
    ["WWW-Authenticate"] = 'Bearer realm="mcp-internal", error="invalid_token", error_description="'
      .. reason .. '"',
  })
end

function CnfCheck:certificate(conf)
  -- Ask every TLS client for a certificate; verification is the thumbprint
  -- comparison below, not a CA allowlist — the token's cnf is the authority.
  local ok, err = kong.client.tls.request_client_certificate()
  if not ok then
    kong.log.warn("cnf-check: request_client_certificate failed: ", err)
  end
end

function CnfCheck:access(conf)
  local auth = kong.request.get_header("authorization") or ""
  local token = auth:match("^[Bb]earer%s+(.+)$")
  if not token then return end -- unauthenticated: upstream challenges

  local claims = token_claims(token)
  if not claims then return end -- malformed: signature validators reject

  local cnf = claims.cnf
  if type(cnf) ~= "table" or type(cnf["x5t#S256"]) ~= "string" then
    return -- bearer path: nothing to bind
  end

  local got_chain, chain = pcall(kong.client.tls.get_full_client_certificate_chain)
  if not got_chain or type(chain) ~= "string" then
    return deny("no_client_certificate", claims)
  end

  local presented = leaf_thumbprint(chain)
  if not presented then
    return deny("unreadable_client_certificate", claims)
  end
  if presented ~= cnf["x5t#S256"] then
    return deny("thumbprint_mismatch", claims)
  end
end

return CnfCheck
