-- dpop-check: RFC 9449 DPoP sender-constraint enforcement at the DP.
--
-- The public-client analogue of cnf-check. Where cnf-check binds a token to a
-- TLS client certificate (cnf.x5t#S256), this binds a token to a client-held
-- key (cnf.jkt): every request must carry a fresh, matching DPoP proof, so a
-- stolen access token is useless without the private key that signed the proof.
--
-- Scope of THIS layer (early rejection): the proof is structurally well-formed,
-- its embedded key's thumbprint equals the token's cnf.jkt, and htm/htu/iat/ath
-- match this request, and the jti has not been seen (single-entry DP → a shared
-- dict is authoritative for replay). What this layer deliberately does NOT do is
-- verify the proof's ECDSA signature — consistent with the repo doctrine that
-- the DP performs no cryptographic token validation on first-party routes (the
-- tier wall base64-decodes without verifying too). The MCP servers' `requireDpop`
-- middleware (jose EmbeddedJWK) is the AUTHORITATIVE signature check. The residual
-- this split leaves — a proof carrying the correct public key but an invalid
-- signature — requires possessing the (public) key yet not the private key, and
-- is closed at the server. See plugins/dpop-check/README.md.
--
-- Runs globally in the access phase; claim-driven, so bearer tokens (no cnf.jkt)
-- pass straight through and the claude-code path is untouched. Rejections emit a
-- single-line JSON audit record (contract §9 fields) picked up by the audit spine.

local cjson = require "cjson.safe"
local sha256 = require "resty.sha256"

local DpopCheck = {
  PRIORITY = 1010, -- after cnf-check (1100) and the tier wall; before proxying
  VERSION = "0.1.0",
}

local IAT_WINDOW = 60           -- ± seconds of accepted proof-issuance skew
local JTI_TTL = 2 * IAT_WINDOW  -- replay-cache lifetime ≥ the acceptance window

local function b64url_encode(raw)
  return (ngx.encode_base64(raw):gsub("+", "-"):gsub("/", "_"):gsub("=", ""))
end

local function b64url_decode(s)
  if type(s) ~= "string" then return nil end
  s = s:gsub("-", "+"):gsub("_", "/")
  s = s .. string.rep("=", (4 - #s % 4) % 4)
  return ngx.decode_base64(s)
end

-- Unverified payload decode: enough to read cnf/jti; authenticity is downstream.
local function token_claims(token)
  local payload = token:match("^[^.]+%.([^.]+)%.")
  if not payload then return nil end
  local raw = b64url_decode(payload)
  local claims = raw and cjson.decode(raw)
  if type(claims) ~= "table" then return nil end
  return claims
end

-- RFC 7638 JWK thumbprint of an EC P-256 public key: SHA-256 over the canonical
-- JSON with lexicographically-ordered required members and no whitespace.
local function ec_jwk_thumbprint(jwk)
  if type(jwk) ~= "table" or jwk.kty ~= "EC" or jwk.crv ~= "P-256"
     or type(jwk.x) ~= "string" or type(jwk.y) ~= "string" then
    return nil
  end
  local canonical = string.format(
    '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}', jwk.x, jwk.y)
  local d = sha256:new()
  d:update(canonical)
  return b64url_encode(d:final())
end

local function ath_of(token)
  local d = sha256:new()
  d:update(token)
  return b64url_encode(d:final())
end

local function decode_segment(seg)
  local raw = b64url_decode(seg)
  local obj = raw and cjson.decode(raw)
  if type(obj) ~= "table" then return nil end
  return obj
end

local function deny(reason, claims)
  local route = kong.router.get_route()
  kong.log.warn(cjson.encode({
    audit = "dpop-check",
    decision = "deny",
    reason = reason,
    token_id = claims and claims.jti or ngx.null,
    principal = claims and claims.sub or ngx.null,
    client = claims and claims.azp or ngx.null,
    origin_idp = claims and claims.idp_origin or ngx.null,
    tier = claims and claims.mcp_tier or ngx.null,
    route = route and route.name or ngx.null,
    ts = ngx.now(),
  }))
  return kong.response.exit(401, { message = "dpop: " .. reason }, {
    ["WWW-Authenticate"] = 'DPoP algs="ES256", error="invalid_dpop_proof", error_description="'
      .. reason .. '"',
  })
end

function DpopCheck:access(conf)
  local auth = kong.request.get_header("authorization") or ""
  local scheme, token = auth:match("^(%a+)%s+(.+)$")
  if not token then return end -- unauthenticated: upstream challenges

  local claims = token_claims(token)
  if not claims then return end -- malformed: signature validators reject

  local cnf = claims.cnf
  if type(cnf) ~= "table" or type(cnf.jkt) ~= "string" then
    return -- bearer path: nothing to sender-constrain
  end

  -- A jkt-bound token MUST be presented under the DPoP scheme (RFC 9449 §7.1).
  if not scheme or scheme:lower() ~= "dpop" then
    return deny("wrong_auth_scheme", claims)
  end

  -- Exactly one DPoP proof header.
  local proof = kong.request.get_header("dpop")
  if not proof then return deny("missing_proof", claims) end
  if type(proof) == "table" then return deny("multiple_proofs", claims) end

  local header_seg, payload_seg = proof:match("^([^.]+)%.([^.]+)%.[^.]+$")
  if not header_seg then return deny("malformed_proof", claims) end

  local header = decode_segment(header_seg)
  if not header or header.typ ~= "dpop+jwt" or header.alg ~= "ES256" then
    return deny("bad_proof_header", claims)
  end
  local jwk = header.jwk
  if type(jwk) ~= "table" or jwk.d ~= nil then
    return deny("bad_proof_jwk", claims) -- missing key, or private material present
  end

  -- Binding: the proof key's thumbprint MUST equal the token's cnf.jkt.
  local thumb = ec_jwk_thumbprint(jwk)
  if not thumb then return deny("bad_proof_jwk", claims) end
  if thumb ~= cnf.jkt then return deny("thumbprint_mismatch", claims) end

  local payload = decode_segment(payload_seg)
  if not payload then return deny("malformed_proof", claims) end

  if payload.htm ~= kong.request.get_method() then
    return deny("htm_mismatch", claims)
  end

  -- htu: scheme://authority/path of THIS inbound request (pre strip_path),
  -- query and fragment ignored per RFC 9449 §4.3. The authority comes from the
  -- Host header (the client-facing host:port the client actually signed), not
  -- kong.request.get_port() which is the DP's internal listen port.
  local scheme = kong.request.get_scheme()
  local authority = kong.request.get_header("host") or kong.request.get_host()
  local path = kong.request.get_path()
  local expected_htu = scheme .. "://" .. authority .. path
  local got_htu = type(payload.htu) == "string" and payload.htu:match("^[^?#]*") or ""
  -- Also accept the form with the scheme-default port dropped/added.
  local default_port = (scheme == "https") and ":443" or ":80"
  local authority_no_default = authority:gsub(default_port .. "$", "")
  local alt_htu = scheme .. "://" .. authority_no_default .. path
  if got_htu ~= expected_htu and got_htu ~= alt_htu then
    return deny("htu_mismatch", claims)
  end

  if type(payload.iat) ~= "number" or math.abs(ngx.now() - payload.iat) > IAT_WINDOW then
    return deny("stale_proof", claims)
  end

  if payload.ath ~= ath_of(token) then
    return deny("ath_mismatch", claims)
  end

  if type(payload.jti) ~= "string" or #payload.jti == 0 or #payload.jti > 256 then
    return deny("bad_jti", claims)
  end

  -- Single-use replay defense. The internal DP is the single entry point, so a
  -- shared dict is globally authoritative here (production: a shared cache at
  -- the resource servers, since their replicas are stateless). Fail closed: a
  -- missing dict or a failed insert means replay can no longer be excluded.
  local cache = ngx.shared.dpop_jti
  if not cache then
    kong.log.err("dpop_jti shared dict is not configured; refusing DPoP traffic")
    return kong.response.exit(503, { message = "dpop: replay cache unavailable" })
  end
  local ok, err, forcible = cache:add(cnf.jkt .. ":" .. payload.jti, true, JTI_TTL)
  if not ok then
    if err == "exists" then
      return deny("proof_replay", claims)
    end
    kong.log.err("dpop_jti cache add failed: ", err)
    return kong.response.exit(503, { message = "dpop: replay cache unavailable" })
  end
  if forcible then
    -- The dict evicted unexpired entries to fit this one: replay tracking is
    -- degraded under memory pressure. Detection-only — the evicted entry is
    -- already gone, so denying THIS request would not protect anyone.
    kong.log.warn(cjson.encode({
      audit = "dpop-check",
      decision = "degraded",
      reason = "jti_cache_eviction",
      token_id = claims.jti or ngx.null,
      ts = ngx.now(),
    }))
  end
end

return DpopCheck
