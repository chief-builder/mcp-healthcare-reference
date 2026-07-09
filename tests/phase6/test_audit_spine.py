"""Phase 6 acceptance: the audit spine (plan §3).

Pick a vendor action and walk it back to the human, client, gateway
decision, and DLP verdict in ONE Loki query keyed by the token jti;
a DLP block joins the same way; first-party MCP tool calls carry the
§9 tuple; Kong traces land in Tempo; no token material on the spine.

Requires the compose/phase5 stack up (re-run ./setup-phase5.sh after
pulling phase 6: it rebuilds the servers and syncs the otel deck config).
"""
import requests

from conftest import (EGRESS_MOCKHUB, GRAFANA, SCHED_MCP, TEMPO, claims_of,
                      do_consent, loki_query, mcp_call, tuple_records, wait_for)


def audits(records: list[tuple[dict, dict]]) -> set[tuple[str, str]]:
    return {(rec.get("audit", ""), rec.get("decision", rec.get("audit", "")))
            for _, rec in records}


def test_vendor_call_walks_back_in_one_query(alice):
    """create_issue at the vendor -> gateway decision (vendor-token), DLP
    verdict, and broker resolve all join on the hub jti in a single query."""
    do_consent(alice)
    r = mcp_call(EGRESS_MOCKHUB, alice, "create_issue", {"title": "audit spine walk-back"})
    assert r.status_code == 200, r.text
    claims = claims_of(alice)
    jti = claims["jti"]

    def complete():
        records = tuple_records(jti)
        seen = audits(records)
        need = {("vendor-token", "allow"), ("dlp-egress", "allow"), ("broker.resolve", "allow")}
        return records if need <= seen else None

    records = wait_for(complete, 90, what="vendor-token + dlp-egress + broker.resolve joined on jti")

    # The tuple crosses shipping paths: Kong via OTLP, broker via container logs.
    assert {s.get("service_name") for s, _ in records} >= {"kong-internal", "broker"}

    # §9 fields answer "which human, through which client" directly.
    for _, rec in records:
        if rec.get("audit") == "vendor-token":
            assert rec["principal"] == claims["sub"]
            assert rec["client"] == claims["azp"]
            break


def test_dlp_block_joins_on_the_same_jti(alice):
    r = mcp_call(EGRESS_MOCKHUB, alice, "create_issue",
                 {"title": "chart note", "body": "patient MRN-1234567"})
    assert r.status_code == 403, r.text
    jti = claims_of(alice)["jti"]

    def blocked():
        for _, rec in tuple_records(jti):
            if (rec.get("audit"), rec.get("decision"), rec.get("pattern")) == \
                    ("dlp-egress", "deny", "mrn"):
                return rec
        return None

    rec = wait_for(blocked, 90, what="dlp-egress deny (pattern=mrn) joined on jti")
    assert rec["principal"] == claims_of(alice)["sub"]


def test_first_party_tool_call_carries_the_tuple(alice_internal):
    r = mcp_call(SCHED_MCP, alice_internal, "find-slots", {})
    assert r.status_code == 200, r.text
    claims = claims_of(alice_internal)

    def audited():
        for _, rec in tuple_records(claims["jti"]):
            if rec.get("audit") == "mcp-server" and rec.get("tool") == "find-slots":
                return rec
        return None

    rec = wait_for(audited, 90, what="mcp-server audit record joined on jti")
    assert rec["server"] == "mcp://srv/scheduling"
    assert rec["decision"] == "allow"
    assert rec["principal"] == claims["sub"]
    assert rec["origin_idp"] == "ping"
    assert rec["tier"] == "internal"


def test_kong_traces_reach_tempo():
    def traces():
        r = requests.get(f"{TEMPO}/api/search",
                         params={"q": '{resource.service.name="kong-internal"}',
                                 "limit": "5"}, timeout=15)
        if r.status_code != 200:
            return None
        return r.json().get("traces") or None

    assert wait_for(traces, 90, what="kong-internal traces in Tempo")


def test_tuple_dashboard_is_provisioned(env):
    r = requests.get(f"{GRAFANA}/api/dashboards/uid/mcp-audit-tuple",
                     auth=("admin", env["GRAFANA_ADMIN_PASSWORD"]), timeout=15)
    assert r.status_code == 200, r.text
    assert r.json()["dashboard"]["title"] == "MCP Audit Tuple"


def test_no_token_material_on_the_spine(alice):
    """The spine must not become the leak: the bearer token (its unique
    signature segment) appears in no shipped log line. Runs last, after the
    token has crossed Kong, the broker, and the servers."""
    signature = alice.split(".")[2]
    hits = loki_query('{service_name=~".+"} |= "%s"' % signature)
    assert hits == [], f"token material leaked to the audit spine: {hits[:2]}"
