"""V1.10.0 — each laptop gets its own scanner record although all laptops of one user
bind the same emailed access token.

Field state: Laptop-NITIN online, Laptop-DESKTOP-J19GUGP always "offline". Agent auth
resolved the token with "... LIMIT 1", so every laptop holding the user's token
heartbeated and claimed jobs as one record. The agent now sends its Windows computer
name (X-Aetheris-Agent-Computer) and install id (X-Aetheris-Agent-Instance)."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from app.services.scanner_agent_auth import pick_laptop_scanner, resolve_edge_scanner

NOW = datetime(2026, 10, 16, 9, 0, tzinfo=timezone.utc)


def _row(id_, name, computer=None, instance=None, hb_min=None):
    return {"id": id_, "name": name, "agent_computer_name": computer, "agent_instance_id": instance,
            "agent_token_hint": "...abcd", "scanner_role": "portable",
            "last_heartbeat_at": NOW - timedelta(minutes=hb_min) if hb_min is not None else None}


NITIN = _row("11111111-1111-1111-1111-111111111111", "Laptop-NITIN", hb_min=0)
J19 = _row("22222222-2222-2222-2222-222222222222", "Laptop-DESKTOP-J19GUGP", hb_min=600)


# --- record picker -------------------------------------------------------------
def test_each_laptop_picks_its_own_record_by_name_and_claims_it():
    assert pick_laptop_scanner([NITIN, J19], computer="DESKTOP-J19GUGP", instance="i-j19") == (J19, True)
    assert pick_laptop_scanner([NITIN, J19], computer="NITIN", instance="i-nitin") == (NITIN, True)


def test_a_bound_record_is_found_by_computer_name():
    bound = dict(J19, agent_computer_name="DESKTOP-J19GUGP", agent_instance_id="i-j19")
    assert pick_laptop_scanner([NITIN, bound], computer="desktop-j19gugp", instance="i-j19") == (bound, False)
    # reinstalled agent (new instance id): same computer, identity refreshed
    assert pick_laptop_scanner([NITIN, bound], computer="DESKTOP-J19GUGP", instance="i-new") == (bound, True)


def test_never_takes_a_record_bound_to_another_computer_or_named_after_another_laptop():
    nitin_bound = dict(NITIN, agent_computer_name="NITIN")
    assert pick_laptop_scanner([nitin_bound], computer="DESKTOP-J19GUGP", instance="x") == (None, False)
    # only one record, unbound, but it is "Laptop-<other computer>": not ours either
    assert pick_laptop_scanner([NITIN], computer="DESKTOP-J19GUGP", instance="x") == (None, False)
    # SCANNER_ID copied from the other laptop's .env is ignored
    assert pick_laptop_scanner([NITIN], computer="DESKTOP-J19GUGP", instance="x",
                               preferred_id=NITIN["id"]) == (None, False)


def test_single_renamed_record_of_a_pre_1_10_laptop_is_kept():
    renamed = _row("33333333-3333-3333-3333-333333333333", "Nitin-test", hb_min=1)
    assert pick_laptop_scanner([renamed], computer="DESKTOP-JA5BG0K", instance="i") == (renamed, True)


def test_agent_without_computer_name_keeps_old_behaviour_deterministically():
    row, claim = pick_laptop_scanner([J19, NITIN], computer="", instance="")
    assert row is NITIN and claim is False  # most recently seen record
    bound = dict(J19, agent_instance_id="i-j19")
    assert pick_laptop_scanner([NITIN, bound], computer="", instance="i-j19") == (bound, False)


# --- resolver with a fake database -------------------------------------------------
def _resolve(rows, reuse=None, **kw):
    writes = []
    created = {"id": "44444444-4444-4444-4444-444444444444"}

    def one(db, sql, params=None):
        if "INSERT INTO vuln_scanners" in sql:
            writes.append(("insert", params))
            return dict(created, name=params["name"], agent_computer_name=params["comp"])
        if "lower(name) = lower(:name)" in sql:
            return reuse
        if "WHERE id = CAST(:id AS uuid)" in sql:
            return dict(reuse or {}, agent_computer_name=kw.get("computer"))
        return None

    with patch("app.services.scanner_agent_auth.fetchall", return_value=rows), \
         patch("app.services.scanner_agent_auth.fetchone", side_effect=one), \
         patch("app.services.scanner_agent_auth.execute", side_effect=lambda db, sql, params=None: writes.append(("exec", params))), \
         patch("app.services.scanner_credentials.ensure_scanner_role_column"):
        db = SimpleNamespace(commit=lambda: None)
        return resolve_edge_scanner(db, "hash", **kw), writes


def test_two_laptops_with_one_token_resolve_to_two_records():
    row, writes = _resolve([NITIN, J19], computer="DESKTOP-J19GUGP", instance="i-j19")
    assert row["id"] == J19["id"] and row["agent_computer_name"] == "DESKTOP-J19GUGP"
    assert writes[0][1]["comp"] == "DESKTOP-J19GUGP" and writes[0][1]["id"] == J19["id"]
    row, _ = _resolve([NITIN, J19], computer="NITIN", instance="i-nitin")
    assert row["id"] == NITIN["id"]


def test_new_laptop_with_the_users_token_is_registered_under_its_own_name():
    nitin_bound = dict(NITIN, agent_computer_name="NITIN")
    row, writes = _resolve([nitin_bound], computer="DESKTOP-NEWPC", instance="i-new")
    inserts = [w for w in writes if w[0] == "insert"]
    assert inserts and inserts[0][1]["name"] == "Laptop-DESKTOP-NEWPC"
    assert inserts[0][1]["th"] == "hash" and inserts[0][1]["comp"] == "DESKTOP-NEWPC"
    assert row["name"] == "Laptop-DESKTOP-NEWPC"


def test_existing_record_named_after_this_laptop_is_reused_not_duplicated():
    nitin_bound = dict(NITIN, agent_computer_name="NITIN")
    old_j19 = dict(J19, agent_token_hint="...old")
    row, writes = _resolve([nitin_bound], reuse=old_j19, computer="DESKTOP-J19GUGP", instance="i-j19")
    assert not [w for w in writes if w[0] == "insert"]
    upd = [w for w in writes if w[0] == "exec"][0][1]
    assert upd["id"] == J19["id"] and upd["th"] == "hash" and upd["comp"] == "DESKTOP-J19GUGP"


def test_unknown_token_is_still_rejected():
    row, writes = _resolve([], computer="DESKTOP-J19GUGP", instance="i")
    assert row is None and not writes


# --- bind-client-token (Start-Laptop sign-in) -----------------------------------------
def _bind(body_kw, rows):
    from app.routers import vuln

    writes = []

    def one(db, sql, params=None):
        if "INSERT INTO vuln_scanners" in sql:
            writes.append(("insert", params))
            return {"id": "55555555-5555-5555-5555-555555555555", "name": params["name"], "url": "agent://edge",
                    "status": "active", "agent_computer_name": params["comp"]}
        if "WHERE id = CAST(:id AS uuid)" in sql:
            return next(r for r in rows if r["id"] == params["id"])
        return None

    current = SimpleNamespace(tenant="p", email="support@aetheris.in", user_id="u1")
    db = SimpleNamespace(commit=lambda: None)
    with patch("app.services.client_access_token.parse_and_verify", return_value=("p", "support@aetheris.in")), \
         patch.object(vuln, "_require_vuln_module", lambda: None), \
         patch("app.services.scanner_credentials.ensure_scanner_role_column"), \
         patch("app.services.scanner_agent_auth.ensure_edge_agent_recovery_columns"), \
         patch.object(vuln, "fetchall", return_value=rows), \
         patch.object(vuln, "fetchone", side_effect=one), \
         patch.object(vuln, "execute", side_effect=lambda db, sql, params=None: writes.append(("exec", params))), \
         patch.object(vuln, "audit", lambda *a, **k: None), \
         patch.object(vuln, "row_scanner", lambda r: dict(r)):
        out = vuln.bind_scanner_client_token(vuln.BindClientTokenIn(token="tok", **body_kw), db=db, current=current)
    return out, writes


def _edge(row):
    return dict(row, connection_mode="edge_agent", url="agent://edge", status="active")


def test_bind_with_copied_scanner_id_binds_this_laptops_own_record():
    rows = [_edge(dict(NITIN, agent_computer_name="NITIN")), _edge(J19)]
    out, writes = _bind({"name": "Laptop-DESKTOP-J19GUGP", "scanner_id": NITIN["id"],
                         "computer_name": "DESKTOP-J19GUGP", "agent_instance_id": "i-j19"}, rows)
    upd = [w for w in writes if w[0] == "exec"][0][1]
    assert upd["id"] == J19["id"] and upd["comp"] == "DESKTOP-J19GUGP" and upd["inst"] == "i-j19"
    assert out["id"] == J19["id"]


def test_bind_on_a_new_laptop_creates_its_record_instead_of_taking_the_only_one():
    rows = [_edge(NITIN)]  # the only laptop record, not yet bound to a computer
    out, writes = _bind({"name": "", "computer_name": "DESKTOP-NEWPC", "agent_instance_id": "i-new"}, rows)
    ins = [w for w in writes if w[0] == "insert"]
    assert ins and ins[0][1]["name"] == "Laptop-DESKTOP-NEWPC" and ins[0][1]["comp"] == "DESKTOP-NEWPC"


def test_bind_from_an_old_laptop_script_keeps_previous_rules():
    rows = [_edge(NITIN)]
    out, writes = _bind({"name": "Laptop-SOMETHING"}, rows)
    assert [w for w in writes if w[0] == "exec"][0][1]["id"] == NITIN["id"]
