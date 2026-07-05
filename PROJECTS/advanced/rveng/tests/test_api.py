"""
©AngelaMos | 2026
test_api.py
"""

import pytest
from fastapi.testclient import TestClient

from rveng.api.app import create_app
from rveng.api.limits import MAX_HEX_BYTES

ELF_MAGIC_LINE = (
    "00000000  7f 45 4c 46 02 01 01 00  "
    "00 00 00 00 00 00 00 00  |.ELF............|"
)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


def test_list_has_three_seed_challenges(client: TestClient):
    body = client.get("/api/challenges").json()
    ids = {c["id"] for c in body}
    assert ids == {
        "03-flip-the-gate", "04-name-the-function", "05-find-the-gate"}


def test_detail_does_not_leak_source_or_answer(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate").json()
    assert body["category"] == "found_value"
    assert "source" not in body
    assert "answer" not in body
    assert "expected" not in body


def test_missing_challenge_is_404(client: TestClient):
    assert client.get("/api/challenges/nope").status_code == 404


def test_hex_first_line_is_elf_magic(client: TestClient):
    body = client.get(
        "/api/challenges/05-find-the-gate/hex?offset=0&length=16").json()
    assert body["lines"][0] == ELF_MAGIC_LINE


def test_hex_length_is_capped(client: TestClient):
    body = client.get(
        "/api/challenges/05-find-the-gate/hex?length=999999").json()
    assert body["length"] == MAX_HEX_BYTES


def test_elf_view_reports_entry_and_functions(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/elf").json()
    assert body["entry"] == 0x401060
    names = {f["name"] for f in body["functions"]}
    assert "check" in names and "main" in names


def test_disasm_marks_the_gate(client: TestClient):
    body = client.get(
        "/api/challenges/05-find-the-gate/disasm?symbol=check").json()
    assert body["gate_address"] == 0x40114D
    gate = next(i for i in body["instructions"] if i["is_gate"])
    assert gate["mnemonic"] == "cmp"
    assert gate["immediate"] == 1337


def test_disasm_unknown_symbol_is_404(client: TestClient):
    r = client.get("/api/challenges/05-find-the-gate/disasm?symbol=nope")
    assert r.status_code == 404


def test_strings_finds_the_secret(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/strings").json()
    texts = {s["text"] for s in body["strings"]}
    assert "the_flag_is_here" in texts


def test_submit_found_value_correct_reveals_source(client: TestClient):
    r = client.post(
        "/api/challenges/05-find-the-gate/submit",
        json={"answer": "0x539"}).json()
    assert r["correct"] is True
    assert "1337" in r["revealed_source"] or "the_flag" in r["revealed_source"]


def test_submit_found_value_wrong_hides_source(client: TestClient):
    r = client.post(
        "/api/challenges/05-find-the-gate/submit",
        json={"answer": "42"}).json()
    assert r["correct"] is False
    assert r["revealed_source"] is None


def test_submit_identified_symbol(client: TestClient):
    r = client.post(
        "/api/challenges/04-name-the-function/submit",
        json={"answer": "check"}).json()
    assert r["correct"] is True


def test_submit_patched_bytes_correct(client: TestClient):
    r = client.post(
        "/api/challenges/03-flip-the-gate/submit",
        json={"answer": "9090"}).json()
    assert r["correct"] is True


def test_submit_bad_hex_does_not_500(client: TestClient):
    r = client.post(
        "/api/challenges/03-flip-the-gate/submit",
        json={"answer": "zz"})
    assert r.status_code == 200
    assert r.json()["correct"] is False


def test_submit_oversized_answer_rejected(client: TestClient):
    r = client.post(
        "/api/challenges/05-find-the-gate/submit",
        json={"answer": "9" * 100000})
    assert r.status_code == 413


def test_progress_tracks_solves(client: TestClient):
    client.post(
        "/api/challenges/05-find-the-gate/submit",
        json={"answer": "1337", "session": "s1"})
    body = client.get("/api/progress?session=s1").json()
    assert body["solved"] == ["05-find-the-gate"]
    assert body["total"] == 3
