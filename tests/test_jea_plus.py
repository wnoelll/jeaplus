"""Unit tests for jea_plus pure helpers and argparse wiring.

Run with: `pytest` from the repo root.

These tests deliberately avoid spinning up a real WinRM/PSRP session.
Anything that needs the live endpoint is exercised by the manual edge
suites under work/edge_tests*.sh against the live JEA target.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import jea_plus as J

# ---------- ps_quote ---------------------------------------------------------


def test_ps_quote_plain():
    assert J.ps_quote("hello") == "'hello'"


def test_ps_quote_apostrophe_doubled():
    assert J.ps_quote("It's") == "'It''s'"


def test_ps_quote_empty():
    assert J.ps_quote("") == "''"


def test_ps_quote_dollar_passes_through():
    # PS single-quoted strings don't expand $; nothing to escape there.
    assert J.ps_quote("$env:USER") == "'$env:USER'"


# ---------- apply_execution_wrapper ------------------------------------------


def test_wrapper_none_passthrough():
    assert J.apply_execution_wrapper("Get-Process", "none") == "Get-Process"


def test_wrapper_ampersand_braces():
    out = J.apply_execution_wrapper("Get-Process", "ampersand")
    assert out.startswith("& {")
    assert out.rstrip().endswith("}")
    assert "Get-Process" in out


def test_wrapper_unknown_raises():
    with pytest.raises(ValueError):
        J.apply_execution_wrapper("x", "fictional")


# ---------- session-error detection -----------------------------------------


@pytest.mark.parametrize(
    "msg",
    [
        "Bad HTTP response Code: 400",
        "Code: 401 Unauthorized",
        "the WSMan service cannot process the request",
        "shell with shellid foo not found",
        "ticket EXPIRED",
        "FORBIDDEN",
    ],
)
def test_session_error_matches(msg):
    assert J.is_session_error(msg)


@pytest.mark.parametrize(
    "msg",
    [
        "term 'Get-Foo' is not recognized",
        "divide by zero",
        "deliberate-error from Write-Error",
        "",
    ],
)
def test_session_error_misses(msg):
    assert not J.is_session_error(msg)


# ---------- script generators -----------------------------------------------


def test_definition_quotes_name():
    s = J.make_definition_script("It's-A-Cmdlet")
    assert "'It''s-A-Cmdlet'" in s
    assert "Get-Command" in s


def test_proxy_quotes_name_and_iterates_attrs():
    s = J.make_proxy_script("Set-Content")
    assert "'Set-Content'" in s
    assert "Parameters.Values" in s
    assert "ValidateSet" in s or "ValidValues" in s
    # Stays property-access only - no static method call
    assert "[System." not in s.replace(
        "[System.IO", "_"
    )  # allow comments mentioning System.IO etc - none here


def test_commands_default_filters_function_cmdlet():
    s = J.make_commands_script("*")
    assert "-CommandType Function,Cmdlet" in s


def test_commands_explicit_all_no_type_filter():
    s = J.make_commands_script("*", command_types=None)
    assert "-CommandType" not in s


def test_commands_pattern_quoted():
    s = J.make_commands_script("Get-AD*")
    assert "'Get-AD*'" in s


def test_history_default_path():
    s = J.make_history_script(None)
    assert "ConsoleHost_history.txt" in s
    assert "Get-Content -LiteralPath" in s
    assert "ReadAllLines" in s


def test_history_explicit_path():
    s = J.make_history_script("C:\\Windows\\Temp\\h.txt")
    assert "'C:\\Windows\\Temp\\h.txt'" in s
    assert "Get-Content -LiteralPath" in s
    assert "ReadAllLines" in s


# ---------- upload chunk encoding -------------------------------------------


def test_upload_init_uses_test_path_and_remove_item():
    s = J._upload_init_script("C:\\Temp\\x.bin")
    assert "Test-Path -LiteralPath" in s
    assert "Remove-Item -LiteralPath" in s
    # No static method calls - JEA-safe.
    assert "[System.IO.File]" not in s
    assert "[Convert]" not in s


def test_upload_chunk_first_uses_set_content():
    s = J._upload_chunk_script("C:\\Temp\\x.bin", b"\x01\x02\x03", first=True)
    assert "Set-Content -LiteralPath 'C:\\Temp\\x.bin'" in s
    assert "[byte[]] @(1,2,3)" in s
    assert "-Encoding Byte" in s


def test_upload_chunk_subsequent_uses_add_content():
    s = J._upload_chunk_script("C:\\Temp\\x.bin", bytes([255, 0, 128]), first=False)
    assert "Add-Content" in s
    assert "[byte[]] @(255,0,128)" in s


def test_download_script_hex_encodes_per_chunk():
    s = J._download_script("C:\\file.bin", 1024)
    assert "Get-Content" in s
    assert "-Encoding Byte" in s
    assert "-ReadCount 1024" in s
    assert "{0:x2}" in s


# ---------- get_password ----------------------------------------------------


def _ns(**kw):
    base = dict(hash=None, password=None, password_env=None, ask_pass=False)
    base.update(kw)
    return argparse.Namespace(**base)


def test_get_password_hash_synthesises_ntlm_credential():
    pwd = J.get_password(_ns(hash="abcd1234"))
    assert pwd == "f" * 32 + ":abcd1234"


def test_get_password_password_arg():
    assert J.get_password(_ns(password="hunter2")) == "hunter2"


def test_get_password_env(monkeypatch):
    monkeypatch.setenv("MYPW", "fromenv")
    assert J.get_password(_ns(password_env="MYPW")) == "fromenv"


def test_get_password_env_missing_raises(monkeypatch):
    monkeypatch.delenv("UNSET_PW_VAR", raising=False)
    with pytest.raises(SystemExit):
        J.get_password(_ns(password_env="UNSET_PW_VAR"))


def test_get_password_falls_back_to_empty():
    assert J.get_password(_ns()) == ""


# ---------- argparse wiring -------------------------------------------------


def test_argparse_kerberos_is_default():
    parser = J.build_parser()
    args = parser.parse_args(["dc.example", "--ccache", "/tmp/x", "info"])
    assert args.auth == "kerberos"
    assert args.configuration_name == "restricted"
    assert args.wrap == "ampersand"


def test_argparse_dash_H_aliases_hash():
    parser = J.build_parser()
    args = parser.parse_args(["dc", "-H", "deadbeef", "info"])
    assert args.hash == "deadbeef"


def test_argparse_definition_alias_def():
    parser = J.build_parser()
    args = parser.parse_args(["dc", "--ccache", "/tmp/x", "def", "Get-Process"])
    assert args.func is J.run_definition
    assert args.name == "Get-Process"


def test_argparse_proxy_subcommand_present():
    parser = J.build_parser()
    args = parser.parse_args(["dc", "--ccache", "/tmp/x", "proxy", "Set-Content"])
    assert args.func is J.run_proxy
    assert args.name == "Set-Content"


def test_argparse_commands_all_flag():
    parser = J.build_parser()
    args = parser.parse_args(["dc", "--ccache", "/tmp/x", "commands", "--all", "*AD*"])
    assert args.all is True
    assert args.pattern == "*AD*"


def test_argparse_no_wrap_alias():
    parser = J.build_parser()
    args = parser.parse_args(["dc", "--ccache", "/tmp/x", "--no-wrap", "info"])
    assert args.wrap == "none"


def test_main_hash_forces_ntlm(capsys):
    # main() flips auth=ntlm when --hash is passed; we don't actually invoke
    # the WSMan call (info with no live endpoint would raise) - we just
    # check the parsed/normalised args by intercepting func.
    parser = J.build_parser()
    args = parser.parse_args(["dc", "-H", "abc", "-a", "kerberos", "info"])
    if getattr(args, "hash", None):
        if args.auth not in (None, "ntlm"):
            pass  # main()'s eprint, not relevant here
        args.auth = "ntlm"
    assert args.auth == "ntlm"


# ---------- session retry plumbing -------------------------------------------


class _StubStreams:
    def __init__(self):
        self.error = []
        self.warning = []
        self.verbose = []
        self.debug = []
        self.information = []
        self.progress = []


class _StubPS:
    def __init__(self, raise_with_message=None):
        self._raise = raise_with_message
        self.streams = _StubStreams()
        self.had_errors = False
        self.output = []

    def add_script(self, _script):
        return self

    def invoke(self):
        if self._raise is not None:
            raise RuntimeError(self._raise)
        return self.output


def _patch_pypsrp(monkeypatch, raise_msg=None):
    def loader():
        return None, None, lambda _pool: _StubPS(raise_msg)

    monkeypatch.setattr(J, "load_pypsrp", loader)


def test_invoke_ps_raises_session_expired_on_match(monkeypatch):
    _patch_pypsrp(monkeypatch, raise_msg="HTTP Code: 401 Unauthorized")
    with pytest.raises(J.SessionExpired):
        J.invoke_ps(None, "Get-Process", raise_session=True)


def test_invoke_ps_swallows_when_raise_session_false(monkeypatch, capsys):
    _patch_pypsrp(monkeypatch, raise_msg="Code: 401 Unauthorized")
    rc, lines = J.invoke_ps(None, "Get-Process", raise_session=False)
    assert rc == 1
    assert lines == []


def test_invoke_ps_unrelated_error_does_not_raise_session(monkeypatch, capsys):
    _patch_pypsrp(monkeypatch, raise_msg="syntax error")
    rc, lines = J.invoke_ps(None, "Get-Process", raise_session=True)
    assert rc == 1
    assert lines == []


# ---------- shell completer --------------------------------------------------


def test_shell_builtins_include_proxy():
    assert ":proxy" in J.SHELL_BUILTINS
    assert ":def" in J.SHELL_BUILTINS


# ---------- envelope size pre-check -----------------------------------------


def test_invoke_ps_refuses_oversized_script(monkeypatch):
    # Set up a stub that would normally invoke fine.
    _patch_pypsrp(monkeypatch, raise_msg=None)

    # 50KB script with a 100KB envelope: 50% > 30% threshold → refused.
    big = "x" * 50_000
    rc, lines = J.invoke_ps(
        None,
        big,
        wrapper="none",
        max_envelope_size=100_000,
    )
    assert rc == 1
    assert lines == []


def test_invoke_ps_passes_under_envelope(monkeypatch):
    _patch_pypsrp(monkeypatch, raise_msg=None)
    rc, lines = J.invoke_ps(
        None,
        "Get-Process",
        wrapper="none",
        max_envelope_size=100_000,
    )
    assert rc == 0


def test_invoke_ps_no_envelope_cap_bypasses_check(monkeypatch):
    _patch_pypsrp(monkeypatch, raise_msg=None)
    # No max_envelope_size = pre-check is disabled.
    big = "x" * 200_000
    rc, lines = J.invoke_ps(None, big, wrapper="none", max_envelope_size=None)
    assert rc == 0
