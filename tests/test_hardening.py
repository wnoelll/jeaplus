"""Regression tests for the JEA+ hardening release.

The tests use protocol-shaped stubs so the safety properties can be proven
without a Windows/JEA integration host.  Live endpoint validation remains a
separate release gate.
"""

from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path
from typing import ClassVar

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import jea_plus as J


def _connection_args(**overrides):
    values = vars(
        J.build_parser().parse_args(
            ["server.example", "--ccache", "/tmp/test.ccache", "info"]
        )
    )
    values.update(overrides)
    return argparse.Namespace(**values)


class _Pool:
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _Streams:
    def __init__(self):
        self.error = []
        self.warning = []
        self.verbose = []
        self.debug = []
        self.information = []
        self.progress = []


class _RecordingPowerShell:
    """Small pypsrp PowerShell double that records structured API calls."""

    instances: ClassVar[list[_RecordingPowerShell]] = []
    output: ClassVar[list[object]] = ["ok"]
    failure: ClassVar[type[Exception] | None] = None

    def __init__(self, pool):
        self.pool = pool
        self.calls = []
        self.streams = _Streams()
        self.had_errors = False
        type(self).instances.append(self)

    def add_cmdlet(self, name):
        self.calls.append(("cmdlet", name))
        return self

    def add_parameter(self, name, value=None):
        self.calls.append(("parameter", name, value))
        return self

    def add_argument(self, value):
        self.calls.append(("argument", value))
        return self

    def add_statement(self):
        self.calls.append(("statement",))
        return self

    def add_script(self, script):
        self.calls.append(("script", script))
        return self

    def invoke(self):
        if type(self).failure:
            raise type(self).failure
        return list(type(self).output)


@pytest.fixture
def recording_ps(monkeypatch):
    _RecordingPowerShell.instances = []
    _RecordingPowerShell.output = ["ok"]
    _RecordingPowerShell.failure = None
    monkeypatch.setattr(
        J,
        "load_pypsrp",
        lambda: (None, None, _RecordingPowerShell),
    )
    return _RecordingPowerShell


# ---------- structured / NoLanguage execution ------------------------------


def test_invoke_structured_uses_cmdlet_parameter_argument_and_statement_apis(
    recording_ps,
):
    specs = [
        J.CommandSpec(
            "Get-Service",
            parameters=(("Name", "Spooler"),),
            end_of_statement=True,
        ),
        J.CommandSpec(
            "Select-Object",
            parameters=(("Property", ["Name", "Status"]),),
            arguments=("ignored-positional",),
        ),
    ]

    rc, output = J.invoke_structured(_Pool(), specs, display=False)

    assert rc == 0
    assert output == ["ok"]
    assert recording_ps.instances[-1].calls == [
        ("cmdlet", "Get-Service"),
        ("parameter", "Name", "Spooler"),
        ("statement",),
        ("cmdlet", "Select-Object"),
        ("parameter", "Property", ["Name", "Status"]),
        ("argument", "ignored-positional"),
    ]
    assert not any(call[0] == "script" for call in recording_ps.instances[-1].calls)


def test_parse_pipeline_document_accepts_typed_parameters_and_statements():
    document = [
        {
            "cmdlet": "Get-Process",
            "parameters": {"Name": ["pwsh", "powershell"]},
            "arguments": [3],
            "end_of_statement": True,
        },
        {"cmdlet": "Get-Service", "parameters": {"ErrorAction": "Stop"}},
    ]

    specs = J.parse_pipeline_document(document)

    assert specs[0].name == "Get-Process"
    assert specs[0].parameters == (("Name", ["pwsh", "powershell"]),)
    assert specs[0].arguments == (3,)
    assert specs[0].end_of_statement is True
    assert specs[1].name == "Get-Service"


@pytest.mark.parametrize(
    "document",
    [
        {},
        [],
        [{}],
        [{"cmdlet": ""}],
        [{"cmdlet": "Get-Process", "parameters": []}],
        [{"cmdlet": "Get-Process", "arguments": "not-a-list"}],
        [{"cmdlet": "Get-Process", "surprise": True}],
    ],
)
def test_parse_pipeline_document_rejects_ambiguous_or_invalid_shapes(document):
    with pytest.raises(ValueError):
        J.parse_pipeline_document(document)


def test_cmdlet_parser_supports_string_json_switch_and_positional_values():
    parser = J.build_parser()
    args = parser.parse_args(
        [
            "dc",
            "cmdlet",
            "Set-Thing",
            "--parameter",
            "Name=hello",
            "--parameter-json",
            'Options={"enabled":true}',
            "--switch",
            "Force",
            "--argument",
            "tail",
            "--argument-json",
            "42",
        ]
    )

    specs = J.command_specs_from_args(args)

    assert specs == [
        J.CommandSpec(
            "Set-Thing",
            parameters=(
                ("Name", "hello"),
                ("Options", {"enabled": True}),
                ("Force", None),
            ),
            arguments=("tail", 42),
        )
    ]


def test_pipeline_parser_accepts_stdin_marker():
    args = J.build_parser().parse_args(["dc", "pipeline", "-"])
    assert args.pipeline_path == "-"
    assert args.func is J.run_pipeline


# ---------- source command input contract ----------------------------------


def test_command_remainder_preserves_single_complete_expression():
    expression = "Get-Process | Select-Object -First 1"
    assert J.command_from_remainder([expression]) == expression


def test_command_remainder_rejects_lost_shell_quoting():
    with pytest.raises(SystemExit, match="ambiguous"):
        J.command_from_remainder(["Write-Output", "hello world"])


def test_read_command_source_supports_file_and_stdin(tmp_path, monkeypatch):
    command_file = tmp_path / "command.ps1"
    command_file.write_text("Write-Output 'from file'", encoding="utf-8")
    file_args = argparse.Namespace(
        command_file=str(command_file),
        command_stdin=False,
        command=[],
        encoding="utf-8",
    )
    assert J.read_command_source(file_args) == "Write-Output 'from file'"

    monkeypatch.setattr(
        sys, "stdin", type("Input", (), {"read": lambda self: "stdin"})()
    )
    stdin_args = argparse.Namespace(
        command_file=None,
        command_stdin=True,
        command=[],
        encoding="utf-8",
    )
    assert J.read_command_source(stdin_args) == "stdin"


# ---------- pypsrp capability filtering / version ---------------------------


def test_supported_kwargs_does_not_treat_var_kwargs_as_unbounded_support():
    def accepts_any(**_kwargs):
        return None

    filtered, ignored = J.supported_kwargs(
        accepts_any,
        {"known": 1, "obsolete": 2},
        var_keyword_names={"known"},
    )
    assert filtered == {"known": 1}
    assert ignored == ["obsolete"]


def test_build_wsman_never_passes_dead_kerberos_delegation_alias(monkeypatch):
    captured = {}

    class WSMan:
        def __init__(self, server, **kwargs):
            captured["server"] = server
            captured.update(kwargs)

    monkeypatch.setattr(J, "load_pypsrp", lambda: (WSMan, None, None))
    args = _connection_args(delegate=True, auth="kerberos")

    J.build_wsman(args)

    assert captured["negotiate_delegate"] is True
    assert "kerberos_delegation" not in captured


def test_version_output_includes_program_and_pypsrp_versions(monkeypatch):
    monkeypatch.setattr(J, "dependency_version", lambda _name: "0.9.1")
    assert J.version_string() == f"jeaplus {J.__version__} (pypsrp 0.9.1)"


def test_top_level_version_does_not_require_a_host(monkeypatch, capsys):
    monkeypatch.setattr(J, "dependency_version", lambda _name: "0.9.1")
    with pytest.raises(SystemExit) as exc:
        J.build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "jeaplus" in output
    assert "pypsrp" in output


# ---------- secure logging --------------------------------------------------


def test_logger_creates_owner_only_file(tmp_path):
    log_path = tmp_path / "nested" / "session.log"
    J.Logger(str(log_path)).write("secret-ish transcript")

    mode = stat.S_IMODE(log_path.stat().st_mode)
    assert mode == 0o600
    assert log_path.read_text(encoding="utf-8") == "secret-ish transcript\n"


def test_logger_refuses_symlink_targets(tmp_path):
    real = tmp_path / "real.log"
    real.write_text("do not modify\n", encoding="utf-8")
    link = tmp_path / "link.log"
    link.symlink_to(real)

    with pytest.raises(OSError):
        J.Logger(str(link)).write("redirected")
    assert real.read_text(encoding="utf-8") == "do not modify\n"


# ---------- history methods -------------------------------------------------


def test_history_cmdlet_method_uses_only_get_content():
    script = J.make_history_script("C:\\Temp\\h.txt", "cmdlet")
    assert "Get-Content -LiteralPath" in script
    assert "ReadAllLines" not in script


def test_history_dotnet_method_is_real_and_explicitly_uses_read_all_lines():
    script = J.make_history_script("C:\\Temp\\h.txt", "dotnet")
    assert "[System.IO.File]::ReadAllLines" in script
    assert "Get-Content -LiteralPath" not in script


def test_history_auto_tries_cmdlet_then_full_language_fallback():
    script = J.make_history_script("C:\\Temp\\h.txt", "auto")
    assert "Get-Content -LiteralPath" in script
    assert "[System.IO.File]::ReadAllLines" in script
    assert "catch" in script


# ---------- literal, staged, verified transfers -----------------------------


def test_transfer_scripts_use_literal_path_consistently():
    remote = "C:\\Temp\\artifact[1]*.bin"
    assert "Set-Content -LiteralPath" in J._upload_chunk_script(
        remote, b"abc", first=True
    )
    assert "Add-Content -LiteralPath" in J._upload_chunk_script(
        remote, b"def", first=False
    )
    assert "Get-Content -LiteralPath" in J._download_script(remote, 1024)


def test_remote_staging_path_is_adjacent_and_unpredictable(monkeypatch):
    monkeypatch.setattr(J.secrets, "token_hex", lambda _n: "0123456789abcdef")
    final = "C:\\Temp\\artifact[1].bin"
    staged = J.make_remote_staging_path(final)
    assert staged == final + ".jeaplus-tmp-0123456789abcdef"


def test_upload_commit_renames_staging_file_to_final_destination():
    script = J._upload_commit_script("C:\\Temp\\x.tmp", "C:\\Temp\\x.bin")
    assert "Move-Item" in script
    assert "-LiteralPath 'C:\\Temp\\x.tmp'" in script
    assert "-Destination 'C:\\Temp\\x.bin'" in script
    assert "-Force" in script


def test_remote_size_parser_requires_machine_readable_marker():
    assert J.parse_remote_size(["JEAPLUS-SIZE:42"]) == 42
    with pytest.raises(ValueError):
        J.parse_remote_size(["Uploaded: foo (42 bytes)"])


def test_upload_streams_local_file_and_commits_only_after_size_match(
    tmp_path, monkeypatch
):
    local = tmp_path / "large.bin"
    local.write_bytes(b"0123456789")
    final = "C:\\Temp\\result[1].bin"
    args = _connection_args(
        local_path=str(local),
        remote_path=final,
        chunk_size=4,
        progress=False,
        verify="size",
        backend="script",
    )
    calls = []

    def fake_invoke(_args, _pool, operation, **_kwargs):
        calls.append(operation)
        if "JEAPLUS-SIZE:" in str(operation):
            return 0, ["JEAPLUS-SIZE:10"]
        return 0, []

    monkeypatch.setattr(J, "invoke_remote", fake_invoke)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _self: (_ for _ in ()).throw(AssertionError("must stream")),
    )
    monkeypatch.setattr(J.secrets, "token_hex", lambda _n: "feedfacefeedface")

    rc = J._do_upload(_Pool(), args, J.Logger(None))

    assert rc == 0
    rendered = "\n".join(map(str, calls))
    assert rendered.count("Set-Content -LiteralPath") == 1
    assert rendered.count("Add-Content -LiteralPath") == 2
    assert "Move-Item" in rendered
    assert final + ".jeaplus-tmp-feedfacefeedface" in rendered


def test_upload_size_mismatch_never_replaces_destination(tmp_path, monkeypatch):
    local = tmp_path / "x.bin"
    local.write_bytes(b"abcdef")
    args = _connection_args(
        local_path=str(local),
        remote_path="C:\\Temp\\x.bin",
        chunk_size=1024,
        progress=False,
        verify="size",
        backend="script",
    )
    calls = []

    def fake_invoke(_args, _pool, operation, **_kwargs):
        calls.append(str(operation))
        if "JEAPLUS-SIZE:" in str(operation):
            return 0, ["JEAPLUS-SIZE:5"]
        return 0, []

    monkeypatch.setattr(J, "invoke_remote", fake_invoke)

    assert J._do_upload(_Pool(), args, J.Logger(None)) == 1
    assert not any("Move-Item" in operation for operation in calls)
    assert any("Remove-Item" in operation for operation in calls)


def test_download_writes_through_local_staging_and_preserves_mode(
    tmp_path, monkeypatch
):
    destination = tmp_path / "artifact.bin"
    destination.write_bytes(b"old")
    args = _connection_args(
        remote_path="C:\\Temp\\artifact[1].bin",
        local_path=str(destination),
        chunk_bytes=4,
        verify="size",
        backend="script",
    )
    operations = []

    def fake_invoke(_args, _pool, operation, **_kwargs):
        operations.append(str(operation))
        if "JEAPLUS-SIZE:" in str(operation):
            return 0, ["JEAPLUS-SIZE:4"]
        return 0, ["00010203"]

    monkeypatch.setattr(J, "invoke_remote", fake_invoke)
    monkeypatch.setattr(
        Path,
        "write_bytes",
        lambda _self, _data: (_ for _ in ()).throw(AssertionError("must stream")),
    )

    assert J._do_download(_Pool(), args, J.Logger(None)) == 0
    assert destination.read_bytes() == b"\x00\x01\x02\x03"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert all(
        "Get-Content -LiteralPath" in op or "JEAPLUS-SIZE:" in op for op in operations
    )


# ---------- safe shell recovery ---------------------------------------------


def _shell_args(**overrides):
    values = vars(J.build_parser().parse_args(["dc", "--backend", "script", "shell"]))
    values.update(overrides)
    return argparse.Namespace(**values)


def _prepare_shell(monkeypatch, inputs, dispatcher):
    iterator = iter(inputs)
    monkeypatch.setattr(J, "open_pool", lambda _args: _Pool())
    monkeypatch.setattr(J, "load_cmdlet_cache", lambda *_args: [])
    monkeypatch.setattr(J, "install_shell_completer", lambda _cmdlets: None)
    monkeypatch.setattr(J, "dispatch_shell_line", dispatcher)
    monkeypatch.setattr("builtins.input", lambda _prompt: next(iterator))
    monkeypatch.setattr(J.time, "sleep", lambda _seconds: None)


def test_shell_reconnects_but_does_not_replay_uncertain_command_by_default(
    monkeypatch, capsys
):
    calls = []

    def dispatch(_args, _pool, line, _logger):
        calls.append(line)
        raise J.SessionExpired("response lost")

    _prepare_shell(monkeypatch, ["Restart-Service Spooler", ":quit"], dispatch)

    assert J.run_shell(_shell_args(retry_unsafe=False)) == 0
    assert calls == ["Restart-Service Spooler"]
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "may have executed remotely" in combined
    assert ":retry" in combined


def test_shell_retry_builtin_explicitly_replays_last_uncertain_command(monkeypatch):
    calls = []

    def dispatch(_args, _pool, line, _logger):
        calls.append(line)
        if len(calls) == 1:
            raise J.SessionExpired("response lost")
        return 0

    _prepare_shell(
        monkeypatch,
        ["Restart-Service Spooler", ":retry", ":quit"],
        dispatch,
    )

    assert J.run_shell(_shell_args(retry_unsafe=False)) == 0
    assert calls == ["Restart-Service Spooler", "Restart-Service Spooler"]


def test_shell_unsafe_retry_flag_preserves_opt_in_at_least_once_semantics(
    monkeypatch,
):
    calls = []

    def dispatch(_args, _pool, line, _logger):
        calls.append(line)
        if len(calls) == 1:
            raise J.SessionExpired("response lost")
        return 0

    _prepare_shell(monkeypatch, ["Restart-Service Spooler", ":quit"], dispatch)

    assert J.run_shell(_shell_args(retry_unsafe=True)) == 0
    assert calls == ["Restart-Service Spooler", "Restart-Service Spooler"]


def test_shell_help_explains_retry_semantics():
    assert ":retry" in J.SHELL_BUILTINS
    assert "may have executed" in J.shell_help()
    shell_args = J.build_parser().parse_args(["dc", "shell", "--retry-unsafe"])
    assert shell_args.retry_unsafe is True


# ---------- JSON pipeline loading -------------------------------------------


def test_load_pipeline_document_from_file_and_stdin(tmp_path, monkeypatch):
    payload = [{"cmdlet": "Get-Service", "parameters": {"Name": "Spooler"}}]
    path = tmp_path / "pipeline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert J.load_pipeline_document(str(path), "utf-8") == payload

    monkeypatch.setattr(
        sys,
        "stdin",
        type("Input", (), {"read": lambda self: json.dumps(payload)})(),
    )
    assert J.load_pipeline_document("-", "utf-8") == payload


def test_transfer_cli_exposes_verification_policy():
    upload = J.build_parser().parse_args(
        ["dc", "upload", "--verify", "sha256", "local", "C:\\x"]
    )
    download = J.build_parser().parse_args(
        ["dc", "download", "--verify", "none", "C:\\x", "local"]
    )
    assert upload.verify == "sha256"
    assert download.verify == "none"


def test_backend_cli_defaults_to_auto_and_accepts_structured():
    assert J.build_parser().parse_args(["dc", "info"]).backend == "auto"
    assert (
        J.build_parser().parse_args(["dc", "--backend", "structured", "info"]).backend
        == "structured"
    )
