"""Runtime-path coverage for CLI orchestration and protocol-shaped branches."""

from __future__ import annotations

import argparse
import builtins
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import jea_plus as J


class Pool:
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class Streams:
    def __init__(self):
        self.error = []
        self.warning = []
        self.verbose = []
        self.debug = []
        self.information = []
        self.progress = []


class Pipeline:
    output: ClassVar[list[object]] = ["out"]
    error: ClassVar[Exception | None] = None
    had_errors: ClassVar[bool] = False

    def __init__(self, pool):
        self.pool = pool
        self.streams = Streams()
        self.streams.warning = ["careful"]
        self.commands = []

    def add_script(self, script):
        self.commands.append(("script", script))
        return self

    def add_cmdlet(self, name):
        self.commands.append(("cmdlet", name))
        return self

    def add_parameter(self, name, value=None):
        self.commands.append(("parameter", name, value))
        return self

    def add_argument(self, value):
        self.commands.append(("argument", value))
        return self

    def add_statement(self):
        self.commands.append(("statement",))
        return self

    def invoke(self):
        if type(self).error:
            raise type(self).error
        self.had_errors = type(self).had_errors
        return list(type(self).output)


def parse(*argv: str) -> argparse.Namespace:
    return J.build_parser().parse_args(list(argv))


def shell_args(*extra: str, backend: str = "script") -> argparse.Namespace:
    return parse("dc", "--backend", backend, "shell", *extra)


@pytest.fixture(autouse=True)
def reset_pipeline():
    Pipeline.output = ["out"]
    Pipeline.error = None
    Pipeline.had_errors = False


def test_emit_logger_and_dependency_helpers(tmp_path, monkeypatch, capsys):
    log = J.Logger(str(tmp_path / "events.log"))
    J.emit("stdout", logger=log)
    J.emit("stderr", stderr=True, logger=log)
    captured = capsys.readouterr()
    assert captured.out == "stdout\n"
    assert captured.err == "stderr\n"
    assert (tmp_path / "events.log").read_text() == "OUT stdout\nERR stderr\n"

    monkeypatch.setattr(J.importlib.metadata, "version", lambda _name: "1.2.3")
    assert J.dependency_version("thing") == "1.2.3"
    monkeypatch.setattr(
        J.importlib.metadata,
        "version",
        lambda _name: (_ for _ in ()).throw(J.importlib.metadata.PackageNotFoundError),
    )
    assert J.dependency_version("thing") == "not installed"


def test_load_pypsrp_success_and_import_failure(monkeypatch):
    wsman, pool, powershell = J.load_pypsrp()
    assert wsman.__name__ == "WSMan"
    assert pool.__name__ == "RunspacePool"
    assert powershell.__name__ == "PowerShell"

    real_import = builtins.__import__

    def fail_pypsrp(name, *args, **kwargs):
        if name.startswith("pypsrp"):
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_pypsrp)
    with pytest.raises(SystemExit, match="Missing dependency"):
        J.load_pypsrp()


def test_supported_kwargs_signature_failure_and_no_var_kwargs(monkeypatch):
    monkeypatch.setattr(
        J.inspect,
        "signature",
        lambda _callable: (_ for _ in ()).throw(ValueError("opaque")),
    )
    filtered, ignored = J.supported_kwargs(
        object(), {"dynamic": 1, "other": 2, "empty": None}, var_keyword_names={"dynamic"}
    )
    assert filtered == {"dynamic": 1}
    assert ignored == ["other"]

    monkeypatch.undo()

    def fixed(one=None):
        return one

    filtered, ignored = J.supported_kwargs(fixed, {"one": 1, "two": 2})
    assert filtered == {"one": 1}
    assert ignored == ["two"]


def test_password_prompt_and_kerberos_environment(monkeypatch):
    args = SimpleNamespace(hash=None, password_env=None, ask_pass=True, password=None)
    monkeypatch.setattr(J.getpass, "getpass", lambda _prompt: "prompted")
    assert J.get_password(args) == "prompted"

    kerberos = SimpleNamespace(ccache="FILE:/tmp/c", keytab="/tmp/k", krb5_config="/tmp/conf")
    J.apply_kerberos_env(kerberos)
    assert J.os.environ["KRB5CCNAME"] == "FILE:/tmp/c"
    assert J.os.environ["KRB5_CLIENT_KTNAME"] == "/tmp/k"
    assert J.os.environ["KRB5_CONFIG"] == "/tmp/conf"


def test_build_wsman_auth_specific_options_and_verbose_drop(monkeypatch, capsys):
    captured = []

    class WSMan:
        def __init__(self, server, **kwargs):
            captured.append((server, kwargs))

    monkeypatch.setattr(J, "load_pypsrp", lambda: (WSMan, None, None))
    kerberos = parse(
        "dc",
        "-u",
        "user@example",
        "--delegate",
        "--hostname-override",
        "spn.example",
        "--negotiate-service",
        "HOST",
        "-v",
        "info",
    )
    J.build_wsman(kerberos)
    assert captured[-1][0] == "dc"
    assert captured[-1][1]["negotiate_delegate"] is True
    assert "dropping --username" in capsys.readouterr().err

    certificate = parse(
        "dc",
        "--auth",
        "certificate",
        "--certificate-pem",
        "cert.pem",
        "--certificate-key-pem",
        "key.pem",
        "info",
    )
    J.build_wsman(certificate)
    assert captured[-1][1]["certificate_pem"] == "cert.pem"
    assert "negotiate_delegate" not in captured[-1][1]


def test_stream_items_handles_missing_none_and_non_iterable_streams():
    assert J.stream_items(SimpleNamespace(streams=None)) == []
    streams = Streams()
    streams.error = [None, "boom"]
    streams.warning = 3
    streams.information = ["info"]
    assert J.stream_items(SimpleNamespace(streams=streams)) == [
        ("error", "boom"),
        ("information", "info"),
    ]


def test_pipeline_invocation_display_streams_errors_and_logging(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(J, "load_pypsrp", lambda: (None, None, Pipeline))
    log = J.Logger(str(tmp_path / "pipeline.log"))
    Pipeline.output = [None, "value"]
    rc, values = J.invoke_structured(
        Pool(),
        [J.CommandSpec("Get-X", (("Name", "a"),), (2,), True)],
        logger=log,
    )
    assert rc == 0
    assert values == ["value"]
    captured = capsys.readouterr()
    assert "value" in captured.out
    assert "[warning] careful" in captured.out
    assert "CMDLET Get-X -Name 'a' 2 ;" in (tmp_path / "pipeline.log").read_text()

    Pipeline.had_errors = True
    rc, _ = J.invoke_structured(Pool(), [J.CommandSpec("Bad")], display=False)
    assert rc == 1

    Pipeline.error = RuntimeError("syntax")
    rc, output = J.invoke_structured(Pool(), [J.CommandSpec("Bad")], display=False)
    assert (rc, output) == (1, [])
    Pipeline.error = RuntimeError("Code: 401 Unauthorized")
    with pytest.raises(J.SessionExpired):
        J.invoke_structured(Pool(), [J.CommandSpec("Bad")], display=False, raise_session=True)


def test_invoke_structured_rejects_empty_and_ps_property_shapes(monkeypatch):
    with pytest.raises(ValueError, match="at least one"):
        J.invoke_structured(Pool(), [])

    assert J.ps_property({"nAmE": 1}, "Name") == 1
    adapted = SimpleNamespace(adapted_properties={"NAME": 2})
    assert J.ps_property(adapted, "name") == 2
    extended = SimpleNamespace(extended_properties={"Name": 3})
    assert J.ps_property(extended, "name") == 3
    direct = SimpleNamespace(Name=4)
    assert J.ps_property(direct, "Name") == 4
    assert J.ps_property(object(), "missing", "fallback") == "fallback"


def test_backend_resolution_explicit_cache_script_and_structured(monkeypatch, capsys):
    explicit = SimpleNamespace(backend="script")
    assert J.resolve_backend(explicit, Pool()) == "script"

    calls = []

    def probe(_pool, _script, **_kwargs):
        calls.append(1)
        return 0, ["ConstrainedLanguage"]

    monkeypatch.setattr(J, "invoke_ps", probe)
    auto = SimpleNamespace(backend="auto", max_envelope_size=1000, verbose=True)
    assert J.resolve_backend(auto, Pool()) == "script"
    assert J.resolve_backend(auto, Pool()) == "script"
    assert len(calls) == 1
    assert "[backend] script" in capsys.readouterr().err

    monkeypatch.setattr(J, "invoke_ps", lambda *_args, **_kwargs: (1, []))
    rejected = SimpleNamespace(backend="auto", max_envelope_size=1000, verbose=False)
    assert J.resolve_backend(rejected, Pool()) == "structured"
    assert rejected._remote_language_mode == "source probe rejected"

    monkeypatch.setattr(J, "invoke_ps", lambda *_args, **_kwargs: (0, ["NoLanguage"]))
    no_language = SimpleNamespace(backend="auto", max_envelope_size=1000, verbose=False)
    assert J.resolve_backend(no_language, Pool()) == "structured"

    monkeypatch.setattr(J, "invoke_ps", lambda *_args, **_kwargs: (0, ["RestrictedLanguage"]))
    restricted = SimpleNamespace(backend="auto", max_envelope_size=1000, verbose=False)
    assert J.resolve_backend(restricted, Pool()) == "structured"


def test_invoke_remote_open_pool_and_json_wrapper(monkeypatch):
    captured = {}

    def invoke(_pool, script, **kwargs):
        captured.update(script=script, **kwargs)
        return 0, []

    monkeypatch.setattr(J, "invoke_ps", invoke)
    args = SimpleNamespace(wrap="ampersand", max_envelope_size=999)
    assert J.invoke_remote(args, Pool(), "Get-X") == (0, [])
    assert captured["wrapper"] == "ampersand"
    assert captured["max_envelope_size"] == 999

    class RunspacePool:
        def __init__(self, wsman, configuration_name):
            self.wsman = wsman
            self.configuration_name = configuration_name

    monkeypatch.setattr(J, "load_pypsrp", lambda: (None, RunspacePool, None))
    monkeypatch.setattr(J, "build_wsman", lambda _args: "connection")
    opened = J.open_pool(SimpleNamespace(configuration_name="JEA"))
    assert (opened.wsman, opened.configuration_name) == ("connection", "JEA")
    assert "ConvertTo-Json -Depth 7" in J.wrap_json("Get-X", 7)


def test_command_source_and_pipeline_validation_errors(tmp_path, monkeypatch):
    missing = SimpleNamespace(
        command_file=str(tmp_path / "missing"),
        command_stdin=False,
        command=[],
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="not found"):
        J.read_command_source(missing)
    with pytest.raises(SystemExit, match="exactly one"):
        J.read_command_source(
            SimpleNamespace(command_file=None, command_stdin=False, command=[], encoding="utf-8")
        )
    with pytest.raises(SystemExit, match="exactly one"):
        J.read_command_source(
            SimpleNamespace(command_file="x", command_stdin=True, command=[], encoding="utf-8")
        )

    with pytest.raises(ValueError, match="control"):
        J.parse_pipeline_document([{"cmdlet": "Get-X\nBad"}])
    with pytest.raises(ValueError, match="boolean"):
        J.parse_pipeline_document([{"cmdlet": "Get-X", "end_of_statement": "yes"}])
    with pytest.raises(ValueError, match="must be an object"):
        J.parse_pipeline_document([1])

    args = SimpleNamespace(
        name="Get-X",
        parameters=["broken"],
        parameters_json=[],
        switches=[],
        arguments=[],
        arguments_json=[],
    )
    with pytest.raises(SystemExit, match="NAME=VALUE"):
        J.command_specs_from_args(args)
    args.parameters = []
    args.parameters_json = ["Name={bad"]
    with pytest.raises(SystemExit, match="Invalid JSON"):
        J.command_specs_from_args(args)
    args.parameters_json = []
    args.arguments_json = ["bad"]
    with pytest.raises(SystemExit, match="argument-json"):
        J.command_specs_from_args(args)

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{", encoding="utf-8")
    with pytest.raises(SystemExit, match="Invalid pipeline JSON"):
        J.load_pipeline_document(str(bad_json), "utf-8")
    with pytest.raises(SystemExit, match="not found"):
        J.load_pipeline_document(str(tmp_path / "none.json"), "utf-8")


def test_command_and_pipeline_runners(monkeypatch, tmp_path):
    monkeypatch.setattr(J, "open_pool", lambda _args: Pool())
    structured = []
    monkeypatch.setattr(
        J,
        "invoke_structured",
        lambda _pool, specs, **_kwargs: (structured.extend(specs) or 0, ["ok"]),
    )
    cmdlet = parse("dc", "cmdlet", "Get-X", "--parameter", "Name=a")
    assert J.run_cmdlet(cmdlet) == 0
    assert structured[-1].name == "Get-X"

    pipeline_path = tmp_path / "pipeline.json"
    pipeline_path.write_text('[{"cmdlet":"Get-Y"}]', encoding="utf-8")
    pipeline = parse("dc", "pipeline", str(pipeline_path))
    assert J.run_pipeline(pipeline) == 0
    assert structured[-1].name == "Get-Y"
    monkeypatch.setattr(
        J, "parse_pipeline_document", lambda _doc: (_ for _ in ()).throw(ValueError("bad"))
    )
    with pytest.raises(SystemExit, match="Invalid pipeline"):
        J.run_pipeline(pipeline)


def test_source_runners_script_and_structured_paths(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(J, "open_pool", lambda _args: Pool())
    remote = []
    monkeypatch.setattr(
        J,
        "invoke_remote",
        lambda _args, _pool, script, **_kwargs: (remote.append(script) or 0, []),
    )

    command = parse("dc", "--backend", "script", "run", "Get-X")
    assert J.run_command(command) == 0
    assert remote[-1] == "Get-X"
    json_command = parse("dc", "--backend", "script", "run", "--json", "Get-Y")
    assert J.run_command(json_command) == 0
    assert "ConvertTo-Json" in remote[-1]
    empty = parse("dc", "--backend", "script", "run", "")
    with pytest.raises(SystemExit, match="needs a PowerShell command"):
        J.run_command(empty)

    structured = parse("dc", "--backend", "structured", "run", "Get-X")
    with pytest.raises(SystemExit, match="NoLanguage"):
        J.run_command(structured)

    script_path = tmp_path / "x.ps1"
    script_path.write_text("Get-Z", encoding="utf-8")
    script = parse("dc", "--backend", "script", "script", str(script_path))
    assert J.run_script(script) == 0
    script.backend = "structured"
    assert J.run_script(script) == 1
    assert "NoLanguage" in capsys.readouterr().err
    script.script_path = str(tmp_path / "missing.ps1")
    with pytest.raises(SystemExit, match="Script not found"):
        J.run_script(script)

    batch_path = tmp_path / "batch.txt"
    batch_path.write_text("# comment\nGet-A\n\nGet-B\n", encoding="utf-8")
    batch = parse("dc", "--backend", "script", "batch", str(batch_path))
    assert J.run_batch(batch) == 0
    assert remote[-2:] == ["Get-A", "Get-B"]
    batch.backend = "structured"
    assert J.run_batch(batch) == 1
    batch.batch_path = str(tmp_path / "missing")
    with pytest.raises(SystemExit, match="Batch file not found"):
        J.run_batch(batch)


def test_batch_stops_on_error(monkeypatch, tmp_path):
    path = tmp_path / "batch.txt"
    path.write_text("one\ntwo\n", encoding="utf-8")
    args = parse("dc", "--backend", "script", "batch", "--stop-on-error", str(path))
    monkeypatch.setattr(J, "open_pool", lambda _args: Pool())
    calls = []

    def invoke(_args, _pool, script, **_kwargs):
        calls.append(script)
        return 1, []

    monkeypatch.setattr(J, "invoke_remote", invoke)
    assert J.run_batch(args) == 1
    assert calls == ["one"]


def test_info_commands_and_history_runners(monkeypatch, capsys):
    monkeypatch.setattr(J, "open_pool", lambda _args: Pool())
    monkeypatch.setattr(J, "invoke_remote", lambda *_args, **_kwargs: (0, ["ok"]))
    monkeypatch.setattr(
        J,
        "invoke_structured",
        lambda *_args, **_kwargs: (
            0,
            [
                {"Name": "Get-B", "CommandType": "Function", "ModuleName": "M"},
                {"Name": "Get-A", "CommandType": "Cmdlet", "ModuleName": ""},
            ],
        ),
    )

    info = parse("dc", "--backend", "script", "info")
    assert J.run_info(info) == 0
    info.backend = "structured"
    assert J.run_info(info) == 0
    assert "ExecutionBackend" in capsys.readouterr().out

    commands = parse("dc", "--backend", "script", "commands", "Get-*")
    assert J.run_commands(commands) == 0
    commands.backend = "structured"
    assert J.run_commands(commands) == 0
    table = capsys.readouterr().out
    assert "CommandType" in table and "Get-A" in table

    monkeypatch.setattr(J, "invoke_structured", lambda *_args, **_kwargs: (0, []))
    assert J.run_commands(commands) == 0
    assert "no commands match" in capsys.readouterr().out

    history = parse(
        "dc",
        "--backend",
        "script",
        "history",
        "--method",
        "cmdlet",
        "--remote-path",
        "C:\\h.txt",
    )
    assert J.run_history(history) == 0
    history.backend = "structured"
    assert J.run_history(history) == 0
    history.remote_path = None
    assert J.run_history(history) == 1
    history.remote_path = "C:\\h.txt"
    history.method = "dotnet"
    assert J.run_history(history) == 1


def test_history_unknown_method_and_command_row_fallback():
    with pytest.raises(ValueError, match="Unknown history"):
        J.make_history_script(None, "bad")
    assert J._format_command_rows([]) == []
    rows = J._format_command_rows(["Get-X"])
    assert any("Get-X" in row for row in rows)


def test_transfer_parsers_specs_and_structured_bytes():
    assert "JEAPLUS-SIZE" in J._upload_verify_script("C:\\x")
    assert "Get-FileHash -LiteralPath" in J._remote_hash_script("C:\\x")
    assert "Remove-Item -LiteralPath" in J._remote_cleanup_script("C:\\x")

    assert J.parse_remote_size([{"Length": "3"}]) == 3
    with pytest.raises(ValueError, match="invalid remote size"):
        J.parse_remote_size(["JEAPLUS-SIZE:bad"])
    with pytest.raises(ValueError, match="invalid remote Length"):
        J.parse_remote_size([{"Length": "bad"}])
    with pytest.raises(ValueError, match="not returned"):
        J.parse_remote_size([])

    digest = "a" * 64
    assert J.parse_remote_hash([f"JEAPLUS-SHA256:{digest}"]) == digest
    assert J.parse_remote_hash([{"Hash": digest.upper()}]) == digest
    with pytest.raises(ValueError, match="not returned"):
        J.parse_remote_hash(["bad"])

    assert J._upload_chunk_spec("x", b"\x01", True).name == "Set-Content"
    assert J._upload_chunk_spec("x", b"\x01", False).name == "Add-Content"
    assert J._remote_size_spec("x").name == "Get-Item"
    assert J._remote_hash_spec("x").name == "Get-FileHash"

    assert J._structured_download_bytes(b"a") == b"a"
    assert J._structured_download_bytes(bytearray(b"b")) == b"b"
    assert J._structured_download_bytes(3) == b"\x03"
    assert J._structured_download_bytes([0, 1]) == b"\x00\x01"
    with pytest.raises(ValueError, match="out of range"):
        J._structured_download_bytes(256)
    with pytest.raises(ValueError, match="unsupported"):
        J._structured_download_bytes("00")


def test_invoke_transfer_both_backends_and_cleanup(monkeypatch):
    script_calls = []
    structured_calls = []
    monkeypatch.setattr(
        J,
        "invoke_remote",
        lambda *_args, **_kwargs: (script_calls.append(1) or 0, ["s"]),
    )
    monkeypatch.setattr(
        J,
        "invoke_structured",
        lambda *_args, **_kwargs: (structured_calls.append(1) or 0, ["p"]),
    )
    script = SimpleNamespace(backend="script", wrap="none", max_envelope_size=1)
    assert J._invoke_transfer(
        script, Pool(), "source", [J.CommandSpec("Get-X")], logger=J.Logger(None)
    ) == (0, ["s"])
    structured = SimpleNamespace(backend="structured")
    assert J._invoke_transfer(
        structured, Pool(), "source", [J.CommandSpec("Get-X")], logger=J.Logger(None)
    ) == (0, ["p"])
    J._cleanup_remote(structured, Pool(), "C:\\tmp", J.Logger(None))
    assert len(structured_calls) == 2


def test_upload_hash_success_and_failure_paths(tmp_path, monkeypatch):
    local = tmp_path / "x.bin"
    local.write_bytes(b"abc")
    args = parse(
        "dc",
        "--backend",
        "script",
        "upload",
        "--verify",
        "sha256",
        str(local),
        "C:\\x.bin",
    )
    expected = J.hashlib.sha256(b"abc").hexdigest()
    operations = []

    def invoke(_args, _pool, script, **_kwargs):
        operations.append(script)
        if "JEAPLUS-SIZE" in script:
            return 0, ["JEAPLUS-SIZE:3"]
        if "JEAPLUS-SHA256" in script:
            return 0, [f"JEAPLUS-SHA256:{expected}"]
        return 0, []

    monkeypatch.setattr(J, "invoke_remote", invoke)
    assert J._do_upload(Pool(), args, J.Logger(None)) == 0

    def mismatch(_args, _pool, script, **_kwargs):
        if "JEAPLUS-SIZE" in script:
            return 0, ["JEAPLUS-SIZE:3"]
        if "JEAPLUS-SHA256" in script:
            return 0, ["JEAPLUS-SHA256:" + "0" * 64]
        return 0, []

    monkeypatch.setattr(J, "invoke_remote", mismatch)
    assert J._do_upload(Pool(), args, J.Logger(None)) == 1

    args.local_path = str(tmp_path / "none")
    assert J._do_upload(Pool(), args, J.Logger(None)) == 1


def test_upload_operation_verify_and_commit_failures(tmp_path, monkeypatch):
    local = tmp_path / "x.bin"
    local.write_bytes(b"abc")
    args = parse("dc", "--backend", "script", "upload", str(local), "C:\\x.bin")

    def chunk_fail(_args, _pool, script, **_kwargs):
        return (1, []) if "Set-Content" in script else (0, [])

    monkeypatch.setattr(J, "invoke_remote", chunk_fail)
    assert J._do_upload(Pool(), args, J.Logger(None)) == 1

    def malformed_size(_args, _pool, script, **_kwargs):
        return (0, ["bad"]) if "JEAPLUS-SIZE" in script else (0, [])

    monkeypatch.setattr(J, "invoke_remote", malformed_size)
    assert J._do_upload(Pool(), args, J.Logger(None)) == 1

    def commit_fail(_args, _pool, script, **_kwargs):
        if "JEAPLUS-SIZE" in script:
            return 0, ["JEAPLUS-SIZE:3"]
        return (1, []) if "Move-Item" in script else (0, [])

    monkeypatch.setattr(J, "invoke_remote", commit_fail)
    assert J._do_upload(Pool(), args, J.Logger(None)) == 1


def test_download_structured_hash_and_error_paths(tmp_path, monkeypatch):
    destination = tmp_path / "download.bin"
    args = parse(
        "dc",
        "--backend",
        "structured",
        "download",
        "--verify",
        "sha256",
        "C:\\x",
        str(destination),
    )
    digest = J.hashlib.sha256(b"abc").hexdigest()

    def good(_args, _pool, _script, specs, **_kwargs):
        name = specs[0].name
        if name == "Get-Content":
            return 0, [[97, 98, 99]]
        if name == "Get-Item":
            return 0, [{"Length": 3}]
        return 0, [{"Hash": digest}]

    monkeypatch.setattr(J, "_invoke_transfer", good)
    assert J._do_download(Pool(), args, J.Logger(None)) == 0
    assert destination.read_bytes() == b"abc"

    def bad_bytes(_args, _pool, _script, specs, **_kwargs):
        if specs[0].name == "Get-Content":
            return 0, ["not bytes"]
        return 0, []

    monkeypatch.setattr(J, "_invoke_transfer", bad_bytes)
    assert J._do_download(Pool(), args, J.Logger(None)) == 1

    monkeypatch.setattr(J, "_invoke_transfer", lambda *_args, **_kwargs: (1, []))
    assert J._do_download(Pool(), args, J.Logger(None)) == 1


def _proxy_command():
    return {
        "Name": "Set-X",
        "CommandType": "Function",
        "ModuleName": "Role",
        "Visibility": "Public",
        "Definition": "Set-X [-Name] <string>",
        "Parameters": {
            "Name": {
                "Name": "Name",
                "ParameterType": {"FullName": "System.String"},
                "Attributes": [
                    {
                        "types": ["System.Management.Automation.ValidateSetAttribute"],
                        "ValidValues": ["a", "b"],
                    },
                    {"types": ["X.ValidatePatternAttribute"], "RegexPattern": "^a"},
                    {"types": ["X.ValidateLengthAttribute"], "MinLength": 1, "MaxLength": 5},
                    {"types": ["X.ValidateRangeAttribute"], "MinRange": 1, "MaxRange": 9},
                    {"types": ["X.AliasAttribute"], "AliasNames": ["N"]},
                    {"types": ["X.OtherAttribute"]},
                ],
            }
        },
    }


def test_proxy_rendering_mapping_helpers_and_runners(monkeypatch, capsys):
    command = _proxy_command()
    lines = J._render_structured_proxy(command)
    rendered = "\n".join(lines)
    assert "ValidValues={a, b}" in rendered
    assert "Pattern=^a" in rendered
    assert "Length=1..5" in rendered
    assert "Range=1..9" in rendered
    assert "Aliases=N" in rendered
    assert J._mapping_values(SimpleNamespace(adapted_properties={"x": 1})) == [1]
    assert J._mapping_values([1, 2]) == [1, 2]
    assert J._mapping_values(1) == []
    assert J._attribute_name(object()) == "object"

    monkeypatch.setattr(J, "open_pool", lambda _args: Pool())
    monkeypatch.setattr(J, "invoke_remote", lambda *_args, **_kwargs: (0, []))
    monkeypatch.setattr(J, "invoke_structured", lambda *_args, **_kwargs: (0, [command]))
    args = parse("dc", "--backend", "structured", "proxy", "Set-X")
    assert J.run_proxy(args) == 0
    assert "Set-X" in capsys.readouterr().out
    args.backend = "script"
    assert J.run_proxy(args) == 0

    args = parse("dc", "--backend", "structured", "definition", "Set-X")
    assert J.run_definition(args) == 0
    assert "Definition" in capsys.readouterr().out
    args.backend = "script"
    assert J.run_definition(args) == 0

    monkeypatch.setattr(J, "invoke_structured", lambda *_args, **_kwargs: (0, []))
    args.backend = "structured"
    assert J.run_definition(args) == 1
    proxy = parse("dc", "--backend", "structured", "proxy", "none")
    assert J.run_proxy(proxy) == 1


def test_cmdlet_cache_both_backends(monkeypatch):
    monkeypatch.setattr(
        J,
        "invoke_structured",
        lambda *_args, **_kwargs: (0, [{"Name": "Get-X"}, "Get-Y"]),
    )
    args = SimpleNamespace(backend="structured")
    assert J.load_cmdlet_cache(args, Pool(), J.Logger(None)) == ["Get-X", "Get-Y"]
    monkeypatch.setattr(J, "invoke_structured", lambda *_args, **_kwargs: (1, []))
    assert J.load_cmdlet_cache(args, Pool(), J.Logger(None)) == []

    monkeypatch.setattr(J, "invoke_remote", lambda *_args, **_kwargs: (0, [" A ", ""]))
    args.backend = "script"
    assert J.load_cmdlet_cache(args, Pool(), J.Logger(None)) == ["A"]


def test_shell_completer_and_split(monkeypatch):
    calls = {}
    fake = SimpleNamespace(
        get_line_buffer=lambda: "ge",
        get_begidx=lambda: 0,
        set_completer=lambda value: calls.update(completer=value),
        set_completer_delims=lambda value: calls.update(delims=value),
        parse_and_bind=lambda value: calls.setdefault("bindings", []).append(value),
    )
    monkeypatch.setitem(sys.modules, "readline", fake)
    J.install_shell_completer(["Get-X"])
    assert calls["completer"]("ge", 0) == "Get-X"
    fake.get_line_buffer = lambda: "Get-X p"
    fake.get_begidx = lambda: 6
    assert calls["completer"]("p", 0) is None
    assert J.split_shell_args('"a b" c') == ["a b", "c"]


def _dispatch_setup(monkeypatch, backend="script", remote_output=None):
    monkeypatch.setattr(J, "resolve_backend", lambda *_args, **_kwargs: backend)
    calls = []

    def remote(_args, _pool, script, **_kwargs):
        calls.append(script)
        return 0, list(remote_output or [])

    monkeypatch.setattr(J, "invoke_remote", remote)
    monkeypatch.setattr(
        J, "invoke_structured", lambda *_args, **_kwargs: (0, list(remote_output or []))
    )
    return calls


@pytest.mark.parametrize("line", [":help", ":retry", ":info"])
def test_dispatch_basic_builtins(monkeypatch, line):
    _dispatch_setup(monkeypatch)
    rc = J.dispatch_shell_line(shell_args(), Pool(), line, J.Logger(None))
    assert rc == (1 if line == ":retry" else 0)


def test_dispatch_remote_unknown_and_structured_source(monkeypatch, capsys):
    calls = _dispatch_setup(monkeypatch)
    args = shell_args()
    assert J.dispatch_shell_line(args, Pool(), "Get-X", J.Logger(None)) == 0
    assert calls == ["Get-X"]
    assert J.dispatch_shell_line(args, Pool(), ":unknown", J.Logger(None)) == 1
    _dispatch_setup(monkeypatch, "structured")
    assert J.dispatch_shell_line(args, Pool(), "Get-X", J.Logger(None)) == 1
    assert "NoLanguage" in capsys.readouterr().err


def test_dispatch_cmdlet_and_commands_variants(monkeypatch, capsys):
    _dispatch_setup(monkeypatch, "structured", [{"Name": "Get-X"}])
    args = shell_args(backend="structured")
    assert J.dispatch_shell_line(args, Pool(), ":cmdlet", J.Logger(None)) == 1
    assert (
        J.dispatch_shell_line(
            args,
            Pool(),
            ":cmdlet Set-X Name=value -Force positional",
            J.Logger(None),
        )
        == 0
    )
    assert J.dispatch_shell_line(args, Pool(), ":cmdlet Get-X =bad", J.Logger(None)) == 1
    assert J.dispatch_shell_line(args, Pool(), ":commands --all Get-*", J.Logger(None)) == 0
    assert "Get-X" in capsys.readouterr().out

    calls = _dispatch_setup(monkeypatch, "script")
    assert J.dispatch_shell_line(shell_args(), Pool(), ":commands Get-*", J.Logger(None)) == 0
    assert "Get-Command" in calls[-1]


def test_dispatch_definition_proxy_history_variants(monkeypatch):
    command = _proxy_command()
    _dispatch_setup(monkeypatch, "structured", [command])
    args = shell_args(backend="structured")
    assert J.dispatch_shell_line(args, Pool(), ":def", J.Logger(None)) == 1
    assert J.dispatch_shell_line(args, Pool(), ":def Set-X", J.Logger(None)) == 0
    assert J.dispatch_shell_line(args, Pool(), ":proxy", J.Logger(None)) == 1
    assert J.dispatch_shell_line(args, Pool(), ":proxy Set-X", J.Logger(None)) == 0
    assert J.dispatch_shell_line(args, Pool(), ":history", J.Logger(None)) == 1
    assert J.dispatch_shell_line(args, Pool(), ':history "C:\\a b"', J.Logger(None)) == 0

    calls = _dispatch_setup(monkeypatch, "script")
    script = shell_args()
    assert J.dispatch_shell_line(script, Pool(), ":def Set-X", J.Logger(None)) == 0
    assert J.dispatch_shell_line(script, Pool(), ":proxy Set-X", J.Logger(None)) == 0
    assert J.dispatch_shell_line(script, Pool(), ":history", J.Logger(None)) == 0
    assert len(calls) == 3


def test_dispatch_load_upload_download_paths(tmp_path, monkeypatch):
    _dispatch_setup(monkeypatch, "script")
    args = shell_args()
    assert J.dispatch_shell_line(args, Pool(), ":load", J.Logger(None)) == 1
    assert J.dispatch_shell_line(args, Pool(), ":load missing", J.Logger(None)) == 1
    script = tmp_path / "x.ps1"
    script.write_text("Get-X", encoding="utf-8")
    assert J.dispatch_shell_line(args, Pool(), f":load {script}", J.Logger(None)) == 0

    monkeypatch.setattr(J, "resolve_backend", lambda *_args, **_kwargs: "structured")
    assert J.dispatch_shell_line(args, Pool(), f":load {script}", J.Logger(None)) == 1

    monkeypatch.setattr(J, "resolve_backend", lambda *_args, **_kwargs: "script")
    monkeypatch.setattr(J, "run_upload_with_pool", lambda *_args: 7)
    monkeypatch.setattr(J, "run_download_with_pool", lambda *_args: 8)
    assert J.dispatch_shell_line(args, Pool(), ":upload one", J.Logger(None)) == 1
    assert J.dispatch_shell_line(args, Pool(), ":upload local remote", J.Logger(None)) == 7
    assert J.dispatch_shell_line(args, Pool(), ":download one", J.Logger(None)) == 1
    assert J.dispatch_shell_line(args, Pool(), ":download remote local", J.Logger(None)) == 8
    assert args.local_path is None and args.remote_path is None


def test_shell_no_uncertain_retry_eof_interrupt_and_connect_failure(monkeypatch, capsys):
    monkeypatch.setattr(J, "open_pool", lambda _args: Pool())
    monkeypatch.setattr(J, "load_cmdlet_cache", lambda *_args: [])
    monkeypatch.setattr(J, "install_shell_completer", lambda _items: None)
    values = iter([":retry", EOFError])

    def fake_input(_prompt):
        value = next(values)
        if isinstance(value, type) and issubclass(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(builtins, "input", fake_input)
    assert J.run_shell(shell_args()) == 1
    assert "No uncertain" in capsys.readouterr().err

    monkeypatch.setattr(J, "open_pool", lambda _args: (_ for _ in ()).throw(RuntimeError("bad")))
    assert J.run_shell(shell_args()) == 1


def test_shell_bounds_reconnects_when_post_connect_initialization_keeps_failing(
    monkeypatch,
):
    monkeypatch.setattr(J, "open_pool", lambda _args: Pool())
    cache_calls = []

    def cache(*_args):
        cache_calls.append(1)
        if len(cache_calls) == 1:
            return []
        raise RuntimeError("cache initialization failed")

    monkeypatch.setattr(J, "load_cmdlet_cache", cache)
    monkeypatch.setattr(J, "install_shell_completer", lambda _items: None)
    monkeypatch.setattr(builtins, "input", lambda _prompt: "Get-X")
    monkeypatch.setattr(
        J,
        "dispatch_shell_line",
        lambda *_args: (_ for _ in ()).throw(J.SessionExpired("lost")),
    )
    sleeps = []

    def bounded_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 2:
            raise AssertionError("reconnect counter was reset before initialization")

    monkeypatch.setattr(J.time, "sleep", bounded_sleep)

    assert J.run_shell(shell_args()) == 1
    assert len(cache_calls) == 4  # initial success, then three bounded failures
    assert sleeps == [1.0, 2.0]


def test_transfer_wrappers(monkeypatch):
    monkeypatch.setattr(J, "open_pool", lambda _args: Pool())
    monkeypatch.setattr(J, "_do_upload", lambda *_args: 3)
    monkeypatch.setattr(J, "_do_download", lambda *_args: 4)
    upload = parse("dc", "upload", "a", "b")
    download = parse("dc", "download", "a", "b")
    assert J.run_upload(upload) == 3
    assert J.run_upload_with_pool(Pool(), upload, J.Logger(None)) == 3
    assert J.run_download(download) == 4
    assert J.run_download_with_pool(Pool(), download, J.Logger(None)) == 4


def test_main_success_hash_interrupt_system_exit_and_verbose_error(monkeypatch, capsys):
    monkeypatch.setattr(J, "run_info", lambda _args: 0)
    assert J.main(["dc", "info"]) == 0

    monkeypatch.setattr(J, "run_info", lambda _args: (_ for _ in ()).throw(KeyboardInterrupt))
    assert J.main(["dc", "info"]) == 130

    monkeypatch.setattr(J, "run_info", lambda _args: (_ for _ in ()).throw(RuntimeError("bad")))
    assert J.main(["dc", "info"]) == 1
    assert "Fatal: bad" in capsys.readouterr().err
    with pytest.raises(RuntimeError):
        J.main(["dc", "-v", "info"])

    with pytest.raises(SystemExit):
        J.main([])
