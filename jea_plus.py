#!/usr/bin/env python3
"""JEA+ - a PSRP assessment client for restricted PowerShell endpoints.

The script backend provides rich helpers for FullLanguage and
ConstrainedLanguage sessions. The structured backend builds PSRP command
pipelines without source text for conventional NoLanguage JEA endpoints.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import hashlib
import importlib.metadata
import inspect
import json
import os
import secrets
import stat
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__version__ = "1.1.0"


AUTH_CHOICES = (
    "basic",
    "certificate",
    "credssp",
    "kerberos",
    "negotiate",
    "ntlm",
)
WRAP_CHOICES = ("none", "ampersand")
DEFAULT_WRAPPER = "ampersand"
HISTORY_METHODS = ("auto", "cmdlet", "dotnet")
BACKEND_CHOICES = ("auto", "script", "structured")
TRANSFER_VERIFY_CHOICES = ("none", "size", "sha256")

# WSMan accepts **kwargs for authentication-specific options.  That must not be
# interpreted as carte blanche: unknown names are silently swallowed by some
# pypsrp releases.  These are the dynamic options documented and tested for the
# supported 0.8.1-0.9.x range.
WSMAN_DYNAMIC_KWARGS = frozenset(
    {
        "certificate_key_pem",
        "certificate_pem",
        "negotiate_delegate",
        "negotiate_hostname_override",
        "negotiate_service",
    }
)

SESSION_ERROR_HINTS = (
    "code: 400",  # JEA pipelines often close idle and answer 400/empty body
    "code: 401",
    "unauthorized",
    "invalid shell",
    "expired",
    "forbidden",
    "shell with shellid",
    "wsman service cannot process the request",
)


class SessionExpired(Exception):
    """Raised when a transport error suggests the WinRM/PSRP session is dead."""


@dataclass(frozen=True)
class CommandSpec:
    """One command in a source-free PSRP pipeline.

    Values are serialized by pypsrp and attached through ``add_parameter`` or
    ``add_argument``.  No PowerShell source text is parsed by the endpoint.
    """

    name: str
    parameters: tuple[tuple[str, Any], ...] = ()
    arguments: tuple[Any, ...] = ()
    end_of_statement: bool = False


def is_session_error(value: object) -> bool:
    lowered = str(value).lower()
    return any(hint in lowered for hint in SESSION_ERROR_HINTS)


def ps_quote(value: str) -> str:
    """Return a PowerShell single-quoted literal."""
    return "'" + value.replace("'", "''") + "'"


def apply_execution_wrapper(script: str, wrapper: str) -> str:
    if wrapper in (None, "none"):
        return script
    if wrapper == "ampersand":
        return f"& {{\n{script}\n}}"
    raise ValueError(f"Unknown wrapper: {wrapper}")


def eprint(*parts: object) -> None:
    print(*parts, file=sys.stderr)


class Logger:
    def __init__(self, path: str | None) -> None:
        self.path = Path(path).expanduser() if path else None

    def write(self, line: str) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif self.path.is_symlink():  # Best available protection on Windows.
            raise OSError(f"Refusing to follow log symlink: {self.path}")

        descriptor = os.open(self.path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(f"Log path is not a regular file: {self.path}")
            # Existing transcripts may predate the secure-create behavior.
            # Tighten them too; transcript content regularly contains secrets.
            with contextlib.suppress(AttributeError, OSError):
                os.fchmod(descriptor, 0o600)
            handle = os.fdopen(
                descriptor,
                "a",
                encoding="utf-8",
                errors="replace",
            )
            descriptor = -1
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        with handle:
            handle.write(line)
            if not line.endswith("\n"):
                handle.write("\n")


def emit(line: str, *, stderr: bool = False, logger: Logger | None = None) -> None:
    if stderr:
        eprint(line)
    else:
        print(line)
    if logger:
        prefix = "ERR " if stderr else "OUT "
        logger.write(prefix + line)


def load_pypsrp():
    try:
        from pypsrp.powershell import PowerShell, RunspacePool
        from pypsrp.wsman import WSMan
    except ImportError as exc:
        raise SystemExit(
            "Missing dependency: pypsrp.\n"
            "Install it with one of:\n"
            "  python -m pip install pypsrp\n"
            "  python -m pip install 'pypsrp[kerberos,credssp]'\n"
            "On Linux Kerberos also needs the system krb5 libraries."
        ) from exc
    return WSMan, RunspacePool, PowerShell


def dependency_version(distribution: str) -> str:
    """Return an installed distribution version without importing it."""
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def version_string() -> str:
    return f"jeaplus {__version__} (pypsrp {dependency_version('pypsrp')})"


def supported_kwargs(
    callable_obj,
    kwargs: Mapping[str, Any],
    *,
    var_keyword_names: Iterable[str] = (),
) -> tuple[dict[str, Any], list[str]]:
    """Filter kwargs against an API signature and an explicit ``**kwargs`` allowlist."""
    try:
        signature = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        allowed = set(var_keyword_names)
        filtered = {
            key: value for key, value in kwargs.items() if key in allowed and value is not None
        }
        ignored_on_unknown_signature = [
            key for key, value in kwargs.items() if value is not None and key not in allowed
        ]
        return filtered, ignored_on_unknown_signature

    accepts_any = any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    )
    dynamic = set(var_keyword_names) if accepts_any else set()

    supported: dict[str, Any] = {}
    ignored: list[str] = []
    for key, value in kwargs.items():
        if value is None:
            continue
        if key in signature.parameters or key in dynamic:
            supported[key] = value
        else:
            ignored.append(key)
    return supported, ignored


def get_password(args: argparse.Namespace) -> str:
    nthash = getattr(args, "hash", None)
    if nthash:
        # pypsrp's NTLM auth accepts the LM:NT credential form. The LM half is
        # ignored when only the NT hash is known, so we send 32 'f's as filler.
        return f"{'f' * 32}:{nthash}"
    if args.password_env:
        try:
            return os.environ[args.password_env]
        except KeyError as exc:
            raise SystemExit(f"Environment variable not set: {args.password_env}") from exc
    if args.ask_pass:
        return getpass.getpass("Password: ")
    if args.password is not None:
        return args.password
    return ""


def apply_kerberos_env(args: argparse.Namespace) -> None:
    env_pairs = {
        "KRB5CCNAME": args.ccache,
        "KRB5_CLIENT_KTNAME": args.keytab,
        "KRB5_CONFIG": args.krb5_config,
    }
    for name, value in env_pairs.items():
        if value:
            os.environ[name] = value


def build_wsman(args: argparse.Namespace):
    WSMan, _, _ = load_pypsrp()
    apply_kerberos_env(args)

    password = get_password(args)
    username = args.username

    # When using Kerberos without an explicit secret, pypsrp + gssapi will
    # trigger an AS-REQ the moment a username is passed alongside an empty
    # password - silently ignoring KRB5CCNAME / keytab. Drop username so
    # gssapi falls back to GSS_C_NO_CREDENTIAL and uses the existing cache.
    if args.auth == "kerberos" and not password:
        if username and getattr(args, "verbose", False):
            eprint(f"[kerberos] dropping --username '{username}' to honour KRB5CCNAME / keytab")
        username = None

    kwargs = {
        "server": args.host,
        "max_envelope_size": args.max_envelope_size,
        "operation_timeout": args.operation_timeout,
        "port": args.port,
        "username": username,
        "password": password if password else None,
        "ssl": args.ssl,
        "path": args.path,
        "auth": args.auth,
        "cert_validation": args.cert_validation,
        "connection_timeout": args.connection_timeout,
        "encryption": args.encryption,
        "locale": args.locale,
        "data_locale": args.data_locale,
        "read_timeout": args.read_timeout,
        "reconnection_retries": args.reconnection_retries,
    }

    extras: dict[str, Any] = {}
    if args.auth in ("kerberos", "negotiate", "ntlm"):
        extras.update(
            {
                "negotiate_delegate": args.delegate,
                "negotiate_hostname_override": args.hostname_override,
                "negotiate_service": args.negotiate_service,
            }
        )
    if args.auth == "certificate":
        extras.update(
            {
                "certificate_pem": args.certificate_pem,
                "certificate_key_pem": args.certificate_key_pem,
            }
        )
    kwargs.update(extras)
    filtered, ignored = supported_kwargs(
        WSMan,
        kwargs,
        var_keyword_names=WSMAN_DYNAMIC_KWARGS,
    )

    if ignored and args.verbose:
        eprint("Ignoring options unsupported by this pypsrp version:", ", ".join(ignored))

    return WSMan(**filtered)


def stream_items(ps) -> Iterable[tuple[str, object]]:
    streams = getattr(ps, "streams", None)
    if streams is None:
        return []
    # Drop progress entirely - PSRP emits a flurry of None-valued progress
    # records on most calls and they translate to "[progress] None" noise.
    names = ("error", "warning", "verbose", "debug", "information")
    items = []
    for name in names:
        stream = getattr(streams, name, None)
        if stream is None:
            continue
        try:
            for value in stream:
                if value is None:
                    continue
                items.append((name, value))
        except TypeError:
            continue
    return items


def _invoke_pipeline(
    ps,
    *,
    command_log: str,
    logger: Logger | None,
    display: bool,
    show_streams: bool,
    raise_session: bool,
) -> tuple[int, list[object]]:
    """Invoke a configured pypsrp PowerShell instance and normalize streams."""
    if logger:
        logger.write(command_log)

    try:
        output = ps.invoke()
    except Exception as exc:  # pypsrp exposes multiple transport/runtime types.
        if raise_session and is_session_error(exc):
            raise SessionExpired(str(exc)) from exc
        emit(f"[invoke-error] {exc}", stderr=True, logger=logger)
        return 1, []

    values = [item for item in output if item is not None]
    if display:
        for item in values:
            emit(str(item), logger=logger)

    if show_streams:
        for name, item in stream_items(ps):
            text = str(item)
            emit(f"[{name}] {text}", stderr=(name == "error"), logger=logger)

    return (1 if getattr(ps, "had_errors", False) else 0), values


def _format_command_spec(spec: CommandSpec) -> str:
    parts = [spec.name]
    for name, value in spec.parameters:
        parts.append(f"-{name}")
        if value is not None:
            parts.append(repr(value))
    parts.extend(repr(value) for value in spec.arguments)
    if spec.end_of_statement:
        parts.append(";")
    return " ".join(parts)


def invoke_structured(
    pool,
    specs: Sequence[CommandSpec],
    *,
    logger: Logger | None = None,
    display: bool = True,
    show_streams: bool = True,
    raise_session: bool = False,
) -> tuple[int, list[object]]:
    """Execute a source-free PSRP pipeline through ``add_cmdlet`` APIs."""
    if not specs:
        raise ValueError("A structured pipeline needs at least one command.")

    _, _, PowerShell = load_pypsrp()
    ps = PowerShell(pool)
    for spec in specs:
        ps.add_cmdlet(spec.name)
        for name, value in spec.parameters:
            ps.add_parameter(name, value)
        for value in spec.arguments:
            ps.add_argument(value)
        if spec.end_of_statement:
            ps.add_statement()

    rendered = " | ".join(_format_command_spec(spec) for spec in specs)
    return _invoke_pipeline(
        ps,
        command_log="CMDLET " + rendered,
        logger=logger,
        display=display,
        show_streams=show_streams,
        raise_session=raise_session,
    )


def invoke_ps(
    pool,
    script: str,
    *,
    logger: Logger | None = None,
    display: bool = True,
    show_streams: bool = True,
    wrapper: str = "none",
    raise_session: bool = False,
    max_envelope_size: int | None = None,
) -> tuple[int, list[str]]:
    _, _, PowerShell = load_pypsrp()
    script = apply_execution_wrapper(script, wrapper)

    # Pre-check: PSRP/SOAP wrapping plus the WSMan service's own per-message
    # ceiling means the practical script ceiling is well under
    # --max-envelope-size. Empirically against the live JEA endpoint,
    # scripts above ~30% of the configured envelope tear down the WinRM
    # shell (WSManFault Code 1726, then "shell with shellid not found").
    # Catch it client-side so we don't have to reconnect to recover.
    script_bytes = len(script.encode("utf-8"))
    if max_envelope_size and script_bytes > int(max_envelope_size * 0.30):
        msg = (
            f"script size {script_bytes} UTF-8 bytes exceeds the WSMan envelope "
            f"budget (--max-envelope-size {max_envelope_size}); raise the "
            "envelope or split into smaller calls"
        )
        emit(f"[size-error] {msg}", stderr=True, logger=logger)
        return 1, []

    ps = PowerShell(pool)
    ps.add_script(script)
    rc, output = _invoke_pipeline(
        ps,
        command_log="CMD " + script.strip().replace("\n", "\\n"),
        logger=logger,
        display=display,
        show_streams=show_streams,
        raise_session=raise_session,
    )
    return rc, [str(item) for item in output]


def ps_property(value: object, name: str, default: Any = None) -> Any:
    """Read a deserialized PowerShell property across pypsrp object shapes."""
    lowered = name.lower()
    if isinstance(value, Mapping):
        for key, candidate in value.items():
            if str(key).lower() == lowered:
                return candidate

    for container_name in ("adapted_properties", "extended_properties"):
        container = getattr(value, container_name, None)
        if isinstance(container, Mapping):
            for key, candidate in container.items():
                if str(key).lower() == lowered:
                    return candidate

    attributes = getattr(value, "__dict__", {})
    if isinstance(attributes, Mapping):
        for key, candidate in attributes.items():
            if str(key).lower() == lowered:
                return candidate

    try:
        return getattr(value, name)
    except (AttributeError, TypeError):
        return default


LANGUAGE_MODE_PROBE = "$ExecutionContext.SessionState.LanguageMode"


def resolve_backend(
    args: argparse.Namespace,
    pool,
    logger: Logger | None = None,
) -> str:
    """Resolve ``auto`` by making one non-mutating language-mode probe."""
    requested = getattr(args, "backend", "script")
    if requested != "auto":
        return requested

    cached = getattr(args, "_resolved_backend", None)
    if cached:
        return cached

    rc, lines = invoke_ps(
        pool,
        LANGUAGE_MODE_PROBE,
        logger=logger,
        display=False,
        show_streams=False,
        wrapper="none",
        max_envelope_size=getattr(args, "max_envelope_size", None),
    )
    mode = next(
        (
            line.strip()
            for line in lines
            if line.strip().lower()
            in {
                "fulllanguage",
                "constrainedlanguage",
                "restrictedlanguage",
                "nolanguage",
            }
        ),
        None,
    )
    backend = (
        "script" if rc == 0 and mode is not None and mode.lower() != "nolanguage" else "structured"
    )
    args._resolved_backend = backend
    args._remote_language_mode = mode or "source probe rejected"
    if getattr(args, "verbose", False):
        emit(
            f"[backend] {backend} ({args._remote_language_mode})",
            stderr=True,
            logger=logger,
        )
    return backend


def invoke_remote(
    args: argparse.Namespace,
    pool,
    script: str,
    **kwargs,
) -> tuple[int, list[str]]:
    kwargs.setdefault("wrapper", getattr(args, "wrap", DEFAULT_WRAPPER))
    kwargs.setdefault("max_envelope_size", getattr(args, "max_envelope_size", None))
    return invoke_ps(pool, script, **kwargs)


def open_pool(args: argparse.Namespace):
    _, RunspacePool, _ = load_pypsrp()
    wsman = build_wsman(args)
    return RunspacePool(wsman, configuration_name=args.configuration_name)


def wrap_json(script: str, depth: int) -> str:
    return (
        f"$ErrorActionPreference = 'Stop'\n& {{\n{script}\n}} | ConvertTo-Json -Depth {int(depth)}"
    )


def command_from_remainder(parts: list[str]) -> str:
    if parts and parts[0] == "--":
        parts = parts[1:]
    if len(parts) == 1:
        return parts[0].strip()
    if any(any(character.isspace() for character in part) for part in parts):
        raise SystemExit(
            "run command is ambiguous because the invoking shell removed "
            "argument quoting. Pass the complete PowerShell expression as one "
            "quoted argument, use --command-file, or use --stdin."
        )
    return " ".join(parts).strip()


def read_command_source(args: argparse.Namespace) -> str:
    """Read exactly one source command from argv, a file, or stdin."""
    from_file = getattr(args, "command_file", None)
    from_stdin = bool(getattr(args, "command_stdin", False))
    remainder = list(getattr(args, "command", []))
    if remainder and remainder[0] == "--":
        remainder = remainder[1:]

    selected = int(bool(from_file)) + int(from_stdin) + int(bool(remainder))
    if selected != 1:
        raise SystemExit(
            "run needs exactly one command source: a quoted expression, "
            "--command-file PATH, or --stdin."
        )

    if from_file:
        path = Path(from_file).expanduser()
        if not path.is_file():
            raise SystemExit(f"Command file not found: {path}")
        return path.read_text(
            encoding=getattr(args, "encoding", "utf-8"),
            errors="replace",
        )
    if from_stdin:
        return sys.stdin.read()
    return command_from_remainder(remainder)


PIPELINE_KEYS = frozenset({"cmdlet", "parameters", "arguments", "end_of_statement"})


def _validate_command_name(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ValueError(f"{field} contains a forbidden control character")
    return value.strip()


def parse_pipeline_document(document: object) -> list[CommandSpec]:
    """Validate the JSON schema used by the source-free pipeline command."""
    if not isinstance(document, list) or not document:
        raise ValueError("pipeline JSON must be a non-empty array")

    specs: list[CommandSpec] = []
    for index, entry in enumerate(document):
        if not isinstance(entry, Mapping):
            raise ValueError(f"pipeline entry {index} must be an object")
        unknown = set(entry) - PIPELINE_KEYS
        if unknown:
            raise ValueError(
                f"pipeline entry {index} has unknown keys: {', '.join(sorted(unknown))}"
            )

        name = _validate_command_name(
            entry.get("cmdlet"),
            field=f"pipeline entry {index}.cmdlet",
        )
        parameters = entry.get("parameters", {})
        if not isinstance(parameters, Mapping):
            raise ValueError(f"pipeline entry {index}.parameters must be an object")
        parameter_pairs: list[tuple[str, Any]] = []
        for parameter_name, value in parameters.items():
            validated = _validate_command_name(
                parameter_name,
                field=f"pipeline entry {index} parameter name",
            )
            parameter_pairs.append((validated, value))

        arguments = entry.get("arguments", [])
        if not isinstance(arguments, list):
            raise ValueError(f"pipeline entry {index}.arguments must be an array")
        end_of_statement = entry.get("end_of_statement", False)
        if not isinstance(end_of_statement, bool):
            raise ValueError(f"pipeline entry {index}.end_of_statement must be a boolean")

        specs.append(
            CommandSpec(
                name,
                parameters=tuple(parameter_pairs),
                arguments=tuple(arguments),
                end_of_statement=end_of_statement,
            )
        )
    return specs


def _name_value(value: str, *, option: str) -> tuple[str, str]:
    name, separator, raw = value.partition("=")
    if not separator:
        raise SystemExit(f"{option} expects NAME=VALUE: {value!r}")
    try:
        name = _validate_command_name(name, field=option)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    return name, raw


def command_specs_from_args(args: argparse.Namespace) -> list[CommandSpec]:
    parameters: list[tuple[str, Any]] = []
    for item in getattr(args, "parameters", []) or []:
        parameters.append(_name_value(item, option="--parameter"))
    for item in getattr(args, "parameters_json", []) or []:
        name, raw = _name_value(item, option="--parameter-json")
        try:
            parameters.append((name, json.loads(raw)))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON for parameter {name}: {exc}") from exc
    for name in getattr(args, "switches", []) or []:
        try:
            validated = _validate_command_name(name, field="--switch")
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        parameters.append((validated, None))

    arguments: list[Any] = list(getattr(args, "arguments", []) or [])
    for raw in getattr(args, "arguments_json", []) or []:
        try:
            arguments.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON for --argument-json: {exc}") from exc

    try:
        name = _validate_command_name(args.name, field="cmdlet")
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    return [CommandSpec(name, tuple(parameters), tuple(arguments))]


def load_pipeline_document(path_value: str, encoding: str) -> object:
    if path_value == "-":
        source = sys.stdin.read()
    else:
        path = Path(path_value).expanduser()
        if not path.is_file():
            raise SystemExit(f"Pipeline file not found: {path}")
        source = path.read_text(encoding=encoding, errors="strict")
    try:
        return json.loads(source)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid pipeline JSON: {exc}") from exc


def run_cmdlet(args: argparse.Namespace) -> int:
    specs = command_specs_from_args(args)
    with open_pool(args) as pool:
        rc, _ = invoke_structured(pool, specs, logger=Logger(args.log))
        return rc


def run_pipeline(args: argparse.Namespace) -> int:
    document = load_pipeline_document(args.pipeline_path, args.encoding)
    try:
        specs = parse_pipeline_document(document)
    except ValueError as exc:
        raise SystemExit(f"Invalid pipeline: {exc}") from exc
    with open_pool(args) as pool:
        rc, _ = invoke_structured(pool, specs, logger=Logger(args.log))
        return rc


def run_command(args: argparse.Namespace) -> int:
    script = read_command_source(args)
    if not script:
        raise SystemExit("run needs a PowerShell command.")
    with open_pool(args) as pool:
        backend = resolve_backend(args, pool, Logger(args.log))
        if backend == "structured":
            raise SystemExit(
                "This endpoint rejected PowerShell source and auto-selected the "
                "structured NoLanguage backend. Use the cmdlet or pipeline "
                "subcommand, or force --backend script if the probe was wrong."
            )
        if args.json:
            script = wrap_json(script, args.json_depth)
        rc, _ = invoke_remote(args, pool, script, logger=Logger(args.log))
        return rc


def run_script(args: argparse.Namespace) -> int:
    path = Path(args.script_path).expanduser()
    if not path.is_file():
        raise SystemExit(f"Script not found: {path}")
    script = path.read_text(encoding=args.encoding, errors="replace")
    logger = Logger(args.log)
    with open_pool(args) as pool:
        if resolve_backend(args, pool, logger) == "structured":
            emit(
                "script source is unavailable in the structured NoLanguage "
                "backend; use pipeline with a JSON command document",
                stderr=True,
                logger=logger,
            )
            return 1
        if args.json:
            script = wrap_json(script, args.json_depth)
        rc, _ = invoke_remote(args, pool, script, logger=logger)
        return rc


def run_batch(args: argparse.Namespace) -> int:
    path = Path(args.batch_path).expanduser()
    if not path.is_file():
        raise SystemExit(f"Batch file not found: {path}")
    commands = [
        line.strip()
        for line in path.read_text(encoding=args.encoding, errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    logger = Logger(args.log)
    rc_total = 0
    with open_pool(args) as pool:
        if resolve_backend(args, pool, logger) == "structured":
            emit(
                "batch source is unavailable in the structured NoLanguage "
                "backend; use pipeline with a JSON command document",
                stderr=True,
                logger=logger,
            )
            return 1
        for index, command in enumerate(commands, start=1):
            emit(f"--- [{index}/{len(commands)}] {command}", logger=logger)
            rc, _ = invoke_remote(args, pool, command, logger=logger)
            if rc:
                rc_total = rc
                if args.stop_on_error:
                    break
    return rc_total


# ConstrainedLanguage / NoLanguage runspaces (the bread-and-butter of JEA)
# block static method calls like [Security.Principal.WindowsIdentity]::GetCurrent()
# and reject Select-Object properties that aren't on a small allowlist.
# These helpers stick to variable / property reads and the safe property set.
INFO_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
"ComputerName:        $env:COMPUTERNAME"
"User:                $env:USERDOMAIN\$env:USERNAME"
"PSVersion:           $($PSVersionTable.PSVersion)"
"PSEdition:           $($PSVersionTable.PSEdition)"
"LanguageMode:        $($ExecutionContext.SessionState.LanguageMode)"
"CurrentDirectory:    $((Get-Location).Path)"
if ($PSSenderInfo) {
    "ConnectedUser:       $($PSSenderInfo.ConnectedUser)"
    "RunAsUser:           $($PSSenderInfo.RunAsUser)"
    "ConfigurationName:   $($PSSenderInfo.ConfigurationName)"
}
"""


def make_commands_script(pattern: str, command_types: tuple | None = ("Function", "Cmdlet")) -> str:
    # Select-Object's JEA proxy only allows a fixed property set; Source and
    # Version are excluded. ModuleName is the safe stand-in. Out-String
    # flattens Format-Table's internal record objects to text - without it
    # PSRP serialises FormatEntryData stubs that print as their type name.
    # Default filter to Function+Cmdlet - the typical JEA endpoint dumps
    # 2000+ aliases / Application stubs that drown out the actual surface;
    # callers pass command_types=None to opt in to "show everything".
    type_filter = ""
    if command_types:
        type_filter = f"-CommandType {','.join(command_types)} "
    return rf"""
$ErrorActionPreference = 'Continue'
$cmds = Get-Command -Name {ps_quote(pattern)} {type_filter}-ErrorAction SilentlyContinue
if (-not $cmds) {{
    "no commands match pattern: " + {ps_quote(pattern)}
    return
}}
$cmds |
    Sort-Object CommandType, Name |
    Select-Object CommandType, Name, ModuleName |
    Format-Table -AutoSize |
    Out-String -Stream
"""


def run_info(args: argparse.Namespace) -> int:
    logger = Logger(args.log)
    with open_pool(args) as pool:
        if resolve_backend(args, pool, logger) == "structured":
            emit("ExecutionBackend:    structured", logger=logger)
            emit(
                f"LanguageModeProbe:   {getattr(args, '_remote_language_mode', 'not run')}",
                logger=logger,
            )
            emit(
                "Identity and PSVersion fields require language expressions; "
                "use cmdlet/pipeline for commands allowed by this NoLanguage endpoint.",
                logger=logger,
            )
            return 0
        rc, _ = invoke_remote(args, pool, INFO_SCRIPT, logger=logger)
        return rc


def _format_command_rows(output: Sequence[object]) -> list[str]:
    rows: list[tuple[str, str, str]] = []
    for item in output:
        name = str(ps_property(item, "Name", "")).strip()
        command_type = str(ps_property(item, "CommandType", "")).strip()
        module = str(ps_property(item, "ModuleName", "")).strip()
        if not name:
            name = str(item).strip()
        if name:
            rows.append((command_type or "?", name, module))
    if not rows:
        return []
    widths = [
        max(len(title), *(len(row[index]) for row in rows))
        for index, title in enumerate(("CommandType", "Name", "ModuleName"))
    ]
    header = f"{'CommandType':<{widths[0]}}  {'Name':<{widths[1]}}  {'ModuleName':<{widths[2]}}"
    separator = "  ".join("-" * width for width in widths)
    rendered = [header.rstrip(), separator.rstrip()]
    rendered.extend(
        f"{kind:<{widths[0]}}  {name:<{widths[1]}}  {module:<{widths[2]}}".rstrip()
        for kind, name, module in sorted(rows, key=lambda row: (row[0], row[1]))
    )
    return rendered


def run_commands(args: argparse.Namespace) -> int:
    pattern = args.pattern or "*"
    types = None if getattr(args, "all", False) else ("Function", "Cmdlet")
    logger = Logger(args.log)
    with open_pool(args) as pool:
        if resolve_backend(args, pool, logger) == "structured":
            parameters: list[tuple[str, Any]] = [
                ("Name", pattern),
                ("ErrorAction", "SilentlyContinue"),
            ]
            if types:
                parameters.append(("CommandType", list(types)))
            rc, output = invoke_structured(
                pool,
                [CommandSpec("Get-Command", tuple(parameters))],
                logger=logger,
                display=False,
            )
            if rc:
                return rc
            rows = _format_command_rows(output)
            if not rows:
                emit(f"no commands match pattern: {pattern}", logger=logger)
                return 0
            for row in rows:
                emit(row, logger=logger)
            return 0
        rc, _ = invoke_remote(
            args,
            pool,
            make_commands_script(pattern, command_types=types),
            logger=logger,
        )
        return rc


def make_history_script(remote_path: str | None, method: str = "auto") -> str:
    if method not in HISTORY_METHODS:
        raise ValueError(f"Unknown history method: {method}")
    if remote_path:
        path_expr = ps_quote(remote_path)
    else:
        path_expr = (
            "Join-Path $env:APPDATA "
            "'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'"
        )

    readers = {
        "cmdlet": "$lines = @(Get-Content -LiteralPath $h -ErrorAction Stop)",
        "dotnet": "$lines = @([System.IO.File]::ReadAllLines($h))",
        "auto": """try {
    $lines = @(Get-Content -LiteralPath $h -ErrorAction Stop)
} catch {
    # FullLanguage fallback. ConstrainedLanguage endpoints should expose
    # Get-Content; NoLanguage callers must use the structured backend.
    $lines = @([System.IO.File]::ReadAllLines($h))
}""",
    }

    return rf"""
$ErrorActionPreference = 'Continue'
$h = {path_expr}
if (-not (Test-Path -LiteralPath $h)) {{
    "PATH: $h"
    "ERROR: history not found"
    return
}}
{readers[method]}
"PATH: $h"
"TOTAL LINES: $($lines.Count)"
for ($i = 0; $i -lt $lines.Count; $i++) {{
    "[${{i}}] $($lines[$i])"
}}
"""


def run_history(args: argparse.Namespace) -> int:
    logger = Logger(args.log)
    with open_pool(args) as pool:
        backend = resolve_backend(args, pool, logger)
        if backend == "structured":
            if not args.remote_path:
                emit(
                    "history on a NoLanguage endpoint needs --remote-path; "
                    "the default path expression requires PowerShell language features",
                    stderr=True,
                    logger=logger,
                )
                return 1
            if args.method == "dotnet":
                emit(
                    "--method dotnet requires the script backend",
                    stderr=True,
                    logger=logger,
                )
                return 1
            rc, _ = invoke_structured(
                pool,
                [
                    CommandSpec(
                        "Get-Content",
                        parameters=(
                            ("LiteralPath", args.remote_path),
                            ("ErrorAction", "Stop"),
                        ),
                    )
                ],
                logger=logger,
            )
            return rc
        script = make_history_script(args.remote_path, args.method)
        rc, _ = invoke_remote(args, pool, script, logger=logger)
        return rc


# Upload/download under ConstrainedLanguage (the JEA default) cannot use
# [System.IO.File] / [Convert] static methods. The cmdlet path -
# Set-Content / Add-Content / Get-Content with -Encoding Byte - passes
# both the language-mode check and most JEA proxy ValidateSets.
#
# Upload encodes each chunk as a [byte[]]@(d1,d2,...) literal (3-4 chars
# per byte) so we keep the WSMan envelope sized for the default 150 KB
# limit; pick chunk_size accordingly.
# Download asks the server to format chunks as concatenated hex; Python
# rebuilds with bytes.fromhex.

UPLOAD_DEFAULT_CHUNK = 8192  # 8 KB raw -> ~30 KB script literal
DOWNLOAD_DEFAULT_CHUNK_BYTES = 4096


def _upload_init_script(remote: str) -> str:
    return rf"""
$ErrorActionPreference = 'Stop'
$path = {ps_quote(remote)}
if (Test-Path -LiteralPath $path) {{
    Remove-Item -LiteralPath $path -Force
}}
"""


def _upload_chunk_script(remote: str, chunk: bytes, first: bool) -> str:
    decimals = ",".join(str(b) for b in chunk)
    cmdlet = "Set-Content" if first else "Add-Content"
    return rf"""
$ErrorActionPreference = 'Stop'
$b = [byte[]] @({decimals})
{cmdlet} -LiteralPath {ps_quote(remote)} -Value $b -Encoding Byte
"""


def _upload_verify_script(remote: str) -> str:
    return _remote_size_script(remote)


def _remote_size_script(remote: str) -> str:
    return rf"""
$ErrorActionPreference = 'Stop'
$path = {ps_quote(remote)}
"JEAPLUS-SIZE:$((Get-Item -LiteralPath $path).Length)"
"""


def _remote_hash_script(remote: str) -> str:
    return rf"""
$ErrorActionPreference = 'Stop'
$hash = Get-FileHash -LiteralPath {ps_quote(remote)} -Algorithm SHA256
"JEAPLUS-SHA256:$($hash.Hash)"
"""


def _upload_commit_script(staging: str, destination: str) -> str:
    return rf"""
$ErrorActionPreference = 'Stop'
Move-Item -LiteralPath {ps_quote(staging)} -Destination {ps_quote(destination)} -Force
"""


def _remote_cleanup_script(remote: str) -> str:
    return rf"""
$ErrorActionPreference = 'SilentlyContinue'
if (Test-Path -LiteralPath {ps_quote(remote)}) {{
    Remove-Item -LiteralPath {ps_quote(remote)} -Force
}}
"""


def _download_script(remote: str, chunk_bytes: int) -> str:
    # ReadCount=N tells Get-Content to emit arrays of N bytes; we hex-encode
    # each array server-side so the payload arrives as one string per chunk.
    return rf"""
$ErrorActionPreference = 'Stop'
Get-Content -LiteralPath {ps_quote(remote)} -Encoding Byte -ReadCount {int(chunk_bytes)} |
    ForEach-Object {{ -join ($_ | ForEach-Object {{ '{{0:x2}}' -f $_ }}) }}
"""


def make_remote_staging_path(destination: str) -> str:
    """Return an adjacent random path so the final rename stays on one volume."""
    return f"{destination}.jeaplus-tmp-{secrets.token_hex(8)}"


def parse_remote_size(output: Sequence[object]) -> int:
    for item in output:
        text = str(item).strip()
        if text.startswith("JEAPLUS-SIZE:"):
            raw = text.partition(":")[2].strip()
            try:
                return int(raw)
            except ValueError as exc:
                raise ValueError(f"invalid remote size: {raw!r}") from exc
        length = ps_property(item, "Length")
        if length is not None:
            try:
                return int(length)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid remote Length property: {length!r}") from exc
    raise ValueError("remote size marker was not returned")


def parse_remote_hash(output: Sequence[object]) -> str:
    for item in output:
        text = str(item).strip()
        if text.upper().startswith("JEAPLUS-SHA256:"):
            candidate = text.partition(":")[2].strip().lower()
        else:
            candidate = str(ps_property(item, "Hash", "")).strip().lower()
        if len(candidate) == 64 and all(character in "0123456789abcdef" for character in candidate):
            return candidate
    raise ValueError("remote SHA-256 marker was not returned")


def _invoke_transfer(
    args: argparse.Namespace,
    pool,
    script: str,
    specs: Sequence[CommandSpec],
    *,
    logger: Logger,
    display: bool = False,
    show_streams: bool = True,
) -> tuple[int, list[object]]:
    if resolve_backend(args, pool, logger) == "structured":
        return invoke_structured(
            pool,
            specs,
            logger=logger,
            display=display,
            show_streams=show_streams,
        )
    rc, lines = invoke_remote(
        args,
        pool,
        script,
        logger=logger,
        display=display,
        show_streams=show_streams,
    )
    return rc, list(lines)


def _upload_chunk_spec(remote: str, chunk: bytes, first: bool) -> CommandSpec:
    return CommandSpec(
        "Set-Content" if first else "Add-Content",
        parameters=(
            ("LiteralPath", remote),
            ("Value", list(chunk)),
            ("Encoding", "Byte"),
            ("ErrorAction", "Stop"),
        ),
    )


def _remote_size_spec(remote: str) -> CommandSpec:
    return CommandSpec(
        "Get-Item",
        parameters=(("LiteralPath", remote), ("ErrorAction", "Stop")),
    )


def _remote_hash_spec(remote: str) -> CommandSpec:
    return CommandSpec(
        "Get-FileHash",
        parameters=(
            ("LiteralPath", remote),
            ("Algorithm", "SHA256"),
            ("ErrorAction", "Stop"),
        ),
    )


def _cleanup_remote(
    args: argparse.Namespace,
    pool,
    remote: str,
    logger: Logger,
) -> None:
    _invoke_transfer(
        args,
        pool,
        _remote_cleanup_script(remote),
        [
            CommandSpec(
                "Remove-Item",
                parameters=(
                    ("LiteralPath", remote),
                    ("Force", None),
                    ("ErrorAction", "SilentlyContinue"),
                ),
            )
        ],
        logger=logger,
        display=False,
        show_streams=False,
    )


def _do_upload(pool, args: argparse.Namespace, logger: Logger) -> int:
    local = Path(args.local_path).expanduser()
    if not local.is_file():
        emit(f"Local file not found: {local}", stderr=True, logger=logger)
        return 1
    destination = args.remote_path
    staging = make_remote_staging_path(destination)
    chunk_size = max(1, int(getattr(args, "chunk_size", UPLOAD_DEFAULT_CHUNK)))
    verify = getattr(args, "verify", "size")
    expected_size = local.stat().st_size
    total_chunks = max(1, (expected_size + chunk_size - 1) // chunk_size)
    digest = hashlib.sha256() if verify == "sha256" else None
    bytes_sent = 0
    index = 0

    with local.open("rb") as handle:
        first = True
        while True:
            chunk = handle.read(chunk_size)
            if not chunk and not first:
                break
            index += 1
            rc, _ = _invoke_transfer(
                args,
                pool,
                _upload_chunk_script(staging, chunk, first),
                [_upload_chunk_spec(staging, chunk, first)],
                logger=logger,
                display=False,
            )
            if rc:
                _cleanup_remote(args, pool, staging, logger)
                return rc
            bytes_sent += len(chunk)
            if digest is not None:
                digest.update(chunk)
            if getattr(args, "progress", False):
                emit(f"uploaded chunk {index}/{total_chunks}", logger=logger)
            first = False
            if not chunk:  # Empty files still need one Set-Content call.
                break

    if bytes_sent != expected_size:
        emit(
            f"Upload source changed while reading: expected {expected_size} bytes, "
            f"read {bytes_sent}",
            stderr=True,
            logger=logger,
        )
        _cleanup_remote(args, pool, staging, logger)
        return 1

    if verify != "none":
        rc, output = _invoke_transfer(
            args,
            pool,
            _remote_size_script(staging),
            [_remote_size_spec(staging)],
            logger=logger,
            display=False,
        )
        if rc:
            _cleanup_remote(args, pool, staging, logger)
            return rc
        try:
            remote_size = parse_remote_size(output)
        except ValueError as exc:
            emit(f"Upload verification failed: {exc}", stderr=True, logger=logger)
            _cleanup_remote(args, pool, staging, logger)
            return 1
        if remote_size != expected_size:
            emit(
                f"Upload size mismatch: local={expected_size}, remote={remote_size}",
                stderr=True,
                logger=logger,
            )
            _cleanup_remote(args, pool, staging, logger)
            return 1

    expected_hash: str | None = None
    if verify == "sha256":
        expected_hash = digest.hexdigest() if digest is not None else ""
        rc, output = _invoke_transfer(
            args,
            pool,
            _remote_hash_script(staging),
            [_remote_hash_spec(staging)],
            logger=logger,
            display=False,
        )
        if rc:
            _cleanup_remote(args, pool, staging, logger)
            return rc
        try:
            remote_hash = parse_remote_hash(output)
        except ValueError as exc:
            emit(f"Upload verification failed: {exc}", stderr=True, logger=logger)
            _cleanup_remote(args, pool, staging, logger)
            return 1
        if remote_hash != expected_hash:
            emit(
                f"Upload SHA-256 mismatch: local={expected_hash}, remote={remote_hash}",
                stderr=True,
                logger=logger,
            )
            _cleanup_remote(args, pool, staging, logger)
            return 1

    rc, _ = _invoke_transfer(
        args,
        pool,
        _upload_commit_script(staging, destination),
        [
            CommandSpec(
                "Move-Item",
                parameters=(
                    ("LiteralPath", staging),
                    ("Destination", destination),
                    ("Force", None),
                    ("ErrorAction", "Stop"),
                ),
            )
        ],
        logger=logger,
        display=False,
    )
    if rc:
        _cleanup_remote(args, pool, staging, logger)
        return rc

    suffix = f", sha256={expected_hash}" if expected_hash else ""
    emit(f"Uploaded: {destination} ({expected_size} bytes{suffix})", logger=logger)
    return 0


def _structured_download_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, int) and not isinstance(value, bool):
        if 0 <= value <= 255:
            return bytes((value,))
        raise ValueError(f"byte value out of range: {value}")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return b"".join(_structured_download_bytes(item) for item in value)
    raise ValueError(f"unsupported structured byte value: {type(value).__name__}")


def _do_download(pool, args: argparse.Namespace, logger: Logger) -> int:
    remote = args.remote_path
    local = Path(args.local_path).expanduser()
    chunk_bytes = max(256, getattr(args, "chunk_bytes", DOWNLOAD_DEFAULT_CHUNK_BYTES))
    verify = getattr(args, "verify", "size")
    backend = resolve_backend(args, pool, logger)

    rc, output = _invoke_transfer(
        args,
        pool,
        _download_script(remote, chunk_bytes),
        [
            CommandSpec(
                "Get-Content",
                parameters=(
                    ("LiteralPath", remote),
                    ("Encoding", "Byte"),
                    ("ReadCount", chunk_bytes),
                    ("ErrorAction", "Stop"),
                ),
            )
        ],
        logger=logger,
        display=False,
    )
    if rc:
        return rc
    local.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    downloaded = 0
    digest = hashlib.sha256() if verify == "sha256" else None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{local.name}.jeaplus-",
            dir=local.parent,
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            os.chmod(temporary_path, 0o600)
            for item in output:
                try:
                    if backend == "structured":
                        chunk = _structured_download_bytes(item)
                    else:
                        text = str(item).strip()
                        if not text:
                            continue
                        chunk = bytes.fromhex(text)
                except ValueError as exc:
                    raise ValueError(f"could not decode remote chunk: {exc}") from exc
                handle.write(chunk)
                downloaded += len(chunk)
                if digest is not None:
                    digest.update(chunk)

        if verify != "none":
            rc, metadata = _invoke_transfer(
                args,
                pool,
                _remote_size_script(remote),
                [_remote_size_spec(remote)],
                logger=logger,
                display=False,
            )
            if rc:
                return rc
            remote_size = parse_remote_size(metadata)
            if remote_size != downloaded:
                raise ValueError(
                    f"download size mismatch: remote={remote_size}, local={downloaded}"
                )

        local_hash: str | None = None
        if verify == "sha256":
            local_hash = digest.hexdigest() if digest is not None else ""
            rc, metadata = _invoke_transfer(
                args,
                pool,
                _remote_hash_script(remote),
                [_remote_hash_spec(remote)],
                logger=logger,
                display=False,
            )
            if rc:
                return rc
            remote_hash = parse_remote_hash(metadata)
            if remote_hash != local_hash:
                raise ValueError(
                    f"download SHA-256 mismatch: remote={remote_hash}, local={local_hash}"
                )

        os.replace(temporary_path, local)
        temporary_path = None
        os.chmod(local, 0o600)
    except (OSError, ValueError) as exc:
        emit(f"Download failed: {exc}", stderr=True, logger=logger)
        return 1
    finally:
        if temporary_path is not None:
            with contextlib.suppress(OSError):
                temporary_path.unlink(missing_ok=True)

    suffix = f", sha256={local_hash}" if verify == "sha256" else ""
    emit(f"Downloaded: {local} ({downloaded} bytes{suffix})", logger=logger)
    return 0


def run_upload(args: argparse.Namespace) -> int:
    logger = Logger(args.log)
    with open_pool(args) as pool:
        return _do_upload(pool, args, logger)


def run_download(args: argparse.Namespace) -> int:
    logger = Logger(args.log)
    with open_pool(args) as pool:
        return _do_download(pool, args, logger)


def make_proxy_script(name: str) -> str:
    # Shows the parameters that the JEA proxy actually exposes plus their
    # validation attributes (ValidateSet, ValidatePattern, ValidateLength,
    # ValidateRange, Aliases). This is what matters for escape hunting:
    # the cmdlet's documented signature can include parameters and values
    # the proxy strips, so :def alone (which prints the cmdlet definition)
    # under-reports the constraints. Property access only - no method
    # calls on non-core types - so it runs under ConstrainedLanguage.
    return rf"""
$ErrorActionPreference = 'Continue'
$name = {ps_quote(name)}
$cmd = Get-Command -Name $name -ErrorAction SilentlyContinue
if (-not $cmd) {{
    "Command not found: $name"
    return
}}
"Cmdlet:      $($cmd.Name)"
"CommandType: $($cmd.CommandType)"
if ($cmd.ModuleName) {{ "Module:      $($cmd.ModuleName)" }}
"Visibility:  $($cmd.Visibility)"
""
"Parameters exposed by this proxy:"
foreach ($p in ($cmd.Parameters.Values | Sort-Object Name)) {{
    "  $($p.Name)  [$($p.ParameterType.FullName)]"
    foreach ($a in $p.Attributes) {{
        $tn = $a.PSObject.TypeNames[0]
        $short = $tn.Substring($tn.LastIndexOf('.') + 1)
        if ($short -eq 'ParameterAttribute') {{ continue }}
        $detail = ''
        if ($a.ValidValues) {{
            $detail = "ValidValues={{$($a.ValidValues -join ', ')}}"
        }} elseif ($a.RegexPattern) {{
            $detail = "Pattern=$($a.RegexPattern)"
        }} elseif ($a.MinLength -ne $null) {{
            $detail = "Length=$($a.MinLength)..$($a.MaxLength)"
        }} elseif ($a.MinRange -ne $null) {{
            $detail = "Range=$($a.MinRange)..$($a.MaxRange)"
        }} elseif ($a.AliasNames) {{
            $detail = "Aliases=$($a.AliasNames -join ',')"
        }}
        if ($detail) {{ "    [$short] $detail" }} else {{ "    [$short]" }}
    }}
}}
"""


def _mapping_values(value: object) -> list[object]:
    if isinstance(value, Mapping):
        return list(value.values())
    adapted = ps_property(value, "adapted_properties")
    if isinstance(adapted, Mapping):
        return list(adapted.values())
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _attribute_name(attribute: object) -> str:
    types = ps_property(attribute, "types", [])
    if isinstance(types, Sequence) and types:
        return str(types[0]).rsplit(".", 1)[-1]
    return type(attribute).__name__


def _render_structured_proxy(command: object) -> list[str]:
    name = str(ps_property(command, "Name", command))
    command_type = str(ps_property(command, "CommandType", "?"))
    module = str(ps_property(command, "ModuleName", ""))
    visibility = str(ps_property(command, "Visibility", ""))
    lines = [f"Cmdlet:      {name}", f"CommandType: {command_type}"]
    if module:
        lines.append(f"Module:      {module}")
    if visibility:
        lines.append(f"Visibility:  {visibility}")
    lines.extend(["", "Parameters exposed by this proxy:"])

    parameters = ps_property(command, "Parameters", {})
    values = _mapping_values(parameters)
    values.sort(key=lambda value: str(ps_property(value, "Name", "")))
    for parameter in values:
        parameter_name = str(ps_property(parameter, "Name", "<unknown>"))
        parameter_type = ps_property(parameter, "ParameterType", "<unknown>")
        type_name = str(ps_property(parameter_type, "FullName", parameter_type))
        lines.append(f"  {parameter_name}  [{type_name}]")
        for attribute in _mapping_values(ps_property(parameter, "Attributes", [])):
            attribute_name = _attribute_name(attribute)
            if attribute_name == "ParameterAttribute":
                continue
            detail = ""
            valid_values = ps_property(attribute, "ValidValues")
            pattern = ps_property(attribute, "RegexPattern")
            aliases = ps_property(attribute, "AliasNames")
            minimum_length = ps_property(attribute, "MinLength")
            minimum_range = ps_property(attribute, "MinRange")
            if valid_values:
                detail = "ValidValues={" + ", ".join(map(str, valid_values)) + "}"
            elif pattern:
                detail = f"Pattern={pattern}"
            elif minimum_length is not None:
                detail = f"Length={minimum_length}..{ps_property(attribute, 'MaxLength', '?')}"
            elif minimum_range is not None:
                detail = f"Range={minimum_range}..{ps_property(attribute, 'MaxRange', '?')}"
            elif aliases:
                detail = "Aliases=" + ",".join(map(str, aliases))
            suffix = f" {detail}" if detail else ""
            lines.append(f"    [{attribute_name}]{suffix}")
    if not values:
        lines.append("  <parameter metadata was not serialized by this endpoint>")
    return lines


def run_proxy(args: argparse.Namespace) -> int:
    logger = Logger(args.log)
    with open_pool(args) as pool:
        if resolve_backend(args, pool, logger) == "structured":
            rc, output = invoke_structured(
                pool,
                [
                    CommandSpec(
                        "Get-Command",
                        parameters=(
                            ("Name", args.name),
                            ("ErrorAction", "SilentlyContinue"),
                        ),
                    )
                ],
                logger=logger,
                display=False,
            )
            if rc:
                return rc
            if not output:
                emit(f"Command not found: {args.name}", logger=logger)
                return 1
            for line in _render_structured_proxy(output[0]):
                emit(line, logger=logger)
            return 0
        rc, _ = invoke_remote(
            args,
            pool,
            make_proxy_script(args.name),
            logger=logger,
        )
        return rc


def make_definition_script(name: str) -> str:
    return rf"""
$ErrorActionPreference = 'Stop'
$name = {ps_quote(name)}
$cmd = Get-Command -Name $name -ErrorAction SilentlyContinue
if (-not $cmd) {{
    "Command not found: $name"
    return
}}
"Name:        $($cmd.Name)"
"CommandType: $($cmd.CommandType)"
if ($cmd.Source)     {{ "Source:      $($cmd.Source)" }}
if ($cmd.ModuleName) {{ "Module:      $($cmd.ModuleName)" }}
"Visibility:  $($cmd.Visibility)"
"--- Definition ---"
$cmd.Definition
if ($cmd.Parameters -and $cmd.Parameters.Count -gt 0) {{
    "--- Parameters ---"
    foreach ($p in $cmd.Parameters.Values) {{
        $type = if ($p.ParameterType) {{ $p.ParameterType.FullName }} else {{ '<unknown>' }}
        "$($p.Name)  [$type]"
    }}
}}
"""


def run_definition(args: argparse.Namespace) -> int:
    logger = Logger(args.log)
    with open_pool(args) as pool:
        if resolve_backend(args, pool, logger) == "structured":
            rc, output = invoke_structured(
                pool,
                [
                    CommandSpec(
                        "Get-Command",
                        parameters=(
                            ("Name", args.name),
                            ("ErrorAction", "SilentlyContinue"),
                        ),
                    )
                ],
                logger=logger,
                display=False,
            )
            if rc:
                return rc
            if not output:
                emit(f"Command not found: {args.name}", logger=logger)
                return 1
            command = output[0]
            for label, property_name in (
                ("Name", "Name"),
                ("CommandType", "CommandType"),
                ("Source", "Source"),
                ("Module", "ModuleName"),
                ("Visibility", "Visibility"),
            ):
                value = ps_property(command, property_name)
                if value not in (None, ""):
                    emit(f"{label + ':':<12}{value}", logger=logger)
            definition = ps_property(command, "Definition")
            if definition:
                emit("--- Definition ---", logger=logger)
                emit(str(definition), logger=logger)
            parameters = _mapping_values(ps_property(command, "Parameters", {}))
            if parameters:
                emit("--- Parameters ---", logger=logger)
                for parameter in parameters:
                    parameter_name = ps_property(parameter, "Name", "<unknown>")
                    parameter_type = ps_property(parameter, "ParameterType", "<unknown>")
                    type_name = ps_property(parameter_type, "FullName", parameter_type)
                    emit(f"{parameter_name}  [{type_name}]", logger=logger)
            return 0
        script = make_definition_script(args.name)
        rc, _ = invoke_remote(args, pool, script, logger=logger)
        return rc


SHELL_BUILTINS = (
    ":help",
    ":quit",
    ":exit",
    ":q",
    ":retry",
    ":cmdlet",
    ":load",
    ":upload",
    ":download",
    ":commands",
    ":history",
    ":info",
    ":def",
    ":proxy",
)


def load_cmdlet_cache(args: argparse.Namespace, pool, logger: Logger) -> list[str]:
    # JEA proxies frequently strip Select-Object -ExpandProperty (the
    # parameter is rejected as "not found"). Property access on the array
    # gets us the same names through paths every JEA endpoint allows.
    if resolve_backend(args, pool, logger) == "structured":
        rc, output = invoke_structured(
            pool,
            [CommandSpec("Get-Command")],
            logger=logger,
            display=False,
            show_streams=False,
        )
        if rc:
            return []
        return [
            str(ps_property(item, "Name", item)).strip()
            for item in output
            if str(ps_property(item, "Name", item)).strip()
        ]
    rc, lines = invoke_remote(
        args,
        pool,
        "(Get-Command).Name",
        logger=logger,
        display=False,
        show_streams=False,
    )
    if rc:
        return []
    return [line.strip() for line in lines if line.strip()]


def install_shell_completer(cmdlets: list[str]) -> None:
    try:
        import readline  # Optional and missing on bare Windows.
    except ImportError:
        return

    candidates = sorted(set(SHELL_BUILTINS) | set(cmdlets))

    def completer(text, state):
        try:
            buffer = readline.get_line_buffer()
            begidx = readline.get_begidx()
            # Only complete the first token. Past that we don't know what's a
            # parameter vs a value, so silence is better than wrong guesses.
            if buffer[:begidx].strip():
                return None
            text_lower = text.lower()
            matches = [c for c in candidates if c.lower().startswith(text_lower)]
            return matches[state] if state < len(matches) else None
        except Exception:
            return None

    readline.set_completer(completer)
    readline.set_completer_delims(" \t\n")
    readline.parse_and_bind("tab: complete")
    readline.parse_and_bind("set completion-ignore-case on")


def shell_help() -> str:
    return """Commands:
  :help                         show this help
  :quit                         exit
  :retry                        explicitly resubmit the last command whose result was lost
  :cmdlet <name> [Name=value]   source-free command for NoLanguage endpoints
  :load <local.ps1>             run a local PowerShell script file
  :upload <local> <remote>      upload a file
  :download <remote> <local>    download a file
  :commands [--all] [pattern]   list visible commands (default: Function+Cmdlet only)
  :def <cmdlet>                 print the cmdlet's Definition (parameter sets)
  :proxy <cmdlet>               print parameters the JEA proxy exposes + their validators
  :history [remote-path]        print PSReadLine history
  :info                         show session identity and language mode
Any other line is sent as PowerShell source when the script backend is active.
After recovery, a previous command may have executed remotely; it is never
replayed automatically unless --retry-unsafe was explicitly selected."""


def split_shell_args(line: str) -> list[str]:
    # Small parser for paths with spaces. It handles single and double quotes.
    import shlex

    parts = shlex.split(line, posix=False)
    cleaned = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in ("'", '"'):
            cleaned.append(part[1:-1])
        else:
            cleaned.append(part)
    return cleaned


def dispatch_shell_line(
    args: argparse.Namespace,
    pool,
    line: str,
    logger: Logger,
) -> int:
    # First token decides whether this is a local builtin or remote PowerShell.
    # Anything starting with ':' must dispatch as a builtin (or a usage error)
    # - falling back to PSRP on `:foo` produces a confusing
    # "term ':foo' is not recognized" error from the JEA endpoint.
    head = line.split(maxsplit=1)
    verb = head[0]
    rest = head[1] if len(head) > 1 else ""
    backend = resolve_backend(args, pool, logger)

    if not verb.startswith(":"):
        if backend == "structured":
            emit(
                "PowerShell source is disabled for this NoLanguage session. "
                "Use :cmdlet, or the non-interactive cmdlet/pipeline subcommands.",
                stderr=True,
                logger=logger,
            )
            return 1
        rc, _ = invoke_remote(args, pool, line, logger=logger, raise_session=True)
        return rc

    if verb == ":help":
        emit(shell_help(), logger=logger)
        return 0

    if verb == ":retry":
        emit(
            ":retry is only available after the shell reports an uncertain command",
            stderr=True,
            logger=logger,
        )
        return 1

    if verb == ":cmdlet":
        parts = split_shell_args(rest)
        if not parts:
            emit(
                "usage: :cmdlet <name> [Name=value] [-Switch] [argument]",
                stderr=True,
                logger=logger,
            )
            return 1
        parameters: list[tuple[str, Any]] = []
        arguments: list[str] = []
        for token in parts[1:]:
            if "=" in token:
                try:
                    name, value = _name_value(token, option=":cmdlet")
                except SystemExit as exc:
                    emit(str(exc), stderr=True, logger=logger)
                    return 1
                parameters.append((name, value))
            elif token.startswith("-") and len(token) > 1:
                parameters.append((token[1:], None))
            else:
                arguments.append(token)
        rc, _ = invoke_structured(
            pool,
            [CommandSpec(parts[0], tuple(parameters), tuple(arguments))],
            logger=logger,
            raise_session=True,
        )
        return rc

    if verb == ":info":
        if backend == "structured":
            emit("ExecutionBackend:    structured", logger=logger)
            emit(
                "Identity/PSVersion expressions are unavailable in NoLanguage.",
                logger=logger,
            )
            return 0
        rc, _ = invoke_remote(
            args,
            pool,
            INFO_SCRIPT,
            logger=logger,
            raise_session=True,
        )
        return rc

    if verb == ":commands":
        pattern = "*"
        command_types: tuple[str, str] | None = ("Function", "Cmdlet")
        if rest.strip():
            parts = split_shell_args(rest)
            if "--all" in parts:
                command_types = None
                parts = [p for p in parts if p != "--all"]
            if parts:
                pattern = parts[0]
        if backend == "structured":
            structured_parameters: list[tuple[str, Any]] = [
                ("Name", pattern),
                ("ErrorAction", "SilentlyContinue"),
            ]
            if command_types:
                structured_parameters.append(("CommandType", list(command_types)))
            rc, output = invoke_structured(
                pool,
                [CommandSpec("Get-Command", tuple(structured_parameters))],
                logger=logger,
                display=False,
                raise_session=True,
            )
            for row in _format_command_rows(output):
                emit(row, logger=logger)
            return rc
        rc, _ = invoke_remote(
            args,
            pool,
            make_commands_script(pattern, command_types=command_types),
            logger=logger,
            raise_session=True,
        )
        return rc

    if verb == ":def":
        if not rest.strip():
            emit("usage: :def <cmdlet>", stderr=True, logger=logger)
            return 1
        parts = split_shell_args(rest)
        if backend == "structured":
            rc, output = invoke_structured(
                pool,
                [CommandSpec("Get-Command", parameters=(("Name", parts[0]),))],
                logger=logger,
                display=False,
                raise_session=True,
            )
            if output:
                definition = ps_property(output[0], "Definition")
                emit(str(definition or output[0]), logger=logger)
            return rc
        rc, _ = invoke_remote(
            args,
            pool,
            make_definition_script(parts[0]),
            logger=logger,
            raise_session=True,
        )
        return rc

    if verb == ":proxy":
        if not rest.strip():
            emit("usage: :proxy <cmdlet>", stderr=True, logger=logger)
            return 1
        parts = split_shell_args(rest)
        if backend == "structured":
            rc, output = invoke_structured(
                pool,
                [CommandSpec("Get-Command", parameters=(("Name", parts[0]),))],
                logger=logger,
                display=False,
                raise_session=True,
            )
            if output:
                for rendered in _render_structured_proxy(output[0]):
                    emit(rendered, logger=logger)
            return rc
        rc, _ = invoke_remote(
            args,
            pool,
            make_proxy_script(parts[0]),
            logger=logger,
            raise_session=True,
        )
        return rc

    if verb == ":history":
        remote_path = None
        if rest.strip():
            parts = split_shell_args(rest)
            if parts:
                remote_path = parts[0]
        if backend == "structured":
            if not remote_path:
                emit(
                    "usage in NoLanguage: :history <remote-path>",
                    stderr=True,
                    logger=logger,
                )
                return 1
            rc, _ = invoke_structured(
                pool,
                [
                    CommandSpec(
                        "Get-Content",
                        parameters=(
                            ("LiteralPath", remote_path),
                            ("ErrorAction", "Stop"),
                        ),
                    )
                ],
                logger=logger,
                raise_session=True,
            )
            return rc
        rc, _ = invoke_remote(
            args,
            pool,
            make_history_script(remote_path, "auto"),
            logger=logger,
            raise_session=True,
        )
        return rc

    if verb == ":load":
        if not rest.strip():
            emit("usage: :load <local.ps1>", stderr=True, logger=logger)
            return 1
        parts = split_shell_args(rest)
        script_path = Path(parts[0]).expanduser()
        if not script_path.is_file():
            emit(f"local script not found: {script_path}", stderr=True, logger=logger)
            return 1
        script = script_path.read_text(encoding=args.encoding, errors="replace")
        if backend == "structured":
            emit(
                ":load sends source and is unavailable in NoLanguage; use pipeline",
                stderr=True,
                logger=logger,
            )
            return 1
        rc, _ = invoke_remote(args, pool, script, logger=logger, raise_session=True)
        return rc

    if verb == ":upload":
        parts = split_shell_args(rest)
        if len(parts) != 2:
            emit("usage: :upload <local> <remote>", stderr=True, logger=logger)
            return 1
        old_local, old_remote = args.local_path, args.remote_path
        args.local_path, args.remote_path = parts[0], parts[1]
        try:
            return run_upload_with_pool(pool, args, logger)
        finally:
            args.local_path, args.remote_path = old_local, old_remote

    if verb == ":download":
        parts = split_shell_args(rest)
        if len(parts) != 2:
            emit("usage: :download <remote> <local>", stderr=True, logger=logger)
            return 1
        old_remote, old_local = args.remote_path, args.local_path
        args.remote_path, args.local_path = parts[0], parts[1]
        try:
            return run_download_with_pool(pool, args, logger)
        finally:
            args.remote_path, args.local_path = old_remote, old_local

    emit(
        f"unknown shell command: {verb}  (type :help to list builtins)",
        stderr=True,
        logger=logger,
    )
    return 1


RECONNECT_MAX_ATTEMPTS = 3


def run_shell(args: argparse.Namespace) -> int:
    logger = Logger(args.log)
    rc_total = 0
    pending_line: str | None = None
    uncertain_line: str | None = None
    announce_recovery = False
    first_connect = True
    reconnect_attempts = 0

    who = (args.username or "kerberos").lower()
    config_label = args.configuration_name or "default"
    prompt_text = f"[{who}@{args.host} {config_label}] PS> "

    while True:
        try:
            with open_pool(args) as pool:
                reconnect_attempts = 0  # reached the with body - pool is live
                if getattr(args, "backend", "script") == "auto":
                    for attribute in ("_resolved_backend", "_remote_language_mode"):
                        if hasattr(args, attribute):
                            delattr(args, attribute)
                cmdlets = load_cmdlet_cache(args, pool, logger)
                install_shell_completer(cmdlets)
                if first_connect:
                    emit(
                        f"Connected shell ({len(cmdlets)} cmdlets cached). "
                        "Type :help for local commands, :quit to exit.",
                        logger=logger,
                    )
                    first_connect = False
                else:
                    emit(f"Reconnected ({len(cmdlets)} cmdlets cached).", logger=logger)
                if announce_recovery:
                    if pending_line is not None:
                        emit(
                            "Session recovered. --retry-unsafe is resubmitting "
                            "the uncertain command (at-least-once semantics).",
                            stderr=True,
                            logger=logger,
                        )
                    else:
                        emit(
                            "Session recovered. The previous command may have "
                            "executed remotely. Use :retry to submit it again.",
                            stderr=True,
                            logger=logger,
                        )
                    announce_recovery = False

                while True:
                    if pending_line is not None:
                        line = pending_line
                        pending_line = None
                        is_auto_retry = True
                        is_explicit_retry = False
                        uncertain_line = None
                    else:
                        try:
                            line = input(prompt_text)
                        except EOFError:
                            print()
                            return rc_total
                        except KeyboardInterrupt:
                            print()
                            continue
                        is_auto_retry = False
                        is_explicit_retry = False

                    line = line.strip()
                    if not line:
                        continue
                    if line in (":q", ":quit", ":exit"):
                        return rc_total
                    if line == ":retry":
                        if uncertain_line is None:
                            emit(
                                "No uncertain command is available to retry.",
                                stderr=True,
                                logger=logger,
                            )
                            rc_total = rc_total or 1
                            continue
                        line = uncertain_line
                        uncertain_line = None
                        is_explicit_retry = True
                        emit(
                            f"[session] explicitly retrying: {line}",
                            stderr=True,
                            logger=logger,
                        )

                    try:
                        rc = dispatch_shell_line(args, pool, line, logger)
                    except SessionExpired as exc:
                        uncertain_line = line
                        emit(
                            f"[session] {exc} - reconnecting; result is uncertain",
                            stderr=True,
                            logger=logger,
                        )
                        if (
                            getattr(args, "retry_unsafe", False)
                            and not is_auto_retry
                            and not is_explicit_retry
                        ):
                            pending_line = line
                        elif is_auto_retry:
                            emit(
                                "[session] unsafe automatic retry also lost its "
                                "response; refusing to replay it again",
                                stderr=True,
                                logger=logger,
                            )
                        announce_recovery = True
                        break  # leave inner loop, outer reopens the pool
                    except Exception as exc:
                        emit(f"[local-error] {exc}", stderr=True, logger=logger)
                        rc = 1
                    rc_total = rc_total or rc
        except KeyboardInterrupt:
            print()
            return rc_total
        except SystemExit:
            raise
        except Exception as exc:
            # The first connect should fail loud - config issue, bad creds, etc.
            # Reconnect attempts deserve a brief retry: this JEA endpoint
            # routinely 400s the very first reopen after a pipeline closes.
            if first_connect:
                emit(f"[connect-error] {exc}", stderr=True, logger=logger)
                return rc_total or 1
            reconnect_attempts += 1
            if reconnect_attempts >= RECONNECT_MAX_ATTEMPTS:
                emit(
                    f"[connect-error] {exc} (gave up after {reconnect_attempts} attempts)",
                    stderr=True,
                    logger=logger,
                )
                return rc_total or 1
            backoff = float(reconnect_attempts)
            emit(
                f"[connect-retry] {exc} - "
                f"retrying in {backoff:.0f}s "
                f"({reconnect_attempts}/{RECONNECT_MAX_ATTEMPTS})",
                stderr=True,
                logger=logger,
            )
            time.sleep(backoff)
            continue


def run_upload_with_pool(pool, args: argparse.Namespace, logger: Logger) -> int:
    return _do_upload(pool, args, logger)


def run_download_with_pool(pool, args: argparse.Namespace, logger: Logger) -> int:
    return _do_download(pool, args, logger)


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("host", help="WinRM host, e.g. dc.example.local")
    parser.add_argument("-u", "--username", help="User/UPN, e.g. svc@EXAMPLE.LOCAL")
    parser.add_argument("-p", "--password", help="Password. Defaults to an empty password.")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for the password.")
    parser.add_argument("--password-env", help="Read password from an environment variable.")
    parser.add_argument(
        "-H",
        "--hash",
        help="NTLM hash (pass-the-hash). Forces --auth ntlm.",
    )
    parser.add_argument(
        "-a",
        "--auth",
        choices=AUTH_CHOICES,
        default="kerberos",
        help="pypsrp auth provider. Default: kerberos.",
    )
    parser.add_argument(
        "-c",
        "--configuration-name",
        default="restricted",
        help="PowerShell session configuration/JEA endpoint. Default: restricted.",
    )
    parser.add_argument(
        "--backend",
        choices=BACKEND_CHOICES,
        default="auto",
        help=(
            "Execution backend. auto probes language mode; script is richest "
            "for Full/ConstrainedLanguage; structured uses source-free PSRP "
            "cmdlet pipelines for NoLanguage. Default: auto."
        ),
    )
    parser.add_argument(
        "--wrap",
        choices=WRAP_CHOICES,
        default=DEFAULT_WRAPPER,
        help="Remote execution wrapper. Default: ampersand, which sends & { ... }.",
    )
    parser.add_argument(
        "--no-wrap",
        dest="wrap",
        action="store_const",
        const="none",
        help="Alias for --wrap none.",
    )
    parser.add_argument("--ccache", help="Set KRB5CCNAME before connecting.")
    parser.add_argument("--keytab", help="Set KRB5_CLIENT_KTNAME before connecting.")
    parser.add_argument("--krb5-config", help="Set KRB5_CONFIG before connecting.")
    parser.add_argument("--ssl", dest="ssl", action="store_true", help="Use HTTPS/5986.")
    parser.add_argument("--no-ssl", dest="ssl", action="store_false", help="Use HTTP/5985.")
    parser.set_defaults(ssl=False)
    parser.add_argument("--port", type=int, help="Override WinRM port.")
    parser.add_argument("--path", default="wsman", help="WinRM URL path. Default: wsman.")
    parser.add_argument(
        "--cert-validation",
        action="store_true",
        help="Validate TLS certificates. Default is disabled for lab ergonomics.",
    )
    parser.add_argument(
        "--encryption",
        choices=("auto", "always", "never"),
        default="auto",
        help="Message encryption mode. Default: auto.",
    )
    parser.add_argument(
        "--delegate",
        action="store_true",
        help="Enable Kerberos/negotiate delegation if supported.",
    )
    parser.add_argument(
        "--hostname-override", help="Hostname override for negotiate auth if supported."
    )
    parser.add_argument("--negotiate-service", help="SPN service name override if supported.")
    parser.add_argument(
        "--certificate-pem",
        help="Client certificate PEM for certificate auth if supported.",
    )
    parser.add_argument(
        "--certificate-key-pem",
        help="Client certificate key PEM for certificate auth if supported.",
    )
    parser.add_argument(
        "--connection-timeout", type=int, default=30, help="Connection timeout seconds."
    )
    parser.add_argument(
        "--operation-timeout",
        type=int,
        default=20,
        help="WSMan operation timeout seconds.",
    )
    parser.add_argument("--read-timeout", type=int, help="Read timeout seconds if supported.")
    parser.add_argument(
        "--reconnection-retries",
        type=int,
        default=0,
        help="Reconnect retries if supported.",
    )
    parser.add_argument(
        "--max-envelope-size", type=int, default=153600, help="WSMan envelope size."
    )
    parser.add_argument("--locale", default="en-US", help="WSMan locale.")
    parser.add_argument("--data-locale", help="WSMan data locale.")
    parser.add_argument("--log", help="Append commands and output to a local log file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose local output.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "A pypsrp assessment client for ConstrainedLanguage and NoLanguage JEA endpoints."
        )
    )
    parser.add_argument("--version", action="version", version=version_string())
    add_connection_args(parser)
    sub = parser.add_subparsers(dest="mode", required=True)

    run_p = sub.add_parser("run", aliases=("exec", "x"), help="Run a PowerShell command.")
    run_p.add_argument("--json", action="store_true", help="Pipe output through ConvertTo-Json.")
    run_p.add_argument("--json-depth", type=int, default=4, help="ConvertTo-Json depth.")
    run_p.add_argument("--encoding", default="utf-8", help="Command-file encoding.")
    command_sources = run_p.add_mutually_exclusive_group()
    command_sources.add_argument(
        "--command-file",
        help="Read the complete PowerShell expression from a file.",
    )
    command_sources.add_argument(
        "--stdin",
        dest="command_stdin",
        action="store_true",
        help="Read the complete PowerShell expression from stdin.",
    )
    run_p.add_argument("command", nargs=argparse.REMAINDER)
    run_p.set_defaults(func=run_command)

    cmdlet_p = sub.add_parser(
        "cmdlet",
        help="Invoke one command through source-free PSRP (NoLanguage-safe).",
    )
    cmdlet_p.add_argument("name", help="Cmdlet/function name exposed by the endpoint.")
    cmdlet_p.add_argument(
        "--parameter",
        dest="parameters",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Add a string-valued named parameter; repeatable.",
    )
    cmdlet_p.add_argument(
        "--parameter-json",
        dest="parameters_json",
        action="append",
        default=[],
        metavar="NAME=JSON",
        help="Add a typed JSON parameter value; repeatable.",
    )
    cmdlet_p.add_argument(
        "--switch",
        dest="switches",
        action="append",
        default=[],
        metavar="NAME",
        help="Add a switch parameter; repeatable.",
    )
    cmdlet_p.add_argument(
        "--argument",
        dest="arguments",
        action="append",
        default=[],
        metavar="VALUE",
        help="Add a string positional argument; repeatable.",
    )
    cmdlet_p.add_argument(
        "--argument-json",
        dest="arguments_json",
        action="append",
        default=[],
        metavar="JSON",
        help="Add a typed JSON positional argument; repeatable.",
    )
    cmdlet_p.set_defaults(func=run_cmdlet)

    pipeline_p = sub.add_parser(
        "pipeline",
        help="Invoke a validated JSON PSRP pipeline without source text.",
    )
    pipeline_p.add_argument(
        "--encoding",
        default="utf-8",
        help="Pipeline JSON encoding. Default: utf-8.",
    )
    pipeline_p.add_argument("pipeline_path", help="JSON path, or - for stdin.")
    pipeline_p.set_defaults(func=run_pipeline)

    script_p = sub.add_parser("script", help="Run a local .ps1 file.")
    script_p.add_argument("--encoding", default="utf-8", help="Local script encoding.")
    script_p.add_argument("--json", action="store_true", help="Pipe output through ConvertTo-Json.")
    script_p.add_argument("--json-depth", type=int, default=4, help="ConvertTo-Json depth.")
    script_p.add_argument("script_path")
    script_p.set_defaults(func=run_script)

    batch_p = sub.add_parser("batch", help="Run one command per line from a local file.")
    batch_p.add_argument("--encoding", default="utf-8", help="Local batch file encoding.")
    batch_p.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop after the first failing command.",
    )
    batch_p.add_argument("batch_path")
    batch_p.set_defaults(func=run_batch)

    shell_p = sub.add_parser("shell", help="Open a small interactive loop.")
    shell_p.add_argument("--encoding", default="utf-8", help="Encoding for :load.")
    shell_p.add_argument(
        "--chunk-size",
        type=int,
        default=UPLOAD_DEFAULT_CHUNK,
        help=(
            "Upload chunk size in raw bytes (kept small to fit the WSMan envelope; "
            "the [byte[]]@(...) literal expands to roughly 3.5x)."
        ),
    )
    shell_p.add_argument(
        "--chunk-bytes",
        type=int,
        default=DOWNLOAD_DEFAULT_CHUNK_BYTES,
        help="Download chunk size in bytes (Get-Content -ReadCount).",
    )
    shell_p.add_argument(
        "--retry-unsafe",
        action="store_true",
        help=(
            "Automatically replay once after an uncertain transport failure "
            "(at-least-once semantics). Default: never replay."
        ),
    )
    shell_p.add_argument(
        "--verify",
        choices=TRANSFER_VERIFY_CHOICES,
        default="size",
        help="Verification for :upload/:download. Default: size.",
    )
    shell_p.set_defaults(func=run_shell, local_path=None, remote_path=None, progress=False)

    info_p = sub.add_parser("info", help="Show identity, PS version, and language mode.")
    info_p.set_defaults(func=run_info)

    commands_p = sub.add_parser(
        "commands",
        help="List commands visible inside the endpoint (default: Function+Cmdlet).",
    )
    commands_p.add_argument("pattern", nargs="?", default="*", help="Get-Command pattern.")
    commands_p.add_argument(
        "--all", action="store_true", help="Include Aliases and Applications too."
    )
    commands_p.set_defaults(func=run_commands)

    def_p = sub.add_parser(
        "definition",
        aliases=("def",),
        help="Print the cmdlet's Definition (parameter sets).",
    )
    def_p.add_argument("name", help="Cmdlet or function name visible inside the endpoint.")
    def_p.set_defaults(func=run_definition)

    proxy_p = sub.add_parser(
        "proxy",
        help="Print parameters the JEA proxy exposes + their validators (the escape-hunting view).",
    )
    proxy_p.add_argument("name", help="Cmdlet or function name visible inside the endpoint.")
    proxy_p.set_defaults(func=run_proxy)

    history_p = sub.add_parser("history", help="Read PSReadLine history for the connected profile.")
    history_p.add_argument("--remote-path", help="Override remote ConsoleHost_history.txt path.")
    history_p.add_argument(
        "--method",
        choices=HISTORY_METHODS,
        default="auto",
        help=(
            "Read with Get-Content, force FullLanguage .NET ReadAllLines, or "
            "try the cmdlet then .NET fallback. Default: auto."
        ),
    )
    history_p.set_defaults(func=run_history)

    upload_p = sub.add_parser("upload", help="Upload a local file to a remote path.")
    upload_p.add_argument(
        "--chunk-size",
        type=int,
        default=UPLOAD_DEFAULT_CHUNK,
        help=(
            "Upload chunk size in raw bytes (each chunk turns into a "
            "[byte[]]@(d1,d2,...) literal, roughly 3.5x the byte count)."
        ),
    )
    upload_p.add_argument("--progress", action="store_true", help="Print chunk progress.")
    upload_p.add_argument(
        "--verify",
        choices=TRANSFER_VERIFY_CHOICES,
        default="size",
        help="Verify staged content before replacement. Default: size.",
    )
    upload_p.add_argument("local_path")
    upload_p.add_argument("remote_path")
    upload_p.set_defaults(func=run_upload)

    download_p = sub.add_parser("download", help="Download a remote file to a local path.")
    download_p.add_argument(
        "--chunk-bytes",
        type=int,
        default=DOWNLOAD_DEFAULT_CHUNK_BYTES,
        help="Download chunk size in bytes (Get-Content -ReadCount).",
    )
    download_p.add_argument(
        "--verify",
        choices=TRANSFER_VERIFY_CHOICES,
        default="size",
        help="Verify downloaded content before local replacement. Default: size.",
    )
    download_p.add_argument("remote_path")
    download_p.add_argument("local_path")
    download_p.set_defaults(func=run_download)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "hash", None):
        if args.auth not in (None, "ntlm"):
            eprint(f"[hash] forcing --auth ntlm (was {args.auth})")
        args.auth = "ntlm"
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        eprint("Interrupted.")
        return 130
    except SystemExit:
        raise
    except Exception as exc:
        eprint(f"Fatal: {exc}")
        if getattr(args, "verbose", False):
            raise
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
