#!/usr/bin/env python3
"""
jea_plus.py - small PSRP/WinRM client for JEA endpoints.

This is intentionally a wrapper around pypsrp. It gives you a friendlier CLI
for Kerberos ccache/keytab auth, restricted endpoint names, quick enumeration,
simple file movement, and an interactive loop.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import inspect
import os
import sys
import time
from pathlib import Path
from typing import Iterable, Optional


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
    def __init__(self, path: Optional[str]) -> None:
        self.path = Path(path).expanduser() if path else None

    def write(self, line: str) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", errors="replace") as handle:
            handle.write(line)
            if not line.endswith("\n"):
                handle.write("\n")


def emit(line: str, *, stderr: bool = False, logger: Optional[Logger] = None) -> None:
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


def supported_kwargs(callable_obj, kwargs: dict) -> tuple[dict, list[str]]:
    """Filter kwargs against the installed pypsrp version."""
    try:
        signature = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return kwargs, []

    accepts_any = any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    )
    if accepts_any:
        return kwargs, []

    supported = {}
    ignored = []
    for key, value in kwargs.items():
        if value is None:
            continue
        if key in signature.parameters:
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
            eprint(
                f"[kerberos] dropping --username '{username}' "
                "to honour KRB5CCNAME / keytab"
            )
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

    extras = {
        "negotiate_delegate": args.delegate,
        "negotiate_hostname_override": args.hostname_override,
        "negotiate_service": args.negotiate_service,
        "kerberos_delegation": args.delegate,
        "certificate_pem": args.certificate_pem,
        "certificate_key_pem": args.certificate_key_pem,
    }
    kwargs.update(extras)
    filtered, ignored = supported_kwargs(WSMan, kwargs)

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


def invoke_ps(
    pool,
    script: str,
    *,
    logger: Optional[Logger] = None,
    display: bool = True,
    show_streams: bool = True,
    wrapper: str = "none",
    raise_session: bool = False,
    max_envelope_size: Optional[int] = None,
) -> tuple[int, list[str]]:
    _, _, PowerShell = load_pypsrp()
    script = apply_execution_wrapper(script, wrapper)

    # Pre-check: PSRP/SOAP wrapping plus the WSMan service's own per-message
    # ceiling means the practical script ceiling is well under
    # --max-envelope-size. Empirically against the live JEA endpoint,
    # scripts above ~30% of the configured envelope tear down the WinRM
    # shell (WSManFault Code 1726, then "shell with shellid not found").
    # Catch it client-side so we don't have to reconnect to recover.
    if max_envelope_size and len(script) > int(max_envelope_size * 0.30):
        msg = (
            f"script size {len(script)} chars exceeds the WSMan envelope "
            f"budget (--max-envelope-size {max_envelope_size}); raise the "
            "envelope or split into smaller calls"
        )
        emit(f"[size-error] {msg}", stderr=True, logger=logger)
        return 1, []

    ps = PowerShell(pool)
    ps.add_script(script)

    if logger:
        logger.write("CMD " + script.strip().replace("\n", "\\n"))

    try:
        output = ps.invoke()
    except Exception as exc:  # pypsrp exposes several transport/runtime exceptions.
        if raise_session and is_session_error(exc):
            raise SessionExpired(str(exc)) from exc
        emit(f"[invoke-error] {exc}", stderr=True, logger=logger)
        return 1, []

    lines = [str(item) for item in output if item is not None]
    if display:
        for line in lines:
            emit(line, logger=logger)

    if show_streams:
        for name, item in stream_items(ps):
            text = str(item)
            emit(f"[{name}] {text}", stderr=(name == "error"), logger=logger)

    return (1 if getattr(ps, "had_errors", False) else 0), lines


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
        "$ErrorActionPreference = 'Stop'\n"
        f"& {{\n{script}\n}} | ConvertTo-Json -Depth {int(depth)}"
    )


def command_from_remainder(parts: list[str]) -> str:
    if parts and parts[0] == "--":
        parts = parts[1:]
    return " ".join(parts).strip()


def run_command(args: argparse.Namespace) -> int:
    script = command_from_remainder(args.command)
    if not script:
        raise SystemExit("run needs a PowerShell command.")
    if args.json:
        script = wrap_json(script, args.json_depth)
    with open_pool(args) as pool:
        rc, _ = invoke_remote(args, pool, script, logger=Logger(args.log))
        return rc


def run_script(args: argparse.Namespace) -> int:
    path = Path(args.script_path).expanduser()
    if not path.is_file():
        raise SystemExit(f"Script not found: {path}")
    script = path.read_text(encoding=args.encoding, errors="replace")
    if args.json:
        script = wrap_json(script, args.json_depth)
    with open_pool(args) as pool:
        rc, _ = invoke_remote(args, pool, script, logger=Logger(args.log))
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


def make_commands_script(pattern: str, command_types: Optional[tuple] = ("Function", "Cmdlet")) -> str:
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
    with open_pool(args) as pool:
        rc, _ = invoke_remote(args, pool, INFO_SCRIPT, logger=Logger(args.log))
        return rc


def run_commands(args: argparse.Namespace) -> int:
    pattern = args.pattern or "*"
    types = None if getattr(args, "all", False) else ("Function", "Cmdlet")
    with open_pool(args) as pool:
        rc, _ = invoke_remote(
            args, pool, make_commands_script(pattern, command_types=types),
            logger=Logger(args.log),
        )
        return rc


def make_history_script(remote_path: Optional[str], method: str = "auto") -> str:
    # The earlier implementation kept a [System.IO.File]::ReadAllLines
    # fallback for "method=dotnet". Useless under ConstrainedLanguage
    # (every JEA endpoint), and on FullLanguage Get-Content already works,
    # so the fallback was dead code in both real cases. Cmdlet path only.
    # `method` kept on the CLI for back-compat; it's now a no-op.
    del method  # noqa: F841
    if remote_path:
        path_expr = ps_quote(remote_path)
    else:
        path_expr = "Join-Path $env:APPDATA 'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'"

    return rf"""
$ErrorActionPreference = 'Continue'
$h = {path_expr}
if (-not (Test-Path -LiteralPath $h)) {{
    "PATH: $h"
    "ERROR: history not found"
    return
}}
$lines = @(Get-Content -LiteralPath $h -ErrorAction SilentlyContinue)
"PATH: $h"
"TOTAL LINES: $($lines.Count)"
for ($i = 0; $i -lt $lines.Count; $i++) {{
    "[${{i}}] $($lines[$i])"
}}
"""


def run_history(args: argparse.Namespace) -> int:
    script = make_history_script(args.remote_path, args.method)
    with open_pool(args) as pool:
        rc, _ = invoke_remote(args, pool, script, logger=Logger(args.log))
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
{cmdlet} -Path {ps_quote(remote)} -Value $b -Encoding Byte
"""


def _upload_verify_script(remote: str) -> str:
    return rf"""
$ErrorActionPreference = 'Stop'
$path = {ps_quote(remote)}
"Uploaded: $path ($((Get-Item -LiteralPath $path).Length) bytes)"
"""


def _download_script(remote: str, chunk_bytes: int) -> str:
    # ReadCount=N tells Get-Content to emit arrays of N bytes; we hex-encode
    # each array server-side so the payload arrives as one string per chunk.
    return rf"""
$ErrorActionPreference = 'Stop'
Get-Content -Path {ps_quote(remote)} -Encoding Byte -ReadCount {int(chunk_bytes)} |
    ForEach-Object {{ -join ($_ | ForEach-Object {{ '{{0:x2}}' -f $_ }}) }}
"""


def _do_upload(pool, args: argparse.Namespace, logger: Logger) -> int:
    local = Path(args.local_path).expanduser()
    if not local.is_file():
        emit(f"Local file not found: {local}", stderr=True, logger=logger)
        return 1
    remote = args.remote_path
    data = local.read_bytes()
    chunk_size = max(1024, getattr(args, "chunk_size", UPLOAD_DEFAULT_CHUNK))

    rc, _ = invoke_remote(
        args, pool, _upload_init_script(remote),
        logger=logger, display=getattr(args, "verbose", False),
    )
    if rc:
        return rc

    total_chunks = (len(data) + chunk_size - 1) // chunk_size or 1
    for index in range(total_chunks):
        chunk = data[index * chunk_size : (index + 1) * chunk_size]
        rc, _ = invoke_remote(
            args, pool, _upload_chunk_script(remote, chunk, first=(index == 0)),
            logger=logger, display=False,
        )
        if rc:
            return rc
        if getattr(args, "progress", False):
            emit(f"uploaded chunk {index + 1}/{total_chunks}", logger=logger)

    rc, _ = invoke_remote(args, pool, _upload_verify_script(remote), logger=logger)
    return rc


def _do_download(pool, args: argparse.Namespace, logger: Logger) -> int:
    remote = args.remote_path
    local = Path(args.local_path).expanduser()
    chunk_bytes = max(256, getattr(args, "chunk_bytes", DOWNLOAD_DEFAULT_CHUNK_BYTES))

    rc, lines = invoke_remote(
        args, pool, _download_script(remote, chunk_bytes),
        logger=logger, display=False,
    )
    if rc:
        return rc

    pieces: list[bytes] = []
    for line in lines:
        hex_str = line.strip()
        if not hex_str:
            continue
        try:
            pieces.append(bytes.fromhex(hex_str))
        except ValueError as exc:
            emit(f"Could not decode chunk: {exc}", stderr=True, logger=logger)
            return 1
    data = b"".join(pieces)

    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(data)
    emit(f"Downloaded: {local} ({len(data)} bytes)", logger=logger)
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
        if     ($a.ValidValues)              {{ $detail = "ValidValues={{$($a.ValidValues -join ', ')}}" }}
        elseif ($a.RegexPattern)             {{ $detail = "Pattern=$($a.RegexPattern)" }}
        elseif ($a.MinLength -ne $null)      {{ $detail = "Length=$($a.MinLength)..$($a.MaxLength)" }}
        elseif ($a.MinRange -ne $null)       {{ $detail = "Range=$($a.MinRange)..$($a.MaxRange)" }}
        elseif ($a.AliasNames)               {{ $detail = "Aliases=$($a.AliasNames -join ',')" }}
        if ($detail) {{ "    [$short] $detail" }} else {{ "    [$short]" }}
    }}
}}
"""


def run_proxy(args: argparse.Namespace) -> int:
    with open_pool(args) as pool:
        rc, _ = invoke_remote(args, pool, make_proxy_script(args.name), logger=Logger(args.log))
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
    script = make_definition_script(args.name)
    with open_pool(args) as pool:
        rc, _ = invoke_remote(args, pool, script, logger=Logger(args.log))
        return rc


SHELL_BUILTINS = (
    ":help",
    ":quit",
    ":exit",
    ":q",
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
        import readline  # noqa: WPS433 - optional, missing on bare Windows
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
  :load <local.ps1>             run a local PowerShell script file
  :upload <local> <remote>      upload a file
  :download <remote> <local>    download a file
  :commands [--all] [pattern]   list visible commands (default: Function+Cmdlet only)
  :def <cmdlet>                 print the cmdlet's Definition (parameter sets)
  :proxy <cmdlet>               print parameters the JEA proxy exposes + their validators
  :history [remote-path]        print PSReadLine history
  :info                         show session identity and language mode
Any other line is sent as PowerShell to the remote endpoint."""


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

    if not verb.startswith(":"):
        rc, _ = invoke_remote(args, pool, line, logger=logger, raise_session=True)
        return rc

    if verb == ":help":
        emit(shell_help(), logger=logger)
        return 0

    if verb == ":info":
        rc, _ = invoke_remote(
            args, pool, INFO_SCRIPT, logger=logger, raise_session=True,
        )
        return rc

    if verb == ":commands":
        pattern = "*"
        command_types = ("Function", "Cmdlet")
        if rest.strip():
            parts = split_shell_args(rest)
            if "--all" in parts:
                command_types = None
                parts = [p for p in parts if p != "--all"]
            if parts:
                pattern = parts[0]
        rc, _ = invoke_remote(
            args, pool, make_commands_script(pattern, command_types=command_types),
            logger=logger, raise_session=True,
        )
        return rc

    if verb == ":def":
        if not rest.strip():
            emit("usage: :def <cmdlet>", stderr=True, logger=logger)
            return 1
        parts = split_shell_args(rest)
        rc, _ = invoke_remote(
            args, pool, make_definition_script(parts[0]),
            logger=logger, raise_session=True,
        )
        return rc

    if verb == ":proxy":
        if not rest.strip():
            emit("usage: :proxy <cmdlet>", stderr=True, logger=logger)
            return 1
        parts = split_shell_args(rest)
        rc, _ = invoke_remote(
            args, pool, make_proxy_script(parts[0]),
            logger=logger, raise_session=True,
        )
        return rc

    if verb == ":history":
        remote_path = None
        if rest.strip():
            parts = split_shell_args(rest)
            if parts:
                remote_path = parts[0]
        rc, _ = invoke_remote(
            args, pool, make_history_script(remote_path, "auto"),
            logger=logger, raise_session=True,
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
    pending_line: Optional[str] = None
    retried_line: Optional[str] = None
    first_connect = True
    reconnect_attempts = 0

    who = (args.username or "kerberos").lower()
    config_label = args.configuration_name or "default"
    prompt_text = f"[{who}@{args.host} {config_label}] PS> "

    while True:
        try:
            with open_pool(args) as pool:
                reconnect_attempts = 0  # reached the with body - pool is live
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

                while True:
                    if pending_line is not None:
                        line = pending_line
                        pending_line = None
                        # Same line that triggered the reconnect - note it so
                        # we can refuse to spin if it keeps blowing up.
                        is_retry = True
                    else:
                        try:
                            line = input(prompt_text)
                        except EOFError:
                            print()
                            return rc_total
                        except KeyboardInterrupt:
                            print()
                            continue
                        is_retry = False
                        retried_line = None

                    line = line.strip()
                    if not line:
                        continue
                    if line in (":q", ":quit", ":exit"):
                        return rc_total

                    try:
                        rc = dispatch_shell_line(args, pool, line, logger)
                    except SessionExpired as exc:
                        emit(
                            f"[session] {exc} - reconnecting",
                            stderr=True,
                            logger=logger,
                        )
                        if is_retry and retried_line == line:
                            emit(
                                "[session] retry already attempted on this "
                                "line - giving up; type :quit and relaunch "
                                "if it persists",
                                stderr=True,
                                logger=logger,
                            )
                            retried_line = None
                            rc = 1
                        else:
                            pending_line = line
                            retried_line = line
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
                    f"[connect-error] {exc} "
                    f"(gave up after {reconnect_attempts} attempts)",
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
    parser.add_argument("--delegate", action="store_true", help="Enable Kerberos/negotiate delegation if supported.")
    parser.add_argument("--hostname-override", help="Hostname override for negotiate auth if supported.")
    parser.add_argument("--negotiate-service", help="SPN service name override if supported.")
    parser.add_argument("--certificate-pem", help="Client certificate PEM for certificate auth if supported.")
    parser.add_argument("--certificate-key-pem", help="Client certificate key PEM for certificate auth if supported.")
    parser.add_argument("--connection-timeout", type=int, default=30, help="Connection timeout seconds.")
    parser.add_argument("--operation-timeout", type=int, default=20, help="WSMan operation timeout seconds.")
    parser.add_argument("--read-timeout", type=int, help="Read timeout seconds if supported.")
    parser.add_argument("--reconnection-retries", type=int, default=0, help="Reconnect retries if supported.")
    parser.add_argument("--max-envelope-size", type=int, default=153600, help="WSMan envelope size.")
    parser.add_argument("--locale", default="en-US", help="WSMan locale.")
    parser.add_argument("--data-locale", help="WSMan data locale.")
    parser.add_argument("--log", help="Append commands and output to a local log file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose local output.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A compact pypsrp WinRM/JEA client with Kerberos ccache support."
    )
    add_connection_args(parser)
    sub = parser.add_subparsers(dest="mode", required=True)

    run_p = sub.add_parser("run", aliases=("exec", "x"), help="Run a PowerShell command.")
    run_p.add_argument("--json", action="store_true", help="Pipe output through ConvertTo-Json.")
    run_p.add_argument("--json-depth", type=int, default=4, help="ConvertTo-Json depth.")
    run_p.add_argument("command", nargs=argparse.REMAINDER)
    run_p.set_defaults(func=run_command)

    script_p = sub.add_parser("script", help="Run a local .ps1 file.")
    script_p.add_argument("--encoding", default="utf-8", help="Local script encoding.")
    script_p.add_argument("--json", action="store_true", help="Pipe output through ConvertTo-Json.")
    script_p.add_argument("--json-depth", type=int, default=4, help="ConvertTo-Json depth.")
    script_p.add_argument("script_path")
    script_p.set_defaults(func=run_script)

    batch_p = sub.add_parser("batch", help="Run one command per line from a local file.")
    batch_p.add_argument("--encoding", default="utf-8", help="Local batch file encoding.")
    batch_p.add_argument("--stop-on-error", action="store_true", help="Stop after the first failing command.")
    batch_p.add_argument("batch_path")
    batch_p.set_defaults(func=run_batch)

    shell_p = sub.add_parser("shell", help="Open a small interactive loop.")
    shell_p.add_argument("--encoding", default="utf-8", help="Encoding for :load.")
    shell_p.add_argument("--chunk-size", type=int, default=UPLOAD_DEFAULT_CHUNK,
                         help="Upload chunk size in raw bytes (kept small to fit the WSMan envelope; the [byte[]]@(...) literal expands to roughly 3.5x).")
    shell_p.add_argument("--chunk-bytes", type=int, default=DOWNLOAD_DEFAULT_CHUNK_BYTES,
                         help="Download chunk size in bytes (Get-Content -ReadCount).")
    shell_p.set_defaults(func=run_shell, local_path=None, remote_path=None, progress=False)

    info_p = sub.add_parser("info", help="Show identity, PS version, and language mode.")
    info_p.set_defaults(func=run_info)

    commands_p = sub.add_parser("commands", help="List commands visible inside the endpoint (default: Function+Cmdlet).")
    commands_p.add_argument("pattern", nargs="?", default="*", help="Get-Command pattern.")
    commands_p.add_argument("--all", action="store_true", help="Include Aliases and Applications too.")
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
        help="Read with Get-Content, .NET static methods, or auto fallback. Default: auto.",
    )
    history_p.set_defaults(func=run_history)

    upload_p = sub.add_parser("upload", help="Upload a local file to a remote path.")
    upload_p.add_argument("--chunk-size", type=int, default=UPLOAD_DEFAULT_CHUNK,
                          help="Upload chunk size in raw bytes (each chunk turns into a [byte[]]@(d1,d2,...) literal, roughly 3.5x the byte count).")
    upload_p.add_argument("--progress", action="store_true", help="Print chunk progress.")
    upload_p.add_argument("local_path")
    upload_p.add_argument("remote_path")
    upload_p.set_defaults(func=run_upload)

    download_p = sub.add_parser("download", help="Download a remote file to a local path.")
    download_p.add_argument("--chunk-bytes", type=int, default=DOWNLOAD_DEFAULT_CHUNK_BYTES,
                            help="Download chunk size in bytes (Get-Content -ReadCount).")
    download_p.add_argument("remote_path")
    download_p.add_argument("local_path")
    download_p.set_defaults(func=run_download)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
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
