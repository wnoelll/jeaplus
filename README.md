# JEA+

`jeaplus` is a focused PSRP/WinRM client for assessing and operating
[PowerShell Just Enough Administration (JEA)](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/overview)
endpoints. It is built around the details that matter in restricted sessions:

- enumerating the command surface without drowning in aliases;
- inspecting generated proxy functions, exposed parameters, and validators;
- retrieving usable command definitions;
- invoking cmdlets without submitting PowerShell source;
- moving files through restricted cmdlet surfaces;
- using Kerberos ccaches/keytabs correctly;
- recovering dead runspaces without silently replaying mutating commands; and
- rejecting source payloads that are likely to exceed the WSMan envelope.

Use it only on endpoints you are authorized to assess or administer.

## Language-mode scope: read this first

Canonical JEA configurations created with `RestrictedRemoteServer` operate in
**NoLanguage**. Custom restricted endpoints are also commonly encountered in
**ConstrainedLanguage** or FullLanguage. Those modes are materially different.

JEA+ therefore has two execution backends:

| Backend | Transport construction | Intended endpoint | Capability |
|---|---|---|---|
| `script` | `PowerShell.add_script()` | FullLanguage / ConstrainedLanguage | All rich helpers, arbitrary source, proxy inspection, history expressions, CLM transfer helpers |
| `structured` | `add_cmdlet()`, `add_parameter()`, `add_argument()`, `add_statement()` | NoLanguage | Source-free cmdlet and JSON pipelines; reduced helper set based on exposed commands |

`--backend auto` is the default. It sends one non-mutating language-mode probe.
If the endpoint rejects the expression (as stock NoLanguage JEA does), JEA+
selects the structured backend. Use `--backend script` or
`--backend structured` to override detection.

NoLanguage does not magically make unavailable commands available. A stock
`RestrictedRemoteServer` endpoint exposes only a small default command set and
no PowerShell providers. Structured file transfer, for example, works only if
the role explicitly exposes the necessary content and item cmdlets. The client
never attempts to bypass the role capability.

## Install

Python 3.10 or newer is required. JEA+ is tested with `pypsrp` 0.8.1 and 0.9.1;
the declared compatibility window is `>=0.8.1,<0.10`.

```bash
python -m pip install -r requirements-jea-plus.txt
```

Install the project to expose the `jeaplus` console command:

```bash
python -m pip install .
jeaplus --version
```

Kerberos on Linux:

```bash
python -m pip install '.[kerberos]'
```

CredSSP:

```bash
python -m pip install '.[credssp]'
```

## Quick start

Kerberos ccache against a custom ConstrainedLanguage endpoint:

```bash
KRB5CCNAME='/tmp/svc_gmsa.ccache' \
python jea_plus.py dc.example.local \
  --auth kerberos --no-ssl -c restricted \
  shell
```

Canonical NoLanguage JEA, forcing source-free execution:

```bash
python jea_plus.py server.example.local \
  --auth kerberos --ccache /tmp/operator.ccache \
  -c JEAMaintenance --backend structured \
  commands
```

When Kerberos is active without an explicit password/hash, JEA+ deliberately
drops `--username`. Passing a username alongside an empty password can make the
GSSAPI stack initiate a new AS-REQ instead of selecting the principal from
`KRB5CCNAME` or the configured keytab.

## Assessment workflow

```text
connect
→ enumerate exposed commands
→ inspect definitions and effective proxy validators
→ map the permitted parameter/value space
→ execute through the appropriate backend
→ transfer artifacts only when the role exposes the required cmdlets
```

### Rich helpers

| Subcommand / shell builtin | Purpose |
|---|---|
| `info` / `:info` | Identity, PS version, language mode, configuration, connected user, and run-as user in the script backend; backend status in NoLanguage |
| `commands` / `:commands [--all] [pattern]` | Visible commands, defaulting to Function + Cmdlet |
| `definition` (`def`) / `:def <name>` | Command definition and parameter metadata |
| `proxy` / `:proxy <name>` | Effective proxy parameters plus `ValidateSet`, `ValidatePattern`, ranges, lengths, and aliases |
| `history` / `:history [path]` | PSReadLine history; NoLanguage requires an explicit path and exposed `Get-Content` |
| `upload` / `:upload <local> <remote>` | Staged remote upload with verification and final rename |
| `download` / `:download <remote> <local>` | Local staged download with verification and atomic replacement |
| `run`, `script`, `batch` | Source execution for FullLanguage/ConstrainedLanguage endpoints |
| `cmdlet` / `:cmdlet` | A single source-free PSRP command |
| `pipeline` | A validated source-free JSON pipeline |
| `shell` | Interactive loop with completion, safe recovery, and explicit retry |

The structured versions of `proxy` and `definition` are best effort: their
quality depends on which `Get-Command` properties the endpoint serializes. The
script backend retains the richest validator view because it can inspect
metadata before PSRP serialization.

## Source-free NoLanguage invocation

Invoke one cmdlet. Plain values are strings; JSON variants preserve numbers,
booleans, arrays, objects, and null:

```bash
python jea_plus.py server -c JEAMaintenance cmdlet Get-Service \
  --parameter Name=Spooler

python jea_plus.py server -c JEAMaintenance cmdlet Set-Example \
  --parameter Name=demo \
  --parameter-json 'Options={"enabled":true,"retries":3}' \
  --switch Force \
  --argument tail \
  --argument-json 42
```

For a pipeline, provide a JSON array. Adjacent entries are piped together;
`end_of_statement` terminates that pipeline before the next command:

```json
[
  {
    "cmdlet": "Get-Process",
    "parameters": {"Name": ["pwsh", "powershell"]}
  },
  {
    "cmdlet": "Select-Object",
    "parameters": {"Property": ["Name", "Id"]},
    "end_of_statement": true
  },
  {
    "cmdlet": "Get-Service",
    "parameters": {"Name": "Spooler"}
  }
]
```

```bash
python jea_plus.py server -c JEAMaintenance pipeline pipeline.json
cat pipeline.json | python jea_plus.py server -c JEAMaintenance pipeline -
```

The document schema is strict: unknown keys, empty command names, malformed
parameter maps, and non-array argument lists are rejected locally.

## Proxy introspection

The proxy view is intentionally distinct from ordinary command help. JEA role
capabilities can remove parameters and constrain values with validation
attributes. The effective proxy is the assessment surface:

```text
[operator@server JEAMaintenance] PS> :proxy Select-Object
Cmdlet:      Select-Object
CommandType: Cmdlet
...
  Property  [System.String[]]
    [ValidateCountAttribute] Length=1..11
    [ValidateSetAttribute] ValidValues={ModuleName, Namespace, OutputType, ...}
```

## Safe session recovery

Transport failure after dispatch is ambiguous: the remote mutation may have
completed even though its response was lost. The shell reconnects automatically
but **does not replay the command**:

```text
Session recovered. The previous command may have executed remotely.
Use :retry to submit it again.
```

`:retry` is an explicit operator decision. `--retry-unsafe` restores one
automatic replay for workflows that deliberately accept at-least-once
execution semantics.

## File transfer guarantees

Upload no longer writes into the final path. It uses an adjacent random staging
name, streams the local file in chunks, verifies the staged content, then calls
`Move-Item -Force` to replace the destination. A failed write or verification
leaves the prior destination untouched and triggers best-effort staging cleanup.

Download writes into an owner-only local temporary file and uses `os.replace()`
only after successful decoding and verification. The previous local destination
is preserved on failure.

All content/item operations use `-LiteralPath`, including names containing
`[`, `]`, `*`, or `?`.

Verification policies:

```text
--verify size      compare byte lengths (default)
--verify sha256    compare length and SHA-256; requires exposed Get-FileHash
--verify none      explicit opt-out
```

Remote staged upload requires the role to expose the relevant subset of
`Set-Content`, `Add-Content`, `Get-Item`, `Move-Item`, and `Remove-Item`.
Download requires `Get-Content` and, unless verification is disabled,
`Get-Item`. Structured NoLanguage transfer sends byte arrays as PSRP parameter
values rather than PowerShell byte-array source literals.

## Source input and shell quoting

Shells remove their own quote delimiters before Python receives `argv`. JEA+
refuses ambiguous reconstruction when a multi-part argument already contains
whitespace. Use one of these unambiguous forms:

```bash
# Complete expression as one argv element
python jea_plus.py server run "Write-Output 'hello world'"

# File
python jea_plus.py server run --command-file command.ps1

# Stdin
printf "%s\n" "Write-Output 'hello world'" | \
  python jea_plus.py server run --stdin
```

## History methods

`--method` is functional rather than decorative:

- `cmdlet` uses `Get-Content -LiteralPath`;
- `dotnet` uses `[System.IO.File]::ReadAllLines()` and therefore requires
  FullLanguage;
- `auto` tries the cmdlet and then the FullLanguage fallback.

Structured NoLanguage history never uses the .NET path and requires an explicit
`--remote-path`.

## Authentication examples

```bash
# Kerberos ccache (default auth)
python jea_plus.py dc.example.local --no-ssl -c restricted \
  --ccache /tmp/svc_gmsa.ccache info

# Kerberos keytab
python jea_plus.py dc.example.local --no-ssl -c restricted \
  -u svc@EXAMPLE.LOCAL --keytab /tmp/svc.keytab info

# NTLM pass-the-hash
python jea_plus.py dc.example.local --no-ssl -c Microsoft.PowerShell \
  -u 'EXAMPLE\alice' -H 31d6cfe0d16ae931b73c59d7e0c089c0 info

# HTTPS with certificate validation and a prompted NTLM password
python jea_plus.py dc.example.local --ssl --cert-validation \
  -u 'EXAMPLE\alice' --auth ntlm --ask-pass \
  -c Microsoft.PowerShell info
```

## Logging

`--log path` appends `CMD/CMDLET`, `OUT`, and `ERR` records. Transcript files
are created as regular files with mode `0600` on Unix, existing permissive files
are tightened, and symlink targets are refused where the platform provides
`O_NOFOLLOW`. Treat transcripts as sensitive assessment evidence.

## Development and verification

```bash
python -m pip install -e '.[dev]'
ruff format --check jea_plus.py tests
ruff check jea_plus.py tests
mypy jea_plus.py
pytest --cov=jea_plus --cov-branch --cov-report=term-missing
pip-audit -r requirements-jea-plus.txt
```

CI covers Python 3.10 through 3.14 at representative points and tests both the
oldest and newest supported `pypsrp` releases. Unit tests use protocol-shaped
stubs and do not claim live endpoint coverage; release validation should still
exercise both a stock NoLanguage role and the intended custom
ConstrainedLanguage endpoint.

## License

MIT. See [`LICENSE`](LICENSE).
