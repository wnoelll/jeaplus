# jeaplus

A small `pypsrp` WinRM client built specifically for **JEA** (Just Enough
Administration) endpoints - the kind that run under `ConstrainedLanguage`,
ship with proxy functions whose `Select-Object` only allows a fixed
property allowlist, and reject `[System.IO.File]` / `[Convert]` static
calls. Most generic WinRM tools weren't designed against that wall;
`jeaplus` is.

Lab work, JEA validation, admin troubleshooting, escape-hunting on
endpoints you already have credentials for. Single file.

## Install

```bash
python -m pip install -r requirements-jea-plus.txt
```

For Kerberos ccache support on Linux, install the system Kerberos libraries
and the Kerberos-capable `pypsrp` extra:

```bash
python -m pip install 'pypsrp[kerberos]'
```

For CredSSP:

```bash
python -m pip install 'pypsrp[credssp]'
```

## What's in here

Everything works under ConstrainedLanguage on a real JEA endpoint:

| Subcommand / shell builtin | What it does |
|---|---|
| `info` / `:info` | Identity, PSVersion, LanguageMode, ConfigurationName, RunAsUser. Variable/property reads only - no `[Type]::Method()`. |
| `commands` / `:commands [--all] [pattern]` | Visible commands. Defaults to Function+Cmdlet (Aliases + Applications dropped - they drown the actual surface); `--all` opts in. |
| `definition` (`def`) / `:def <cmdlet>` | The cmdlet's parameter sets and parameters - what's *documented*. |
| `proxy` / `:proxy <cmdlet>` | The parameters this **JEA proxy** actually exposes plus their `[ValidateSet]`, `[ValidatePattern]`, `[ValidateRange]`, `[ValidateLength]`, alias attributes. *This is the escape-hunting view*: the proxy can strip params and tighten validation, and `:def` won't show that. |
| `history [remote-path]` / `:history` | PSReadLine console history - straight cmdlet path, no dead `[IO.File]::ReadAllLines` fallback. |
| `upload` / `:upload <local> <remote>` | File push via `Set-Content` / `Add-Content -Encoding Byte` chunks. ConstrainedLanguage-safe. |
| `download` / `:download <remote> <local>` | File pull via `Get-Content -Encoding Byte` then hex-encode server-side. |
| `run` / `script` / `batch` | One-liner / local `.ps1` / line-per-command file. |
| `shell` | Interactive REPL: tab-complete on the cached `Get-Command` names, contextual prompt, session retry on 400/401/expired, reconnect-with-backoff (3 attempts) when the JEA pipeline closes. |

## Quick start

JEA endpoint with a gMSA Kerberos ticket:

```bash
KRB5CCNAME='/tmp/svc_gmsa.ccache' \
python jea_plus.py dc.example.local \
  --auth kerberos --no-ssl -c restricted \
  shell
```

```text
Connected shell (NNNN cmdlets cached). Type :help for local commands, :quit to exit.
[kerberos@dc.example.local restricted] PS> :info
ComputerName:        DC
LanguageMode:        ConstrainedLanguage
ConfigurationName:   restricted
ConnectedUser:       EXAMPLE\svc_gmsa$
RunAsUser:           EXAMPLE\svc_gmsa$
[kerberos@dc.example.local restricted] PS> :proxy Select-Object
Cmdlet:      Select-Object
CommandType: Cmdlet
Module:      Microsoft.PowerShell.Utility
...
  Property  [System.String[]]
    [ValidateCountAttribute] Length=1..11
    [ValidateSetAttribute] ValidValues={ModuleName, Namespace, OutputType, Count, HelpUri, Name, CommandType, ResolvedCommandName, DefaultParameterSet, CmdletBinding, Parameters}
[kerberos@dc.example.local restricted] PS> :history
PATH: C:\Users\svc_gmsa$\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
TOTAL LINES: 108
[0]  ls
[1]  ls -force
...
```

When `--auth kerberos` is in effect and no explicit secret is given,
`-u` is dropped before talking to gssapi - pypsrp would otherwise
trigger AS-REQ with an empty password and silently bypass the ccache.

## Auth modes

```bash
# Kerberos via ccache (default)
python jea_plus.py dc.example.local --no-ssl -c restricted \
  --ccache '/tmp/svc_gmsa.ccache' info

# Kerberos via keytab
python jea_plus.py dc.example.local --no-ssl -c restricted \
  -u 'svc@EXAMPLE.LOCAL' --keytab /tmp/svc.keytab info

# NTLM pass-the-hash
python jea_plus.py dc.example.local --no-ssl -c Microsoft.PowerShell \
  -u 'EXAMPLE\alice' -H 31d6cfe0d16ae931b73c59d7e0c089c0 info

# NTLM with prompted password
python jea_plus.py dc.example.local --no-ssl -c Microsoft.PowerShell \
  -u 'EXAMPLE\alice' --auth ntlm --ask-pass info

# HTTPS with cert validation
python jea_plus.py dc.example.local --ssl --cert-validation \
  -u 'EXAMPLE\alice' --auth ntlm --ask-pass -c Microsoft.PowerShell info
```

## Wrapping

Restricted endpoints often only accept `& { ... }` invocation; that's the
default. Use `--no-wrap` (alias for `--wrap none`) to send the script
through `add_script` directly when the endpoint accepts it.

## Logging

`--log path/to/file` appends a `CMD/OUT/ERR` transcript of everything the
client sends and receives.

## Tests

```bash
pip install pytest
pytest tests/
```

Unit tests cover the pure helpers (`ps_quote`, `is_session_error`, all the
`make_*_script` builders, `get_password`, the upload chunk encoder, the
download script, the argparse wiring) and exercise `invoke_ps`'s session
detection through a stubbed pypsrp.

## License

MIT - see `LICENSE`.
