# URL Validation

Use URL Validation when a request accepts a URL, host, or origin and parser or
allow-list behavior is the hypothesis. Put a literal marker at every intended
injection point; `{INJECT}` is the default.

```http
GET /redirect?next={INJECT} HTTP/1.1
Host: app.example

```

```bash
python3 scripts/bypassfuzzer.py run url-validation \
  --request redirect.raw \
  --target-origin https://app.example \
  --allowed-host trusted.example \
  --attacker-host attacker.example \
  --contexts absolute-url \
  --attacks domain-allow-list-bypass \
  --encodings raw,intruders \
  --output evidence/url-validation-001
```

The marker must occur in the request. Provide `--attacker-host`, or omit it and
use `--oob-domain` / `--oob-generator` to supply the attacker host.

## Selectors

Contexts:

```text
absolute-url,host-header,cors
```

Attack IDs:

```text
domain-allow-list-bypass
fake-relative-urls
loopback
ipv6
cloud-metadata-endpoints
url-splitting-unicode-characters
normalization-attack
```

Encoding IDs:

```text
raw,intruders,everything,special-chars,unicode-escape
```

Raw CR/LF values that cannot cross the request-model boundary are skipped;
encoded variants remain available.

## Validation boundary

`--oob-domain HOST` uses an operator-controlled or native Collaborator payload
host. `--oob-generator EXECUTABLE` invokes a local executable with no arguments;
it must exit successfully within 15 seconds and print one fresh hostname to
stdout. The two OOB options are mutually exclusive. Do not pass a client that
prints JSON or status lines without a wrapper extracting just the hostname.

Bypass and full-catalog Sweep use that source for callback-dependent payloads.
URL Validation uses it when `--attacker-host` is absent; an explicit attacker
host takes precedence. Payload generation can run during `--preview`, so a
preview sends no target traffic but can still allocate callback tokens.

The CLI does not create a native Burp client or poll interactions. Keep the
callback client session and token attribution with the run and poll it through
the selected observation tool. An apparent parser acceptance or response change
does not prove an outbound request or SSRF. Confirm an attributable interaction
and validate its security consequence separately.
