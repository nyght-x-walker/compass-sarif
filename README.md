# compass-sarif

**Convert COMPASS-RT-style JSON findings into SARIF 2.1.0 for GitHub code scanning.**

[![test](https://github.com/nyght-x-walker/compass-sarif/actions/workflows/test.yml/badge.svg)](https://github.com/nyght-x-walker/compass-sarif/actions/workflows/test.yml)

AI red-team reports usually end up as dashboards, PDFs, or chat transcripts. Code scanning needs SARIF: a stable, reviewable format with rules, locations, levels, and fingerprints. This exporter turns a small findings JSON file into SARIF so the result can be uploaded, reviewed, and tracked like any other security alert.

It is a converter, not a scanner. It does not call models, touch targets, or upload anything.

## Use as a GitHub Action

```yaml
name: compass
on: [push]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nyght-x-walker/compass-sarif@v1
        with:
          input: reports/compass-findings.json
          output: reports/compass.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/compass.sarif
```

The action is composite and needs only Python 3.10+.

## Use as a CLI

```bash
python compass_sarif.py examples/findings.json -o compass.sarif
```

Make absolute source paths relative to the repository:

```bash
python compass_sarif.py findings.json -o compass.sarif --repo-root .
```

Exit codes: `0` on success, `2` on invalid input or I/O errors.

## Input

```json
{
  "tool": {
    "name": "COMPASS-RT",
    "version": "0.2",
    "informationUri": "https://github.com/nyght-x-walker/compass-sarif"
  },
  "run": {
    "name": "sample-chat-run",
    "target": "chat"
  },
  "findings": [
    {
      "ruleId": "LLM01.prompt-injection",
      "ruleName": "Prompt injection",
      "shortDescription": "Direct prompt injection changed the assistant's system behavior.",
      "level": "error",
      "message": "A direct prompt injection changed the assistant's system behavior.",
      "uri": "app/chat.py",
      "startLine": 42,
      "endLine": 42,
      "snippet": "user_input = request.json['message']",
      "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
      "properties": {
        "owasp": "LLM01",
        "attack": "direct",
        "confidence": 0.92
      }
    }
  ]
}
```

| Field | Required | Notes |
|---|---|---|
| `ruleId` | yes | Stable rule identifier |
| `message` | yes | Human-readable finding |
| `level` | no | `error`, `warning`, `note`, or `none`; defaults to `warning` |
| `uri` | no | Source path or URL; relative paths are preferred |
| `startLine`, `endLine` | no | Positive integers; defaults to line 1 |
| `startColumn`, `endColumn` | no | Positive integers |
| `snippet` | no | Source text attached to the region |
| `properties` | no | Arbitrary metadata copied to the result |
| `ruleName`, `shortDescription`, `helpUri` | no | Rule metadata |

The top-level `findings` key may also be named `results`.

## Output

The generated SARIF includes:

- One `run` with the COMPASS-RT driver metadata
- Deduplicated `rules` with stable indexes
- Results with rule IDs, levels, messages, and optional locations
- `partialFingerprints` so repeated findings keep a stable identity
- Run and target metadata in `properties`

See [`examples/compass.sarif`](examples/compass.sarif).

## Scope and safety

- No network access and no third-party dependencies.
- No target data, secrets, or model output are required; only the findings file.
- This does not replace a scanner, a judge, or an authorization process.
- Only test systems you own or have written permission to test.

## Related

- [COMPASS-RT case study](https://github.com/nyght-x-walker/case-studies/blob/main/compass-rt.md)
- [Case studies index](https://github.com/nyght-x-walker/case-studies)

## Development

```bash
python -m unittest discover -s tests -v
python compass_sarif.py examples/findings.json -o examples/compass.sarif
```

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

MIT
