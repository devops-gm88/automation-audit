# automation-audit


An evidence-cited audit of an n8n workflow export: every finding re-verifies against the export bytes, so a finding is a citation and not an opinion.

[![CI](https://github.com/devops-gm88/automation-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/devops-gm88/automation-audit/actions/workflows/ci.yml) **24 tests** in CI run [44549742317](https://github.com/devops-gm88/automation-audit/actions/runs/44549742317) - measured: **14/14 findings re-derived** from a 12-workflow, 38-node fixture, 0 clean workflows

```bash
python3 audit.py audit fixtures/estate_12.json --claims fixtures/claims.json --out out/estate_12
```

An **evidence-cited audit of an n8n automation estate**. It reads a workflow export, reports what is
broken or missing, and every finding cites the workflow, the node and a JSON pointer that
**re-verifies against the export bytes**. If the export changes and a finding can no longer be
re-derived, `verify` fails. That is the whole product: a finding is a citation, not an opinion.

No third-party packages. Python 3.10+. No network. Read-only: it never connects to the client's
instance, never needs credentials, and never runs a workflow.

```
python3 audit.py audit fixtures/estate_12.json --claims fixtures/claims.json --out out/estate_12
python3 audit.py verify fixtures/estate_12.json out/estate_12/findings.json
```

```
14 findings across 12 workflows (38 nodes, 38 analysed); report 2p -> out/estate_12
verify: 14/14 findings re-derived from the export, 11 nodes cited of 38
VERIFY OK
```

Outputs, in the `--out` directory:

| file | what it is |
|---|---|
| `findings.json` | every finding with its rule, severity, pointer, observed values and the expectation it fails |
| `inventory.json` | workflow/node inventory plus the list of node types the rules did not analyse |
| `report.md` | the human report: findings table, evidence, client claims, coverage, limitations |
| `report.pdf` | the same report as a one-or-two page PDF for the client |

## The ten rules

| id | severity | what it means |
|---|---|---|
| R01 | high | a node that writes to another system has no error branch |
| R02 | high | a mailbox trigger runs with nothing keyed on `messageId` (re-reads reprocess mail) |
| R03 | high | a spreadsheet/base/table/document identifier is typed into the node body |
| R04 | critical | a credential-shaped value lives in the workflow body, where it travels with every export |
| R05 | high | no trigger node: the workflow cannot run on its own |
| R06 | critical | two workflows own the same mailbox, cron or webhook - the double-send risk |
| R07 | medium | a write node has no `retryOnFail`; one transient error loses the item |
| R08 | medium | a file-type filter has no rejected branch: the other attachments disappear |
| R09 | high | a switch routes its cases and has no fallback for the item that matches none |
| R10 | medium | a system receives writes and no workflow in the estate ever reads it |

`python3 audit.py rules` prints the same list with the long description of each rule.

## Why a finding can be trusted

Each finding carries two kinds of fact, both recomputed by `verify` from the export alone:

* **observed** - the actual fields of the cited node (`type`, `onError`, `retryOnFail`, or the value
  at the cited parameter pointer). Credential values are never written to any artifact; a finding
  says *a value is present* and never what it is.
* **derived** - a value computed by the same pure graph helpers the rules use: a trigger signature,
  a branch count, the system a node writes to.

`verify` does not re-run the rules. It resolves the pointer, compares the observed fields, recomputes
the derived facts, and refuses any finding whose citation no longer holds.

## The negative control

The test that makes this an audit rather than a report: delete the node a finding depends on and
verification must fail.

```
$ python3 audit.py verify out/estate_12_broken.json out/estate_12/findings.json
FAIL F-bbb88127: pointer /3/nodes/1/parameters/apiKey does not resolve (IndexError)
VERIFY FAILED: the report cites something the export no longer contains.
$ echo $?
1
```

`./demo.sh` runs this end to end, then the fifteen acceptance checks.

## The fixtures

| fixture | what it is |
|---|---|
| `fixtures/estate_12.json` | 12 workflows, 38 nodes, ten planted faults covering all ten rules; two workflows share one mailbox (double-send) and one carries a credential-shaped value in a node body |
| `fixtures/estate_clean.json` | 4 workflows, 14 nodes, no faults: the clean control, where any finding is a false positive |
| `fixtures/claims.json` | five client beliefs, two of which the audit contradicts |

The estate includes the plants a real one hides: an orphan prototype with no trigger, a duplicate
mailbox reader, a hardcoded spreadsheet id, a PDF filter that drops everything else, a router with no
fallback, and a weekly write into Airtable that nothing reads back.

## Commands

```
./demo.sh                  # audit both fixtures, verify, run the negative control, acceptance suite
make test                  # 24 unit tests
make verify                # 15 named acceptance checks, prints 15/15
make rules                 # list the rules
```

## Coverage, limits, honesty

* **n8n exports only.** Make blueprints, Zapier and assistant/bot estates are not parsed by this
  version. A node type the rules do not model is never dropped silently: it is listed as *not
  analysed* with a reason, and coverage is reported as `analysed + not analysed == total nodes`.
* **A finding is a citation, not proof of run-time behaviour.** The rules are conservative heuristics
  over the export. They can miss a defect; they are built not to invent one.
* **No finding does not mean no defect.** A clean workflow can still fail at run time, and the report
  says so on every page that carries a claims table.
* **The export is the client's data.** Run it on a redacted export; nothing in this tool writes
  outside `--out`, opens a socket, or reads a credential value.

## Layout

```
audit.py                 entry point
automation_audit/
  model.py               findings, inventory, JSON-pointer helpers, rule registry data
  n8n.py                 export parsing, graph helpers, trigger signatures, system map
  rules.py               the ten rules
  verify.py              re-derivation of every finding from the export
  report.py              Markdown and PDF report
  pdfwriter.py           dependency-free PDF writer (reused from ClaimCheck)
fixtures/                the planted estate, the clean control, the client claims
tests/                   unittest suite
tools/acceptance.py      15 named acceptance checks
```

## Licence

MIT. The PDF writer is reused from ClaimCheck, also MIT, written for the same reason: a report has to
be produced on a machine with nothing installed.