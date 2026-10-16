# Log-Based Intrusion Detection System

A compact Python utility that parses Linux authentication logs, common combined-format web access logs, and CSV event records. It applies configurable rules and batch-count anomaly checks, then emits JSON alerts. Follow mode watches appended lines for rule-based alerts.

## Features

- Parsers for auth.log, Apache/Nginx combined access format, and CSV.
- Rules for failed logins, suspicious user-agent strings, configured unusual ports, and HTTP denials.
- Batch thresholds for repeated failures and event volume.
- JSON alert output and appended-file monitoring.

## Installation

Python 3.10+; standard library only.

```sh
python -m venv .venv
. .venv/bin/activate
python main.py --help
```

`config.yaml` uses JSON syntax, which is valid YAML, so no YAML package is required.

## Usage

```sh
python main.py sample_logs/auth.log --type auth
python main.py sample_logs/access.log --type access --output reports/access-alerts.json
python main.py sample_logs/events.csv --type csv
python main.py /var/log/auth.log --type auth --follow
```

Example alert summary for the bundled auth.log fixture:

```json
{
  "events_analyzed": 3,
  "alerts": [{"rule": "failed_login", "severity": "medium"}, {"rule": "failed_login", "severity": "medium"}],
  "summary": {"medium": 2}
}
```

## Project Structure

```text
parsers/       Auth, web access, CSV parsers
detectors/     Rule and batch anomaly detectors
sample_logs/   Small safe fixtures
reports/       Destination for generated reports
config.yaml    Detection terms and thresholds
main.py        CLI
```

## Legal & Ethical Use

Analyze only logs you are authorized to access and process. Logs can contain usernames, IP addresses, session details, and other sensitive data: store reports securely, restrict access, and follow applicable retention and privacy requirements. Alerts are investigation leads and should be reviewed in context before action is taken. Do not use this tool to monitor people or systems outside an approved operational or incident-response purpose.

## Limitations

The parsers target common formats and skip malformed records. Detection is intentionally transparent and rule-based; it does not establish malicious intent. Batch spike detection groups failed logins by host/IP label and uses a fixed threshold, not a trained baseline. Follow mode emits rule alerts for newly appended records; it does not recompute batch anomaly thresholds. Rotation and truncation handling are not implemented.

## Tests

`python -m unittest discover -s tests -v`
