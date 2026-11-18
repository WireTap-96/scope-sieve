# ScopeSieve

An offline scope-hygiene tool for authorized security work. It validates a **local CSV asset inventory** for malformed entries, duplicates, missing ownership/authorization details, expired authorization dates, and stale reviews. It does not discover assets, resolve DNS, or contact any host.

## Requirements and use

Python 3.9+; standard library only.

```bash
python -m scopesieve.cli sample-scope.csv
```

Required CSV columns: `asset`, `owner`, `environment`, `authorization_reference`, `authorized_until`, `last_reviewed`. Assets must be literal IP addresses or hostnames; wildcard and URL entries are rejected. Dates use `YYYY-MM-DD`.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limitations and privacy

- A `ready-for-human-review` result only means the inventory passed these format checks; it is not legal authorization or proof of ownership.
- Confirm scope and permission with the system owner before any assessment.
- The program reads a local file only and makes no network requests. Do not commit real client inventories or confidential scope documents.
- Initial starter implementation created with AI assistance; review and extend it before representing the work as your own.
