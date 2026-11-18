# detections

Detection rules for the home lab as code: versioned, reviewed, tested and deployed from Git
instead of hand-edited on the Wazuh manager. Flagship 2 of the Security Automation Roadmap.
Wazuh itself is deployed by [home_lab](https://github.com/bsloan334/home_lab).

## Layout

```
rules/sigma/<platform>/   Sigma rules (the default format)
rules/wazuh/              native Wazuh rules, for what Sigma can't express
rules/suricata/           Suricata rules for the network sensor
fixtures/<rule id>/       match.log (must fire) and no_match.log (normal lab logs, must stay quiet)
tools/check_rules.py      the checks every pull request must pass
```

## Writing a rule

1. Add a Sigma rule under `rules/sigma/`, with a new UUID as its `id` and at least one ATT&CK
   technique tag (`attack.t1110.001`).
2. Add `fixtures/<id>/match.log` with log lines it must catch, and `no_match.log` with normal
   lab traffic it must ignore. Real lab logs are best for `no_match.log`.
3. `python tools/check_rules.py` and `python -m pytest`.

## What CI does now, and what comes next

| Step | Status |
|---|---|
| Every rule parses with pySigma, has id, status, level, description and an ATT&CK technique | built |
| Every rule has match and no-match fixtures (`--strict` also fails on fixtures still marked as needed) | built |
| Convert Sigma to Wazuh rules | next: pick the pySigma backend or write a small one |
| Replay fixtures through a throwaway Wazuh manager (`wazuh-logtest`) and fail on a miss or a false positive | next: the hard part |
| Merge to main deploys through Ansible and records which rule versions are live | after replay works |
| ATT&CK coverage report and a weekly noise ranking from production alerts | later |

Until replay exists, the fixtures are checked for presence, not run.

## Starter rules

- `ssh_bruteforce_from_lab_vlan`: failed SSH logins from the isolated Lab VLAN.
- `sudoers_changed`: sudoers changed by anything other than Ansible (fixtures still needed).

## Set up

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python tools/check_rules.py && python -m pytest
```
