# Demo data

`beacon_findings.jsonl` is a full `beacon export-alerts` run: 544 findings in contract v1
(`contracts/detection-finding-v1.schema.json`), made from beacon commit `34a5284` (beacon PR 12)
with all 12 rules.

| Environment (`unmapped.environment`) | Findings |
|---|---|
| `loghub_openssh` | 515 |
| `apt29_day2_host` | 8 |
| `apt29_day1_host` | 4 |
| `lsass_dump_comsvcs`, `lsass_dump_dumpert_syscalls`, `rdp_taskmanager_lsass_dump`, `run_keys_empire` | 3 each |
| `schtask_create_remote` | 2 |
| `psexec_empire`, `service_mod_fax`, `wmi_exec_empire` | 1 each |

## Sources and licences

- OTRF Security-Datasets (APT29 evaluation host logs and the Empire, Covenant and other lab
  datasets): MIT licence. https://github.com/OTRF/Security-Datasets
- Loghub OpenSSH log: CC BY 4.0, attribution required. https://github.com/logpai/loghub
  It contains real public IP addresses that are already public in that dataset. ThreatLens shows
  them and never looks them up.

## Regenerate

In the beacon repo, after `make load` and `make detect`:

```bash
uv run beacon export-alerts --out "../ThreatLens - All/ThreatLens-fresh/demo/beacon_findings.jsonl"
```

The file is byte-identical when beacon's database has not changed. Re-export after every new
beacon rule, and update the counts above from `scripts/measure_correlation.py` and the file.
