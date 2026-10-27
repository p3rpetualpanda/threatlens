# Correlation: how alerts become incidents

Rules (spec section 6.4): alerts in the same environment link when they share a `host`, `user`
or `src_ip` and their time ranges are within the link window. `dst_ip` and `process` never
link. Incidents are the connected groups. Settings live in `config/correlation.yml`.

Stoplists stop common values from joining everything into one incident:

- Config: users `system`, `local service`, `network service`, `anonymous logon`, `-`, and any
  name ending in `$`.
- Automatic: a value in more than 20% of an environment's alerts, once the environment has at
  least 50 alerts. `partition` returns which values were dropped.

Analyst state: a resolved incident is frozen (new linked alerts open a new incident that points
back with `related_incident`); a touched incident never splits; bridging merges keep the oldest
(touched first) and move comments and playbook rows; incident ids never change.

## Measurement

`scripts/measure_correlation.py DB` on beacon's full export (544 findings, 11 environments):

| Setting | Incidents | Largest | Single-alert |
|---|---|---|---|
| 2 h window, 20% auto-stoplist (shipped) | 478 | 7 | 435 |
| 6 h, 20% | 400 | 8 | 322 |
| 12 h, 20% | 305 | 39 | 224 |
| 24 h, 20% | 216 | 65 | 147 |

Acceptance (no incident above 50 alerts) holds at the shipped settings: the largest has 7.
515 of the 544 alerts are R20 SSH brute-force attempts from 173 source IPs against one host
over four weeks, so most sources appear once or a few times far apart, and that one host is
stopped by the automatic stoplist. The low reduction there (515 to 466) reflects the data, not a
bug. Wider windows group repeat sources but create larger incidents with no ground truth to say
they are right, so the spec defaults stay. Revisit with labelled data.
