# Decisions

Why ThreatLens is built the way it is. Each line is a call that could have gone the other way.

- **No detection here.** Beacon detects; ThreatLens takes its findings and handles them. One
  contract between them (`contracts/`, OCSF Detection Finding with beacon detail under
  `unmapped`), vendored and checked byte-for-byte against beacon's copy.
- **SQLite with numbered migrations, not Postgres.** One file, easy to back up and to run in a
  container. WAL mode. The cost is one writer at a time; fine for one team's queue.
- **Jinja2 pages, no JavaScript.** Plain forms, a CSRF field and an Origin check. Less to attack
  and nothing to build.
- **Python 3.12+** to match beacon.
- **Correlation:** alerts link on a shared host, user or source IP within 2 hours, with an
  automatic stoplist for entities that touch too many alerts. There is no cap on how long an
  incident can run, so grouping does not depend on the order alerts arrive. Tuned on the measured
  demo output (docs/correlation.md). On the SSH brute-force data it barely groups (1.1 alerts per
  incident), because each source address is a different attacker.
- **Risk score:** hand-set weights in `config/risk.yml`, every point explained on the page. It is
  a triage order, not a probability.
- **Incidents:** resolved ones are frozen, touched ones never split on their own, merges keep
  all analyst work, and findings beacon stops producing are kept.
- **Analysts can take unowned incidents** themselves, so MTTA does not wait for a lead.
- **Verdicts go back as a separate CSV** applied with `beacon detect --verdicts`. They fill gaps
  and never override beacon's own; benign true positives do not move precision.
- **Audit log:** hash-chained and append-only in SQL. It catches accidental and naive edits. A
  keyed anchor kept off the machine catches a full rewrite. Someone who controls the host can
  still defeat it (docs/threat-model.md).
- **IP context uses the standard library only.** No lookups, no data leaves the machine.
- **No hosted demo.** `docker compose up` and screenshots instead. The demo admin password is
  random per first start and printed once in the container log.
- **Terraform:** not done. It was optional and nothing here needs a cloud host.
