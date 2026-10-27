-- Real columns for the placeholder assets/identities tables (spec 6.5). Both were empty and
-- unused until now. Hosts and users are stored lower-cased, as the correlator compares them.
DROP TABLE assets;
DROP TABLE identities;

CREATE TABLE assets (
    environment TEXT NOT NULL,
    host        TEXT NOT NULL,
    criticality INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 3),
    owner       TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (environment, host)
);

CREATE TABLE identities (
    environment TEXT NOT NULL,
    user        TEXT NOT NULL,
    privileged  INTEGER NOT NULL CHECK (privileged IN (0, 1)),
    department  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (environment, user)
);
