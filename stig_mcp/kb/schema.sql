CREATE TABLE techniques (
    technique_id     TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    is_subtechnique  INTEGER NOT NULL DEFAULT 0,
    parent_id        TEXT REFERENCES techniques(technique_id),
    tactics          TEXT,
    attack_version   TEXT,
    created          TEXT,
    ctid_status      TEXT NOT NULL DEFAULT 'absent'
                     CHECK (ctid_status IN ('mapped', 'non_mappable', 'absent'))
);

CREATE TABLE controls (
    control_id         TEXT PRIMARY KEY,
    name               TEXT,
    family             TEXT,
    is_enhancement     INTEGER NOT NULL DEFAULT 0,
    parent_control_id  TEXT REFERENCES controls(control_id)
);

CREATE TABLE ccis (
    cci_id      TEXT PRIMARY KEY,
    definition  TEXT
);

CREATE TABLE stigs (
    stig_id            TEXT NOT NULL,
    version            TEXT NOT NULL,
    title              TEXT NOT NULL,
    benchmark_id       TEXT,
    release_info       TEXT,
    release_label      TEXT,
    product_keywords   TEXT,
    origin             TEXT NOT NULL,
    source_artifact    TEXT NOT NULL,
    source_member      TEXT,
    xccdf_status       TEXT,
    xccdf_status_date  TEXT,
    PRIMARY KEY (stig_id, version)
);

CREATE TABLE stig_rules (
    rule_id         TEXT PRIMARY KEY,
    group_id        TEXT,
    stig_id         TEXT NOT NULL,
    stig_version    TEXT NOT NULL,
    severity_cat    TEXT NOT NULL,
    severity_level  TEXT NOT NULL,
    title           TEXT,
    discussion      TEXT,
    fix_text        TEXT,
    check_text      TEXT,
    FOREIGN KEY (stig_id, stig_version) REFERENCES stigs(stig_id, version)
);

CREATE TABLE actors (
    actor_id  TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    aliases   TEXT
);

CREATE TABLE technique_control (
    technique_id    TEXT NOT NULL REFERENCES techniques(technique_id),
    control_id      TEXT NOT NULL REFERENCES controls(control_id),
    source          TEXT NOT NULL,
    source_version  TEXT,
    suppressed      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (technique_id, control_id, source)
);

CREATE TABLE cci_control (
    cci_id          TEXT NOT NULL REFERENCES ccis(cci_id),
    control_id      TEXT NOT NULL REFERENCES controls(control_id),
    source_version  TEXT,
    PRIMARY KEY (cci_id, control_id)
);

CREATE TABLE rule_cci (
    rule_id  TEXT NOT NULL REFERENCES stig_rules(rule_id),
    cci_id   TEXT NOT NULL REFERENCES ccis(cci_id),
    PRIMARY KEY (rule_id, cci_id)
);

CREATE TABLE actor_technique (
    actor_id        TEXT NOT NULL REFERENCES actors(actor_id),
    technique_id    TEXT NOT NULL REFERENCES techniques(technique_id),
    source          TEXT,
    source_version  TEXT,
    PRIMARY KEY (actor_id, technique_id)
);

CREATE TABLE ingest_meta (
    source_name           TEXT PRIMARY KEY,
    source_version        TEXT,
    artifact_url_or_file  TEXT,
    ingested_at           TEXT,
    schema_version        TEXT
);

CREATE TABLE revoked_technique (
    revoked_id      TEXT PRIMARY KEY,
    replacement_id  TEXT NOT NULL REFERENCES techniques(technique_id),
    revoked_name    TEXT,
    source_version  TEXT
);

CREATE TABLE source_files (
    name    TEXT PRIMARY KEY,
    sha256  TEXT NOT NULL CHECK (length(sha256) = 64),
    size    INTEGER NOT NULL
);

CREATE TABLE notices (
    name  TEXT PRIMARY KEY,
    text  TEXT NOT NULL
);

CREATE TABLE mitigations (
    mitigation_id  TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    description    TEXT
);

CREATE TABLE technique_mitigation (
    technique_id   TEXT NOT NULL REFERENCES techniques(technique_id),
    mitigation_id  TEXT NOT NULL REFERENCES mitigations(mitigation_id),
    description    TEXT,
    PRIMARY KEY (technique_id, mitigation_id)
);

CREATE TABLE detection_strategies (
    detection_strategy_id  TEXT PRIMARY KEY,
    technique_id           TEXT NOT NULL REFERENCES techniques(technique_id),
    name                   TEXT NOT NULL
);

CREATE TABLE data_components (
    data_component_id  TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    description        TEXT
);

-- platforms is a comma string like techniques.tactics; mutable_elements is JSON because
-- its descriptions contain commas and nothing queries it.
CREATE TABLE analytics (
    analytic_id            TEXT PRIMARY KEY,
    detection_strategy_id  TEXT NOT NULL REFERENCES detection_strategies(detection_strategy_id),
    name                   TEXT,
    description            TEXT,
    platforms              TEXT,
    mutable_elements       TEXT
);

-- channel defaults to '' rather than NULL so the primary key holds for a source with none.
CREATE TABLE analytic_log_sources (
    analytic_id        TEXT NOT NULL REFERENCES analytics(analytic_id),
    name               TEXT NOT NULL,
    channel            TEXT NOT NULL DEFAULT '',
    data_component_id  TEXT REFERENCES data_components(data_component_id),
    PRIMARY KEY (analytic_id, name, channel)
);

CREATE INDEX idx_stig_rules_stig ON stig_rules(stig_id, stig_version);
CREATE INDEX idx_stig_rules_sev  ON stig_rules(severity_cat);
CREATE INDEX idx_tc_control      ON technique_control(control_id);
CREATE INDEX idx_ccictl_control  ON cci_control(control_id);
CREATE INDEX idx_rulecci_cci     ON rule_cci(cci_id);
CREATE INDEX idx_at_technique    ON actor_technique(technique_id);
CREATE INDEX idx_tm_technique    ON technique_mitigation(technique_id);
CREATE INDEX idx_ds_technique    ON detection_strategies(technique_id);
CREATE INDEX idx_als_name        ON analytic_log_sources(name);
