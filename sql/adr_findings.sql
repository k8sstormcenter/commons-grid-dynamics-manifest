CREATE TABLE forensic_db.adr_findings
(
    `event_time` DateTime64(9),
    `hostname` String,
    `kpi_time` DateTime64(9),
    `cluster` String,
    `namespace` String,
    `iteration` Int64,
    `tool` String,
    `adr` String,
    `adr_summary` String,
    `title` String,
    `status` String,
    `violations` Int64,
    `counted` Bool DEFAULT true,
    `note` String,
    `owner` String,
    `proof` String,
    `source` String,
    `rule` String,
    `workload` String,
    `decision_broken` String,
    `observed` String,
    `fix` String
)
ENGINE = MergeTree
ORDER BY (namespace, iteration, adr)
SETTINGS index_granularity = 8192
;
