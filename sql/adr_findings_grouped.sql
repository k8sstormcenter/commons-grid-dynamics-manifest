CREATE VIEW forensic_db.adr_findings_grouped
(
    `event_time` DateTime64(9),
    `hostname` String,
    `kpi_time` DateTime64(9),
    `iteration` Int64,
    `tool` String,
    `adr` String,
    `adr_summary` String,
    `status` String,
    `violations` Int64,
    `counted` Bool,
    `owner` String,
    `decision_broken` String,
    `affected` String,
    `events` UInt64,
    `observed` String,
    `note` String,
    `fix` String,
    `proof` String
)
AS SELECT
    max(event_time) AS event_time,
    any(hostname) AS hostname,
    max(kpi_time) AS kpi_time,
    iteration,
    tool,
    adr,
    any(adr_summary) AS adr_summary,
    any(status) AS status,
    max(violations) AS violations,
    max(counted) AS counted,
    any(owner) AS owner,
    decision_broken,
    arrayStringConcat(arraySort(groupUniqArray(workload)), ', ') AS affected,
    count() AS events,
    any(observed) AS observed,
    any(note) AS note,
    any(fix) AS fix,
    any(proof) AS proof
FROM forensic_db.adr_findings
GROUP BY
    iteration,
    tool,
    adr,
    decision_broken
;
