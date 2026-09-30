-- Provider health, decided by probes and by explicit operator decisions.
--
-- The state is a separate column from the enabled status rather than a new
-- status value, because an operator's decision and a probe's observation are
-- different facts. Collapsing them would let a probe undo a human decision.
--
-- A row that predates this migration reads as healthy, which is the state a
-- provider starts in and the state it must be in for a deployment to behave
-- exactly as it did before health existed. Health is opt-in: a provider is only
-- ever isolated by a probe somebody configured, so no existing deployment is
-- silently taken out of service by an upgrade.

ALTER TABLE provider
    ADD COLUMN health TEXT NOT NULL DEFAULT 'healthy'
        CHECK (health IN ('healthy', 'isolated', 'maintenance'));

-- The probe configuration, all of it optional and absent by default.
--
-- Health is opt-in: a provider with no probe path is never probed and is never
-- isolated by this subsystem, so an upgrade cannot silently take an existing
-- deployment out of service.
--
-- The stored value is a path, not a URL, because a probe is always resolved
-- against the provider's own endpoint origin. Storing a URL would let a probe
-- outlive the endpoint it was derived from, and would persist a query string
-- that has no business being stored.
--
-- The four values are all-or-nothing: a threshold, interval, or timeout that is
-- not a positive integer is refused, because each would make probing
-- undecidable rather than bound it.

ALTER TABLE provider
    ADD COLUMN probe_path TEXT,
    ADD COLUMN probe_interval_ms BIGINT
        CHECK (probe_interval_ms IS NULL OR (probe_interval_ms > 0 AND probe_interval_ms <= 86400000)),
    ADD COLUMN probe_timeout_ms BIGINT
        CHECK (probe_timeout_ms IS NULL OR (probe_timeout_ms > 0 AND probe_timeout_ms <= 86400000)),
    ADD COLUMN probe_failure_threshold BIGINT
        CHECK (probe_failure_threshold IS NULL OR (probe_failure_threshold > 0 AND probe_failure_threshold <= 1000));

ALTER TABLE provider
    ADD CONSTRAINT provider_probe_all_or_none CHECK (
        (probe_path IS NULL
            AND probe_interval_ms IS NULL
            AND probe_timeout_ms IS NULL
            AND probe_failure_threshold IS NULL)
        OR
        (probe_path IS NOT NULL
            AND probe_interval_ms IS NOT NULL
            AND probe_timeout_ms IS NOT NULL
            AND probe_failure_threshold IS NOT NULL)
    );
