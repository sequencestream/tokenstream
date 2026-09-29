-- Layered admission bounds on the provider and the credential.
--
-- Each bound is optional and NULL means unbounded, so an existing deployment
-- keeps exactly the behaviour it had. A bound is never zero: zero would forbid
-- all traffic through that provider or credential rather than bound it, and is
-- refused before a value can reach this table.

ALTER TABLE provider
    ADD COLUMN max_concurrent_requests INTEGER
        CHECK (max_concurrent_requests IS NULL OR max_concurrent_requests > 0),
    ADD COLUMN max_requests_per_second INTEGER
        CHECK (max_requests_per_second IS NULL OR max_requests_per_second > 0);

ALTER TABLE api_key
    ADD COLUMN max_concurrent_requests INTEGER
        CHECK (max_concurrent_requests IS NULL OR max_concurrent_requests > 0),
    ADD COLUMN max_requests_per_second INTEGER
        CHECK (max_requests_per_second IS NULL OR max_requests_per_second > 0),
    ADD COLUMN max_websockets INTEGER
        CHECK (max_websockets IS NULL OR max_websockets > 0);
