CREATE TRIGGER reject_cache_output
BEFORE INSERT ON artifact_cache_outputs
BEGIN
    SELECT RAISE(ABORT, 'injected output write failure');
END;
