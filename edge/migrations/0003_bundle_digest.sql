-- The trusted publish stage pushes the assembled bundle tar as the
-- `<tag>.bundle` layer; the edge streams that blob by digest instead of
-- assembling a tar from the artifact's layers. Rows registered before this
-- carry an empty digest and are pruned the first time they are served.
ALTER TABLE artifacts ADD COLUMN bundle_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE artifacts ADD COLUMN bundle_size INTEGER NOT NULL DEFAULT 0;
