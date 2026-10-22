<!-- stow-builds-digest -->
The daily record of failed `build-batch.yml` legs (stow#778):
`build-failure-digest.yml` runs `stow-admin builds digest` once a day.
A window with failed legs posts one comment grouping them by class —
the same verdict/infrastructure classification the manual preheat
driver uses — then crate, version and target, with the failing step,
the failed job's first error line and the run link. A clean window
sends nothing and closes this issue.
