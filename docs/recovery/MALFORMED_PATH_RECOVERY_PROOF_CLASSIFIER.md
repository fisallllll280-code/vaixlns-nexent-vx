# Malformed Git Path Recovery — proof_classifier

A malformed tree entry embedded the complete Python source in the Git path after `src/vaixlns/core/proof_classifier.py`, causing Linux CI checkout to fail with `File name too long` before tests ran.

Recovery record:
- malformed blob SHA: `8c592d1da6425203084c90fe2d5fb2a4f9bdf5d6`
- restored canonical source: `src/vaixlns/core/proof_classifier.py`
- source semantics preserved in the corrected file
- malformed identity retained here for zero-loss lineage
