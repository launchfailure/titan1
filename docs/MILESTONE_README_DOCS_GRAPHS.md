# README, Documentation, and Intelligence Graph Milestone

This milestone coordinates four changes:

1. Replace the repository landing page with README v2.
2. Add architecture and subsystem documentation under `docs/`.
3. Add reusable Mermaid source diagrams under `docs/diagrams/`.
4. Add backward-compatible Intelligence annotations to JSON, DOT, and Mermaid graph exports.

## Compatibility

The `GraphExporter` constructor retains its original `nodes` positional argument and adds optional `intelligence`. Without Intelligence, JSON nodes and metadata retain their prior shape, DOT retains existing content-based styling, and Mermaid retains its original flow structure. Intelligence fields are additive.

## Validation

Run focused suites first, remove the extracted package directory, then run the complete test suite from a clean repository root.
