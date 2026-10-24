# Findings on the stack

Points found while building the testbed on top of agent-trust `9af877c`,
OpenMLS fork `dd33278` and openmls-qrand `a102450`. None blocks E1. Each names
what the testbed does today and a proposed change upstream.

| # | Repository | Finding | Testbed today | Proposal |
|---|---|---|---|---|
| F-1 | agent-trust | A worker has no routed request to read the policy state (frontier, `policy_revision`, roster, grants). It needs these values to build a release cover and digest (§5.3 step 2). The lab reads `Adapter::checkpoint`, which is a trusted local read. | The APF service exposes `GET /v1/state`, a projection of the checkpoint. It is advisory: the kernel re-checks every value. | Add a read-only routed command (for example `policy_view`) for roster members, so the view is authenticated and traced like every other request. |
| F-2 | agent-trust | `LabEntropy::provider()` always uses `MemoryStorage`. A networked agent therefore loses its MLS state on restart, and the B1–B8 crash barriers can only be exercised in-process. | Agents are not restartable; the APF is (its adapter state is on disk). | Add a provider constructor with `SqliteStorageProvider` over the same entropy source, for example `LabEntropy::provider_with_storage(path)`. |
| F-3 | agent-trust | Commit distribution is outside the contract. After `submit_commit` only the committer holds the commit bytes and the ack. If it stops before it publishes them, the group cannot move (barrier B7 at group scale). | The committer appends `{commit, ack}` to the relay's ordered log. | Let the adapter keep the canonical `(commit, ack)` log it already sequences and serve it to members, so a committer crash cannot strand the group. |
| F-4 | agent-trust | `ClientEndpoint` has no accessor for "this member is still active". After applying a repair ack, a removed member is detected only because `confirmation()` fails with `group inactive`. | The sidecar uses that failure. | Add `ClientEndpoint::is_active()`. |
| F-5 | agent-trust | The C-37 export (`export_v2_trace`) lives in `lab` and reads the adapter files directly. It works under the APF service's lock, but it is an offline reader of a live directory. | The APF service holds its lock during the export. | Move the export next to `Adapter` (`Adapter::export_trace(&self)`), on the open connections. |
| F-6 | agent-trust | A relay duplicate is refused by MLS (`undecryptable`) before the kernel's `replay` check, so the honest path never exercises `replay`. This is correct, and C-39 allows it. | `check.rejected` accepts duplicate codes after the first copy. | None; documented for readers of the traces. |
