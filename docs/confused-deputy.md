# Invocation provenance and confused-deputy protection

The authority kernel treats an agent that executes an operation on behalf of
another agent as a constrained executor, not as a replacement for the
originating authority.

An `invoke` command creates an invocation capability in the durable APF state.
The APF records the origin, executor, permitted rights, permitted resources,
and optional parent invocation. The returned invocation identifier is only
usable by the recorded executor when allocating an operation. It is not a
caller-selected `original_agent` field.

For a release carrying an invocation, the APF requires all of the following:

* the executor is the authenticated actor for the operation;
* the requested right and frozen resource are present in the invocation;
* the originating principal still has that right under the current delegation
  and revocation state;
* every parent invocation is valid and its executor/authority relationship is
  intact; and
* the executor independently has the requested right and the existing release
  frontier/cover checks pass.

Content releases may request `read` or `write`; administrative rights such as
`admin` and `admit` are not valid release rights.

Consequently, effective authority is bounded by the intersection of executor
authority and invocation authority. An intermediary cannot widen rights or
resources because a child invocation is persisted by the APF and a later hop
must request a subset of its parent invocation. The parent invocation remains
part of the validation chain and cannot be stripped or replaced by the
intermediary.

An operation without an invocation remains an independent operation by its
executor and uses the existing authorization behavior. Thus a privileged
parent can still perform its own authorized write, while a child with only
`read` cannot cause that parent to perform `write`.

Origin revocation is checked again at release time. Existing read revocation
also retains its stronger group-fencing behavior, so a revoked origin can be
rejected either by the invocation-authority check or by the existing read
fence. Invocation records are included in checkpoints and release results
identify the executor, invocation, effective right, and resource for audit.

This mechanism does not detect prompt injection or semantic maliciousness. It
enforces only the narrower property that routing a request through a more
privileged agent cannot increase the authority available to the request.
