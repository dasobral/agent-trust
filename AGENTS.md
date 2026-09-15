# agent-trust work rules
Read only your assigned brief, contracts, and relevant files. Do not spawn agents.
Test authors own tests; implementers must not weaken or rewrite their assertions.
Record genuine red/green commands and exit codes; distinguish behavioral failure from build/setup failure.
No production cryptographic shortcuts, simulated MLS presented as real, or security claims from booleans alone.
Only the coordinator commits, integrates, and packages. Do not touch other agents' owned files.
Never put private keys, real credentials, or live endpoint details in evidence.
Keep source and documentation portable; no absolute workspace paths in runtime commands.
