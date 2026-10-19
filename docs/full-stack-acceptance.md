# Full-stack acceptance

Windows and Ubuntu packaging jobs report compilation, package and startup
results. Overall product acceptance is the separate `full-stack-acceptance`
check on main. It fails when `04 SteamOS` is absent, missing for that commit,
pending, failed or skipped. An older successful run or attempt cannot satisfy it.

The check reads GitHub metadata only. It requires the latest exact-main
`04 SteamOS` attempt, its successful all-VM/per-executable job and both producer
binding and actual-acceptance steps, plus that attempt's retained acceptance
metadata. The SteamOS workflow owns validation of the underlying image,
virtual USB write/full readback, installation/boot and recovery evidence for
every Windows, Ubuntu and macOS artifact and all required VM identities.

It runs automatically on main pushes and after `04 SteamOS` completes. Manual
reevaluation is also available. A completion for an older commit fails instead
of making newer main green. It has read-only permissions and launches no VM,
SSH controller, image writer, retry or physical-media operation. Source PRs
retain their source checks without depending on an impossible pre-merge
protected-main acceptance run. Repository rules and governance are unchanged.

Until the real SteamOS integration is published and its actual tests pass,
the expected main result is failed acceptance with the concrete missing result.
`tests/test_full_stack_acceptance.py` verifies this decision policy; its passing
tests do not constitute product or hardware acceptance.
