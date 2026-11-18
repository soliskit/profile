# Offline isolation qualification

This is an inert first test of a possible dependency-update boundary. It never starts the updater, updates a package, creates a Git commit or ref, or publishes anything. The existing scheduled dependency workflow is unchanged. This is not a claim that dependency automation is protected.

The pull-request workflow runs a fixed fixture on a standard Ubuntu runner with read-only repository permission, no persisted checkout credential and a 20-minute limit. It pulls an immutable official Node 26.13.0 Linux amd64 image, creates one non-root, read-only, capability-dropped container with no network or host mounts, inspects the actual engine configuration, runs the fixture and confirms container absence after removal. It does not give the container a credential, runner environment, command file or publisher endpoint.

Raw fixture output is saved as data and never replayed into the workflow log. The fixed host-generated source is delivered as a direct Node `--eval` argument, never through a shell, file copy, bind mount or image build. Before start, the coordinator compares actual `Config.Entrypoint` and `Config.Cmd` against the exact executable and source it generated. Source authority comes from that host-side comparison, not from a script file being read-only. The binary and root write-refusal checks are only write-denial observations. Nonzero engine commands and timeouts retain bounded raw stdout/stderr as artifact data, never as workflow framing or exception text.

Raw fixture output is saved as data and never replayed into the workflow log. It includes a synthetic workflow-command line to exercise that distinction. Artifacts contain only this fixed fixture's observations, engine/container state and cleanup results, not a credential or actual user source data. Artifact retention is seven days.

A timed-out or failed create is not retried. Exact-name cleanup is armed before the create attempt. Cleanup uses one removal attempt and an independent absence check, but an ambiguous daemon request might complete after that check. The original run still fails and remains on hold, even if immediate absence is observed. A cleanup record alone is not a passing run.

Local tests cover the configuration checks, bounded regular-file archive parser and ambiguous-create cleanup. They do not execute Docker or prove a runtime boundary. The parser is not yet connected to a package-output transfer route. Current stdout capture is suitable only for this fixed bounded fixture, not arbitrary hostile package output.

Failed network connections are only failed-connect observations, not denial proof without a reachable controlled listener and positive control. The host PID signal check is supplemental because a PID number could collide inside another namespace. Actual container configuration, controlled network tests and namespace identity need real-runner evidence. Containers are not a guarantee against kernel or engine vulnerabilities.

Not yet covered: original Lefthook staged-file execution in a sealed sandbox, npm/product checks inside a container, restricted registry egress, candidate reconstruction, metadata creation, publishing, or activation of an updater. Those require separate exact implementation and review within the existing prevention work.

The exact image is pinned in `offline_probe.py`. Its official Node image index, selected platform manifest and config were retrieved anonymously and their content hashes checked before this candidate was prepared. This establishes immutable acquisition, not image safety. The runtime fixture checks the Node version again.
