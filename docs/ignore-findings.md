# Ignoring findings

Findings can be ignored using a YAML configuration file.

> [!IMPORTANT]
> When a finding is ignored, it is removed from consideration for threshold
> checks but it's not discarded. The report created by the plugin adds details
> to the results, giving high visibility on the configured behaviour.
>
> See examples [below](#rendering).

## File naming

### Repository level

Create a file **in the repository** with one of the following names:

- `.ecr-scan-results-ignore.y[a]ml`
- `.buildkite/ecr-scan-results-ignore.y[a]ml`
- `buildkite/ecr-scan-results-ignore.y[a]ml`

Files are load in this order: definitions loaded first take precedence.

### Agent level

A configuration file **on the agent itself** in the
`/etc/ecr-scan-results-buildkite-plugin` directory allows for organizations to
ship agents with plugin configuration that centrally manages findings that can
be ignored.

_Agent configuration takes precedence over repository configuration._

## File format

```yaml
ignores:
  - id: CVE-2023-100
  - id: CVE-2023-200
    until: 2023-12-31
    reason: |
      Allowing 2 weeks for [base image](https://google.com) to update. Markdown is allowed!
  - id: CVE-2023-300
```

- each element must have at least the `id` field: this is effectively the
  primary key and is used to match duplicates.
- the `until` field defines the expiry of this ignore entry. This allows a team
  time to respond while temporarily allowing builds to continue.
- the `reason` field gives a justification that is rendered in the annotation
  for greater visibility. Including the "why" in this field is highly
  recommended.

> [!NOTE]
> So:
>
> - agent configuration is more important than repository configuration
> - multiple repository configuration files are overlaid in priority order
> - expired entries are eliminated early and do not override anything
> - entries are matched by `id` only
>
> Unsure if the configuration is taking effect? Check the plugin output.
> Active ignore definitions are listed at the start of the plugin's execution.

## Rendering

The summary counts at the top show the number of ignored findings:

<img src="img/summary-counts.png" alt="summary counts" width="60%">

Ignored findings are separated from the main list and shown at the bottom:

<img src="img/ignore-finding-list.png" alt="ignored finding list" width="60%">

If a reason for ignoring a finding is provided, it's made available by expanding the Until date:

<img src="img/ignore-reason.png" alt="ignored reason" width="60%">
