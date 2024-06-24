# ECR Scan Results Buildkite Plugin

Buildkite plugin to retrieve ECR scan results from AWS's ECR image scanning
service. By default the plugin will cause the step to fail if there are critical
or high vulnerabilities reported. Specific vulnerabilities can be ignored via [a
configuration file][ignore-findings], and there are configurable thresholds on
absolute numbers of allowed critical and high vulnerabilities.

> [!WARNING]
> By default, this plugin will only fail the build if the thresholds are
> exceeded. Failing to read configuration or to download scan results are only
> considered blocking failures if `fail-build-on-plugin-failure` is explicitly
> set to `true`.
>
> When configuring the plugin, you can either:
> - Check the plugin output to ensure that scan results are being downloaded as
>   expected, or
> - Set `fail-build-on-plugin-failure` to `true` to raise the visibility of
>   problems with fetching scan results.
>
> If blocking on configuration or retrieval failures is desired for your use
> case, see the `fail-build-on-plugin-failure` configuration item below.

## Rendering

The plugin shows a detailed summary of the vulnerability findings in the scanned image using data pulled from AWS ECR. The summary is rendered as a Buildkite [build annotation](https://buildkite.com/docs/agent/v3/cli-annotate).

<figure>
<figcaption>
The default view summarizes the number of findings in the scan, hiding details behind an expanding element.
</figcaption>
<img src="docs/img/eg-success-collapsed.png" alt="example of successful check annotation with collapsed results table" width="80%" align="center">
</figure>

<figure>
<figcaption>
When a threshold is exceeded, the annotation is rendered as an error.
</figcaption>
<img src="docs/img/eg-failed-collapsed.png" alt="example of failed check annotation with collapsed results table" width="80%" align="center">
</figure>

<figure>
<figcaption>
The details view can be expanded, showing a table of the vulnerability findings from the scan. Findings link to the CVE database in most cases. The CVSS vector links to the <a href="https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV%3AN%2FAC%3AL%2FPR%3AN%2FUI%3AN%2FS%3AU%2FC%3AN%2FI%3AN%2FA%3AH&version=3.1">CVSS calculator</a>, allowing for exploration of the potential impact and enabling environmental scoring.
</figcaption>
<img src="docs/img/eg-success-expanded.png" alt="example of successful check annotation with collapsed results table" width="80%" align="center">
</figure>

<figure>
<figcaption>
Multi-platform images (image list manifests) are supported. Point the plugin at the tag for the manifest, and the plugin will retrieve and merge results for all linked images.
</figcaption>
<img src="docs/img/eg-multi-platform.png" alt="example of multi-platform image report rendering" width="80%" align="center">
</figure>

## Example

Add the following lines to your `pipeline.yml`:

```yml
steps:
  - command: "command which creates an image"
    # the docker-compose plugin may be used here instead of a command
    plugins:
      - cultureamp/ecr-scan-results#v1.6.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
```

In a pipeline this will look something like:

```yml
steps:
  - label: ":docker: Build and push CDK deployment image"
    command: "bin/ci_cdk_build_and_push.sh"
    agents:
      queue: ${BUILD_AGENT}
    plugins:
      - cultureamp/aws-assume-role:
          role: ${BUILD_ROLE}
      - cultureamp/ecr-scan-results#v1.6.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
```

To [ignore specific vulnerabilities][ignore-findings], create a file name
`.ecr-scan-results-ignore.yaml` in the repository root and add entries there.
See the [documentation][ignore-findings] for more information.

```yml
# .ecr-scan-results-ignore.yaml contents
ignores:
  - id: CVE-2023-100
  - id: CVE-2023-200
    until: 2023-12-31
    reason: |
      Allowing 2 weeks for [base image](https://google.com) to update. Markdown is allowed!
  - id: CVE-2023-300
```

If you want the pipeline to pass with some vulnerabilities then set
`max-criticals` and `max-highs` like below. This pipeline will pass if there is
one critical vulenerability but fail if there are two. Similarly it will fail if
there are eleven high vulnerabilities.

```yml
steps:
  - label: ":docker: Build and push CDK deployment image"
    command: "bin/ci_cdk_build_and_push.sh"
    agents:
      queue: ${BUILD_AGENT}
    plugins:
      - cultureamp/aws-assume-role:
          role: ${BUILD_ROLE}
      - cultureamp/ecr-scan-results#v1.6.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
          max-criticals: "1"
          max-highs: "10"
```

> [!TIP]
> Prefer defining an ignore file over using thresholds, and use the `reason`
> field to explain why the vulnerability is being ignored.

## Making contributions

Contributions are welcome! See the [Contributions Guide](./CONTRIBUTING.md) for
information about running the plugin locally for testing.

## Configuration

### `image-name` (Required, string)

The name of the container image in ECR. This should be the same string that is
supplied as an arguement to the `docker push` command used to push the image to
AWS ECR. It should have the form:
`AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPOSITORY_NAME:IMAGE_TAG` with the
text in capitals replaced with the appropriate values for your environment.

### `max-criticals` (Optional, string)

If the number of critical vulnerabilities in the image exceeds this threshold
the build is failed. Defaults to 0. Use a sufficiently large number (e.g. 999)
to allow the build to always pass.

> [!IMPORTANT]
> Prefer an [ignore file][ignore-findings] over setting thresholds if
> a finding is irrelevant or time to respond is required.

### `max-highs` (Optional, string)

If the number of high vulnerabilities in the image exceeds this threshold the
build is failed. Defaults to 0. Use a sufficiently large number (e.g. 999) to
allow the build to always pass.

> [!IMPORTANT]
> Prefer an [ignore file][ignore-findings] over setting thresholds if
> a finding is irrelevant or time to respond is required.

### `image-label` (Optional, string)

When supplied, this is used to title the report annotation in place of the
repository name and tag. Useful sometimes when the repo name and tag make the
reports harder to scan visually.

### `fail-build-on-plugin-failure` (Optional, boolean. Default: false)

By default, a failure to fetch the results of an image scan will not cause the
build to fail, since scan access and availability can be flakey. The build will
fail only if the plugin finds results and the results exceed `max-criticals` or
`max-highs`.

When set to `true`, the build will fail if the plugin fails to fetch scan
results. This may results in builds failing even if the images have no
vulnerabilities at all. Useful if you prefer to pass only with a confirmed good
result.

## Requirements

### ECR Basic scanning only

This plugin supports [ECR basic scanning][basic-scanning] only. If support for
[ECR Advanced Scanning][advanced-scanning] is required, please consider
submitting a PR.

### ECR settings: Scan on Push

This plugin assumes that the ECR repository has the `ScanOnPush` setting set
(see the [AWS docs][scan-on-push] for more information). By default this is not
set on AWS ECR repositories. (Note for Culture Amp users: this is set
automatically.)

[Manual scanning][basic-scanning] support is possible: consider submitting a PR
if this is something you need.

[basic-scanning]: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-basic.html
[advanced-scanning]: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced.html
[scan-on-push]: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html

### IAM role and other security requirements

The executing role will need the following permissions on the target repository:

1. `ecr:DescribeImages`: used to translate tags into digests, and discover the
   media type of the target image.
2. `ecr:DescribeImageScanFindings`: used to retrieve the vulnerability scan
   results.
3. `ecr:BatchGetImage`, `ecr:GetAuthorizationToken`,
   `ecr:GetDownloadUrlForLayer`: allows the plugin to login and download the
   manifests of the target image(s). This gives platform information as well as
   the ability to read manifest lists of multi-platform images.

> [!NOTE]
> The plugin will not assume a role necessary to perform the above actions: this
> is required separately. If there is no valid Docker login with the target
> repository, the plugin will log in using the current AWS credentials.

## FAQ

### Unsupported image types (scratch, Windows, etc)

ECR cannot scan scratch based images.

If this plugin is installed and pointed at a scratch image you may receive an
error. The error `UnsupportedImageError` is expected in this scenario; see [the
ECR docs][ecr-troubleshooting] for more information.

Unsupported platforms (like Windows) will also result in this error.

[ecr-troubleshooting]: (https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-troubleshooting.html)

### The build is failing for an unresolved vulnerability. How do I do configure this plugin so I can unblock my builds?

There are two options here:

1. configure an [ignore file][ignore-findings] to tell the plugin to
  skip this vulnerability. Set an `until` date to ensure that it is dealt with
  in the future.
2. refer to how to set your [max-criticals](#max-criticals-optional-string), and
  [max-highs](#max-highs-optional-string) thresholds.

Out of the two options, the first is far more preferable as it targets the
finding that is causing the problem. Altering a threshold is unlikely to be
rolled back and is indiscriminate about the findings that it will ignore.

### How do I set my thresholds? _OR_ My build often breaks because of this plugin. Should I change the thresholds?

Setting the `max-criticals` and `max-high` thresholds requires some thought, and
needs to take into account the risk profile of the company and the service
itself.

Allowing a container with a critical or high vulnerability to be deployed is not
necessarily wrong, it really depends on the environment of the deployed
application and the nature of the vulnerabilities themselves.

Consult with your company's internal security teams about the acceptable risk
level for a service if a non-zero threshold is desired, and consider making use
of the [ignore file][ignore-findings] configuration to avoid temporary
blockages. Using an ignore entry with an expiry is strongly recommended over
increasing the threshold.

### What should I think about when ignoring a finding for a period of time?

Consider the following:

- Follow the link to read the details of the CVE. Does it impact a component
  that is directly (or indirectly) used by your application?
- Reference the CVSS score associated with the vulnerability and look carefully
  at the vector via the link. The vector will help inform about how this
  vulnerability can affect your system.
- Consider using the CVSS calculator (reached via the vector link) to fill out
  the "Environmental" part of the score. The environmental score helps judge the
  risks posed in the context of your application deployment environment. This is
  likely adjust the base score and assist in your decision making.
- Is a patch or update already available?
- Is this update likely to be made available in an update to the current base
  image, or does it exist in a later version of the base image?

Possible actions:

1. Update the base image that incorporates the fix. This may be the simplest
   option.
2. Remove the dependency from the image, or choose a different base image
   without the issue.
3. Add an ignore with an expiry to allow for an update to be published within a
   period of time. This is only valid if your corporate standards allow it, and
   there is a plan to follow up on this issue in the given time frame.
4. Update the image definition to update the package with the vulnerability.
   This can negatively impact image size, and create a future maintenance issue
   if not done carefully. Take care to keep the number of packages updated
   small, and avoid adding hard-coded versions unless a process exists to keep
   them up-to-date.
5. Ignore the finding indefinitely. This will generally only be valid if
   dependency both cannot be removed and is not used in a vulnerable fashion.
   Your working environment may require special exceptions for this.

[ignore-findings]: ./docs/ignore-findings.md
