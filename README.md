# ECR Scan Results Buildkite Plugin

Buildkite plugin to retrieve ECR scan results from AWS's ECR image scanning
service. By default the plugin will cause the step to fail if there are critical
or high vulnerabilities reported, but there are configurable thresholds on this
behaviour.

> ℹ️ TIP: if you want the build to continue when vulnerabilities are found, be
> sure to supply values for `max-criticals` and `max-highs` parameters. If these
> are set to high values your build will never fail, but details will be
> supplied in the annotation.

## Example

Add the following lines to your `pipeline.yml`:

```yml
steps:
  - command: "command which creates an image"
    # the docker-compose plugin may be used here instead of a command
    plugins:
      - cultureamp/ecr-scan-results#v1.2.0:
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
      - cultureamp/ecr-scan-results#v1.2.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
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
      - cultureamp/ecr-scan-results#v1.2.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
          max-criticals: "1"
          max-highs: "10"
```

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

### `max-highs` (Optional, string)

If the number of high vulnerabilities in the image exceeds this threshold the
build is failed. Defaults to 0.  Use a sufficiently large number (e.g. 999) to
allow the build to always pass.

### `image-label` (Optional, string)

When supplied, this is used to title the report annotation in place of the
repository name and tag. Useful sometimes when the repo name and tag make the
reports harder to scan visually.

## Requirements

### ECR Scan on Push

This plugin assumes that the ECR repository has the `ScanOnPush` setting set (see
the [AWS
docs](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html)
for more information). By default this is not set on AWS ECR repositories.
However `Base Infrastructure for Services` configures this for all repostories
that it creates so for `cultureamp` pipelines no change should be required.

### Agent role requires the ecr:DescribeImages permission

The Buildkite agent needs the AWS IAM `ecr:DescribeImages` permission to
retrieve the vulnerability scan counts. Culture Amp build-roles created by `Base
Infrastructure for Services` have all been modified to include this permission.

### Scratch images are not supported

ECR cannot scan scratch based images, and this should be OK as the underlying
container doesn't contain packages to scan.

If this plugin is installed and pointed at a scratch image you may receive an
error and it may block the pipeline as a result. The error
`UnsupportedImageError` is expected in this scenario; see [the ECR
docs](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-troubleshooting.html)
for more information.
