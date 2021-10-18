# ECR Scan Results Buildkite Plugin

Buildkite plugin to retrieve ECR scan results

## Example

Add the following lines to your `pipeline.yml`:

```yml
    plugins:
      - cultureamp/ecr-scan-results#v1.0.0:
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
      - cultureamp/ecr-scan-results#v1.0.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
```

If you want the pipeline to pass with some vulnerabilities then set `max-criticals` and `max-highs` like below. This pipeline will pass if there is one critical vulenerability but fail if there are two. Similarly it will fail if there are eleven high vulnerabilities.

```yml
steps:
  - label: ":docker: Build and push CDK deployment image"
    command: "bin/ci_cdk_build_and_push.sh"
    agents:
      queue: ${BUILD_AGENT}
    plugins:
      - cultureamp/aws-assume-role:
          role: ${BUILD_ROLE}
      - cultureamp/ecr-scan-results#v1.0.1:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
          max-criticals: "1"
          max-highs: "10"
```

## Configuration

### `image-name` (Required, string)
The name of the container image in ECR. This should be the same string that is supplied as an arguement to the `docker push` command used to push the image to AWS ECR. It should have the form:
`AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPOSITORY_NAME:IMAGE_TAG` with the text in capitals replaced with the appropriate values for your environment.

### `max-criticals` (Optional, string)
If the number of critical vulnerabilities in the image exceeds this threshold the build is failed. Defaults to 0. Use a sufficiently large number (e.g. 999) to allow the build to always pass.

### `max-highs` (Optional, string)
If the number of high vulnerabilities in the image exceeds this threshold the build is failed. Defaults to 0.  Use a sufficiently large number (e.g. 999) to allow the build to always pass.

## Requirements

### ECR Scan on Push
This plugin assumes that the ECR repository has the ScanOnPush setting set (see https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html). By default this is not set on AWS ECR repositories. However `Base Infrastructure for Services` configures this for all repostories that it creates so for `cultureamp` pipelines no change should be required.

### Agent role requires the ecr:DescribeImages permission.
The Buildkite agent needs the AWS IAM `ecr:DescribeImages` permission to retrieve the vulnerability scan counts. Culture Amp build-roles created by `Base Infrastructure for Services` have all been modified to include this permission.
