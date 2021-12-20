# ECR Scan Results Buildkite Plugin

Buildkite plugin to retrieve ECR scan results

## Example

Add the following lines to your `pipeline.yml`:

```yml
    plugins:
      - cultureamp/ecr-scan-results#v1.1.7:
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
      - cultureamp/ecr-scan-results#v1.1.7:
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
      - cultureamp/ecr-scan-results#v1.1.7:
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

### `image-label` (Optional, string)
If this plugin is used for multiple images in the same pipeline then set `image-label` to a different alphanumeric label for each image, e.g. `development`, `master` etc. If the pipeline only builds one image then don't use this parameter. See the example pipeline below for how to use this parameter.

```yml
steps:
  - name: "build_and_push_dev"
    command: "bin/ci_build_and_push.sh"
    branches: '!master'
    agents:
      queue: build-unrestricted
    plugins:
      cultureamp/aws-assume-role:
        role: ${DEV_BUILD_ROLE}
        - cultureamp/ecr-scan-results#v1.1.7:
          image-name: "$DEV_BUILD_REPO:deploy-$DEV_BUILD_TAG"
          max-criticals: "2"
          max-highs: "20"
          image-label: "development"


  - name: "build_and_push_master"
    command: "bin/ci_build_and_push.sh"
    branches: 'master'
    agents:
      queue: build-restricted
    plugins:
      cultureamp/aws-assume-role:
        role: ${MASTER_BUILD_ROLE}
        - cultureamp/ecr-scan-results#v1.1.7:
          image-name: "$MASTER_BUILD_REPO:deploy-$MASTER_BUILD_TAG"
          max-criticals: "1"
          max-highs: "10"
          image-label: "master"
```


## Requirements

### ECR Scan on Push
This plugin assumes that the ECR repository has the ScanOnPush setting set (see https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html). By default this is not set on AWS ECR repositories. However `Base Infrastructure for Services` configures this for all repostories that it creates so for `cultureamp` pipelines no change should be required.

### Agent role requires the ecr:DescribeImages permission.
The Buildkite agent needs the AWS IAM `ecr:DescribeImages` permission to retrieve the vulnerability scan counts. Culture Amp build-roles created by `Base Infrastructure for Services` have all been modified to include this permission.

### Scratch images are not supported

ECR cannot scan scratch based images, and this should be OK as the underlying container doesn't contain packages to scan.

If this plugin is installed and pointed at a scratch image you may receive an error and it may block the pipeline as a result. The error `UnsupportedImageError` is expected in this scenario; see [the ECR docs](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-troubleshooting.html) for more information.
