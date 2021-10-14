# ECR Scan Results Buildkite Plugin

Buildkite plugin to retrieve ECR scan results

## Example

Add the following to your `pipeline.yml`:

```yml
steps:
  - command: ls
    plugins:
      - cultureamp/ecr-scan-results#v1.0.0:
          image-name: ${ECR_REPO_API}:${NORMALISED_BRANCH_NAME}
```

## Configuration

### `image-name` (Required, string)
The name of the container image in ECR. 

### `max-criticals` (Optional, string)
If the number of critical vulnerabilities in the image exceeds this threshold the build is failed. Defaults to 0. To allow unlimited critical vulnerabilities set to an empty string.

### `max-highs` (Optional, string)
If the number of high vulnerabilities in the image exceeds this threshold the build is failed. Defaults to 0. To allow unlimited high vulnerabilities set to an empty string.
