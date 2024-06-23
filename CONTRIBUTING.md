# Contributing to the plugin

The plugin is licensed under the MIT license, and we welcome your contributions!

If you are planning to make a larger contribution, please be sure to to raise an
issue first. This allows for conversation and helps us plan to support the
changes being contributed.

## Making contributions

The core of this plugin is in Go. Contributions must be accompanied by unit
tests, and have some level of practical smoke testing completed against ECR.

Useful commands:

```shell
# all Go source is under `src/`
cd src

# running tests
go test ./...

# create the executable
go build
```

## Running the plugin locally

Buildkite plugins [take their input parameters as environment
variables][plugin-docs]. In local development we use
[`direnv`](https://direnv.net/) to set these appropriately.

There is an `.envrc` file present in the repository root. Follow the
instructions in this file to create your own `.envrc.private` file that can be
activated with `direnv allow`.

Set the value of `BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME` in the
`.envrc.private` file to point the plugin at a particular image, and ensure that
you have assumed a role that has access to the ECR registry in question.

Then, `go build` to create the executable and `./ecrscanresults` to run.

```shell
cd src

# apply modifications to env variables
direnv allow

# build and execute
go build && ./ecrscanresults
```

[plugin-docs]: https://buildkite.com/docs/plugins/writing#step-2-add-a-plugin-dot-yml
