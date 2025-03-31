# Download logic based on that used by https://github.com/monebag/monorepo-diff-buildkite-plugin
# Used under the terms of that license.

check_cmd() {
  command -v "$1" > /dev/null 2>&1
  return $?
}

say() {
    echo "$1"
}

err() {
  local red;red=$(tput setaf 1 2>/dev/null || echo '')
  local reset;reset=$(tput sgr0 2>/dev/null || echo '')
  say "${red}ERROR${reset}: $1" >&2
  exit 1
}

get_architecture() {
  local _ostype;_ostype="$(uname -s | tr '[:upper:]' '[:lower:]')"
  local _arch;_arch="$(uname -m)"
  local _arm=("arm armhf aarch64 aarch64_be armv6l armv7l armv8l arm64e") # arm64
  local _amd=("x86 x86pc i386 i686 i686-64 x64 x86_64 x86_64h athlon")    # amd64

  if [[ "${_arm[*]}" =~ ${_arch} ]]; then
    _arch="arm64"
  elif [[ "${_amd[*]}" =~ ${_arch} ]]; then
    _arch="amd64"
  elif [[ "${_arch}" != "ppc64le" ]]; then
    echo -e "ERROR: unsupported architecture \"${_arch}\"" >&2
    exit 2
  fi

  RETVAL="${_ostype}_${_arch}"
}

need_cmd() {
  if ! check_cmd "$1"; then
    err "need '$1' (command not found)"
  fi
}

# This function retries the download - if it fails due to network issues.
retry_download(){
  local max_retries=5
  local retry_delay=2

  for (( i=0 ; i<max_retries ; i++ ))
  do
     if [ "$3" = "curl" ]; then
        curl -sSfL "$1" -o "$2" && return 0
     elif [ "$3" = "wget" ]; then
        wget "$1" -O "$2" && return 0
     fi

     echo "Attempt $i failed. Retrying"
     sleep $retry_delay 
  done

  echo "Download failed after $max_retries attempts"
  return 1
}

# This wraps curl or wget.
# Try curl first, if not installed, use wget instead.
downloader() {
  if check_cmd curl; then
    _dld=curl
  elif check_cmd wget; then
    _dld=wget
  else
    _dld='curl or wget' # to be used in error message of need_cmd
  fi

  if [ "$1" = --check ]; then
    need_cmd "$_dld"
  elif [ "$_dld" = curl ]; then
    retry_download "$1" "$2" "curl"
  elif [ "$_dld" = wget ]; then
    retry_download "$1" "$2" "wget"
  else
    err "Unknown downloader"
  fi
}

get_version() {
  local _plugin=${BUILDKITE_PLUGINS:-""}
  local _version;_version=$(echo "$_plugin" | sed -e 's/.*ecr-scan-results-buildkite-plugin//' -e 's/\".*//')
  RETVAL="$_version"
}

download_binary_and_run() {
  get_architecture || return 1
  local _arch="$RETVAL"
  local _executable="ecr-scan-results-buildkite-plugin"
  local _repo="https://github.com/cultureamp/ecr-scan-results-buildkite-plugin"

  get_version || return 1
  local _version="$RETVAL"

  if [ -z "${_version}" ]; then
    _url=${_repo}/releases/latest/download/${_executable}_${_arch}
  else
    _url=${_repo}/releases/download/${_version:1}/${_executable}_${_arch}
  fi

  if ! downloader "$_url" "$_executable"; then
    say "failed to download $_url"
    exit 1
  fi

  chmod +x ${_executable}

  ./${_executable}
}
