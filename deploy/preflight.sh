#!/usr/bin/env bash
set -euo pipefail

boule_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
boule_repo_root="$(cd -- "${boule_script_dir}/.." && pwd)"
boule_env_file="${1:-${boule_repo_root}/.env}"

fail() {
  printf 'deployment preflight failed: %s\n' "$1" >&2
  exit 1
}

[[ -f "${boule_env_file}" && ! -L "${boule_env_file}" ]] \
  || fail "the env file must be a regular non-symlink file"
[[ "$(stat -c '%a' "${boule_env_file}")" == "600" ]] \
  || fail "the env file must have mode 0600"

read_setting() {
  local boule_setting_name="$1"
  local boule_setting_value
  boule_setting_value="$({
    awk -F= -v key="${boule_setting_name}" '
      $1 == key { count += 1; sub(/^[^=]*=/, ""); value = $0 }
      END { if (count == 1) print value; else exit 1 }
    ' "${boule_env_file}"
  } 2>/dev/null)" || fail "${boule_setting_name} must appear exactly once"
  [[ -n "${boule_setting_value}" ]] || fail "${boule_setting_name} must not be empty"
  printf '%s' "${boule_setting_value}"
}

boule_github_org="$(read_setting BOULE_GITHUB_ORG)"
boule_github_app_id="$(read_setting BOULE_GITHUB_APP_ID)"
boule_github_installation_id="$(read_setting BOULE_GITHUB_INSTALLATION_ID)"
boule_key_path="$(read_setting BOULE_GITHUB_APP_KEY_HOST_PATH)"

[[ "${boule_github_org}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]] \
  || fail "BOULE_GITHUB_ORG is invalid"
[[ "${boule_github_app_id}" =~ ^[0-9]+$ ]] \
  || fail "BOULE_GITHUB_APP_ID must be numeric"
[[ "${boule_github_installation_id}" =~ ^[0-9]+$ ]] \
  || fail "BOULE_GITHUB_INSTALLATION_ID must be numeric"
[[ "${boule_key_path}" == /* ]] \
  || fail "BOULE_GITHUB_APP_KEY_HOST_PATH must be absolute"
[[ "${boule_key_path}" =~ ^/[A-Za-z0-9._/-]+$ ]] \
  || fail "BOULE_GITHUB_APP_KEY_HOST_PATH contains unsupported characters"
command -v realpath >/dev/null || fail "realpath is required"
boule_key_real="$(realpath -e -- "${boule_key_path}" 2>/dev/null)" \
  || fail "the GitHub App key path does not exist"
[[ "${boule_key_real}" == "${boule_key_path}" ]] \
  || fail "the GitHub App key path must be canonical and contain no symlinks"
[[ -f "${boule_key_path}" && ! -L "${boule_key_path}" ]] \
  || fail "the GitHub App key must be a regular non-symlink file"
[[ "$(stat -c '%a' "${boule_key_path}")" == "600" ]] \
  || fail "the GitHub App key must have mode 0600"
[[ "$(stat -c '%u' "${boule_key_path}")" == "10001" ]] \
  || fail "the GitHub App key must be owned by runtime UID 10001"
[[ "$(stat -c '%a' "$(dirname -- "${boule_key_path}")")" == "700" ]] \
  || fail "the GitHub App key directory must have mode 0700"

command -v openssl >/dev/null || fail "openssl is required"
openssl rsa -in "${boule_key_path}" -check -noout >/dev/null 2>&1 \
  || fail "the GitHub App key is not a readable unencrypted RSA PEM"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

docker compose \
  --env-file "${boule_env_file}" \
  -f "${boule_repo_root}/compose.staging.yml" \
  -f "${boule_repo_root}/compose.github.yml" \
  config --quiet
docker compose \
  --env-file "${boule_env_file}" \
  -f "${boule_repo_root}/compose.staging.yml" \
  -f "${boule_repo_root}/compose.github-auto.yml" \
  config --quiet

printf 'Deployment preflight passed. No credential values were printed.\n'
