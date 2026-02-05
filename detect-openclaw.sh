#!/usr/bin/env bash
# Detection script for OpenClaw / Moltbot / Clawdbot (macOS/Linux)
# exit codes:
#   0 = not-installed (clean)
#   1 = OpenClaw/Moltbot/Clawdbot installed (non-compliant)
#   2 = script error
#   3 = malicious skill installed (from risk.txt)

set -euo pipefail

PROFILE="${OPENCLAW_PROFILE:-}"
PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
SCAN_SKILLS=false

# Optional CLI flag: --scan-skills enables skill enumeration and malicious-skill checking
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan-skills)
      SCAN_SKILLS=true
      shift
      ;;
    *)
      break
      ;;
  esac
done

# Global arrays for malicious skills and installed skills (used only when SCAN_SKILLS=true)
MALICIOUS_SKILLS=()
INSTALLED_SKILLS=()
INSTALLED_SKILL_PATHS=()

load_malicious_skills() {
  # Load malicious skill names from risk.txt into MALICIOUS_SKILLS (lowercased)
  local script_dir risk_file
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
  risk_file="${script_dir}/risk.txt"

  MALICIOUS_SKILLS=()
  [[ -f "$risk_file" ]] || return 0

  # From the "Malicious Skills" line to EOF, each non-empty, non-comment line is a skill name
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}" # ltrim
    line="${line%"${line##*[![:space:]]}"}" # rtrim
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    MALICIOUS_SKILLS+=("$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')")
  done < <(awk 'tolower($0) ~ /malicious skills/ {flag=1; next} flag {print}' "$risk_file")
}

is_skill_malicious() {
  local name_lc="$1"
  name_lc="$(printf '%s' "$name_lc" | tr '[:upper:]' '[:lower:]')"
  local s
  for s in "${MALICIOUS_SKILLS[@]}"; do
    if [[ "$s" == "$name_lc" ]]; then
      return 0
    fi
  done
  return 1
}

collect_installed_skills() {
  local root="$1"
  [[ -d "$root" ]] || return 0

  while IFS= read -r file; do
    [[ -f "$file" ]] || continue
    local skill_name
    skill_name="$(basename "$(dirname "$file")")"
    INSTALLED_SKILLS+=("$skill_name")
    INSTALLED_SKILL_PATHS+=("$file")
  done < <(find "$root" -type f -name 'SKILL.md' 2>/dev/null || true)
}

detect_platform() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux) echo "linux" ;;
    *) echo "unknown" ;;
  esac
}

get_state_dir() {
  local home="$1"
  if [[ -n "$PROFILE" ]]; then
    echo "${home}/.openclaw-${PROFILE}"
  else
    echo "${home}/.openclaw"
  fi
}

get_users_to_check() {
  local platform="$1"
  if [[ $EUID -eq 0 ]]; then
    case "$platform" in
      darwin)
        for dir in /Users/*; do
          [[ -d "$dir" && "$(basename "$dir")" != "Shared" ]] && basename "$dir"
        done
        ;;
      linux)
        for dir in /home/*; do
          [[ -d "$dir" ]] && basename "$dir"
        done
        ;;
    esac
  else
    whoami
  fi
}

get_home_dir() {
  local user="$1"
  local platform="$2"
  case "$platform" in
    darwin) echo "/Users/$user" ;;
    linux) echo "/home/$user" ;;
  esac
}

check_cli_in_path() {
  local path
  path=$(command -v openclaw 2>/dev/null) || true
  if [[ -n "$path" ]]; then
    echo "$path"
    return 0
  fi
  return 1
}

check_cli_for_user() {
  local home="$1"
  local locations=(
    "${home}/.volta/bin/openclaw"
    "${home}/.local/bin/openclaw"
    "${home}/.nvm/current/bin/openclaw"
    "${home}/bin/openclaw"
  )
  for loc in "${locations[@]}"; do
    if [[ -x "$loc" ]]; then
      echo "$loc"
      return 0
    fi
  done
  return 1
}

check_cli_global() {
  local locations=(
    "/usr/local/bin/openclaw"
    "/opt/homebrew/bin/openclaw"
    "/usr/bin/openclaw"
  )
  for loc in "${locations[@]}"; do
    if [[ -x "$loc" ]]; then
      echo "$loc"
      return 0
    fi
  done
  return 1
}

check_mac_app() {
  local app_path="/Applications/OpenClaw.app"
  if [[ -d "$app_path" ]]; then
    echo "$app_path"
    return 0
  else
    echo "not-found"
    return 1
  fi
}

check_state_dir() {
  local state_dir="$1"
  if [[ -d "$state_dir" ]]; then
    echo "$state_dir"
    return 0
  else
    echo "not-found"
    return 1
  fi
}

check_config() {
  local config_file="${1}/openclaw.json"
  if [[ -f "$config_file" ]]; then
    echo "$config_file"
  else
    echo "not-found"
  fi
}

check_launchd_service() {
  local label uid
  uid=$(id -u)
  if [[ -n "$PROFILE" ]]; then
    label="bot.molt.${PROFILE}"
  else
    label="bot.molt.gateway"
  fi
  if launchctl print "gui/${uid}/${label}" &>/dev/null; then
    echo "gui/${uid}/${label}"
  else
    echo "not-loaded"
  fi
}

check_systemd_service() {
  local service
  if [[ -n "$PROFILE" ]]; then
    service="openclaw-gateway-${PROFILE}.service"
  else
    service="openclaw-gateway.service"
  fi
  if systemctl --user is-active "$service" &>/dev/null; then
    echo "$service"
  else
    echo "inactive"
  fi
}

get_configured_port() {
  local config_file="$1"
  if [[ -f "$config_file" ]]; then
    # extract port from json without jq (mdm environments may not have it)
    grep -o '"port"[[:space:]]*:[[:space:]]*[0-9]*' "$config_file" 2>/dev/null | head -1 | grep -o '[0-9]*$' || true
  fi
}

check_gateway_port() {
  local port="$1"
  if nc -z localhost "$port" &>/dev/null; then
    echo "listening"
    return 0
  else
    echo "not-listening"
    return 1
  fi
}

check_docker_containers() {
  if ! command -v docker &>/dev/null; then
    return 0
  fi
  docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null | grep -Ei 'openclaw|moltbot|clawdbot' || true
}

check_docker_images() {
  if ! command -v docker &>/dev/null; then
    return 0
  fi
  docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -Ei 'openclaw|moltbot|clawdbot' || true
}

main() {
  local platform cli_found=false app_found=false state_found=false service_running=false port_listening=false malicious_found=false
  local output=""

  out() { output+="$1"$'\n'; }

  platform=$(detect_platform)
  out "platform: $platform"

  if [[ "$platform" == "unknown" ]]; then
    echo "summary: error"
    echo "$output"
    exit 2
  fi

  # check global CLI locations first
  local cli_result=""
  cli_result=$(check_cli_in_path) || cli_result=$(check_cli_global) || true
  if [[ -n "$cli_result" ]]; then
    cli_found=true
    out "cli: $cli_result"
    out "cli-version: $("$cli_result" --version 2>/dev/null | head -1 || echo "unknown")"
  fi

  if [[ "$platform" == "darwin" ]]; then
    local app_result
    app_result=$(check_mac_app) && app_found=true || app_found=false
    out "app: $app_result"
  fi

  local users
  users=$(get_users_to_check "$platform")
  local multi_user=false
  local user_count
  user_count=$(echo "$users" | wc -l | tr -d ' ')
  [[ $user_count -gt 1 ]] && multi_user=true

  local ports_to_check="$PORT"

  for user in $users; do
    local home_dir state_dir
    home_dir=$(get_home_dir "$user" "$platform")
    state_dir=$(get_state_dir "$home_dir")

    if $multi_user; then
      out "user: $user"
      # check user-specific CLI if not already found
      if ! $cli_found; then
        local user_cli
        user_cli=$(check_cli_for_user "$home_dir") || true
        if [[ -n "$user_cli" ]]; then
          cli_found=true
          out "  cli: $user_cli"
          out "  cli-version: $("$user_cli" --version 2>/dev/null | head -1 || echo "unknown")"
        fi
      fi
      local state_result
      state_result=$(check_state_dir "$state_dir") && state_found=true
      out "  state-dir: $state_result"
      if $SCAN_SKILLS; then
        # skills under OpenClaw state dir
        if [[ -d "${state_dir}/skills" ]]; then
          collect_installed_skills "${state_dir}/skills"
        fi
        if [[ -d "${state_dir}/extensions" ]]; then
          local ext_dir
          for ext_dir in "${state_dir}/extensions"/*; do
            [[ -d "$ext_dir/skills" ]] && collect_installed_skills "$ext_dir/skills"
          done
        fi
      fi
      local config_result
      config_result=$(check_config "$state_dir")
      out "  config: $config_result"
      local configured_port
      configured_port=$(get_configured_port "${state_dir}/openclaw.json")
      if [[ -n "$configured_port" ]]; then
        out "  config-port: $configured_port"
        ports_to_check="$ports_to_check $configured_port"
      fi
      # legacy names: Clawdbot and Moltbot state/config
      local clawdbot_state_dir="${home_dir}/.clawdbot"
      local clawdbot_config_file="${clawdbot_state_dir}/clawdbot.json"
      if [[ -d "$clawdbot_state_dir" ]]; then
        out "  clawdbot-state-dir: $clawdbot_state_dir"
        state_found=true
        if $SCAN_SKILLS; then
          if [[ -d "${clawdbot_state_dir}/skills" ]]; then
            collect_installed_skills "${clawdbot_state_dir}/skills"
          fi
          if [[ -d "${clawdbot_state_dir}/extensions" ]]; then
            local ext_dir2
            for ext_dir2 in "${clawdbot_state_dir}/extensions"/*; do
              [[ -d "$ext_dir2/skills" ]] && collect_installed_skills "$ext_dir2/skills"
            done
          fi
        fi
      else
        out "  clawdbot-state-dir: not-found"
      fi
      if [[ -f "$clawdbot_config_file" ]]; then
        out "  clawdbot-config: $clawdbot_config_file"
        configured_port=$(get_configured_port "$clawdbot_config_file")
        if [[ -n "$configured_port" ]]; then
          out "  clawdbot-config-port: $configured_port"
          ports_to_check="$ports_to_check $configured_port"
        fi
      else
        out "  clawdbot-config: not-found"
      fi

      local moltbot_state_dir="${home_dir}/.moltbot"
      local moltbot_config_file="${moltbot_state_dir}/moltbot.json"
      if [[ -d "$moltbot_state_dir" ]]; then
        out "  moltbot-state-dir: $moltbot_state_dir"
        state_found=true
        if $SCAN_SKILLS; then
          if [[ -d "${moltbot_state_dir}/skills" ]]; then
            collect_installed_skills "${moltbot_state_dir}/skills"
          fi
          if [[ -d "${moltbot_state_dir}/extensions" ]]; then
            local ext_dir3
            for ext_dir3 in "${moltbot_state_dir}/extensions"/*; do
              [[ -d "$ext_dir3/skills" ]] && collect_installed_skills "$ext_dir3/skills"
            done
          fi
        fi
      else
        out "  moltbot-state-dir: not-found"
      fi
      if [[ -f "$moltbot_config_file" ]]; then
        out "  moltbot-config: $moltbot_config_file"
        configured_port=$(get_configured_port "$moltbot_config_file")
        if [[ -n "$configured_port" ]]; then
          out "  moltbot-config-port: $configured_port"
          ports_to_check="$ports_to_check $configured_port"
        fi
      else
        out "  moltbot-config: not-found"
      fi
    else
      # single user mode - check user CLI
      if ! $cli_found; then
        local user_cli
        user_cli=$(check_cli_for_user "$home_dir") || true
        if [[ -n "$user_cli" ]]; then
          cli_found=true
          out "cli: $user_cli"
          out "cli-version: $("$user_cli" --version 2>/dev/null | head -1 || echo "unknown")"
        fi
      fi
      if ! $cli_found; then
        out "cli: not-found"
        out "cli-version: n/a"
      fi
      local state_result
      state_result=$(check_state_dir "$state_dir") && state_found=true
      out "state-dir: $state_result"
      if $SCAN_SKILLS; then
        # skills under OpenClaw state dir
        if [[ -d "${state_dir}/skills" ]]; then
          collect_installed_skills "${state_dir}/skills"
        fi
        if [[ -d "${state_dir}/extensions" ]]; then
          local ext_dir
          for ext_dir in "${state_dir}/extensions"/*; do
            [[ -d "$ext_dir/skills" ]] && collect_installed_skills "$ext_dir/skills"
          done
        fi
      fi
      out "config: $(check_config "$state_dir")"
      local configured_port
      configured_port=$(get_configured_port "${state_dir}/openclaw.json")
      if [[ -n "$configured_port" ]]; then
        out "config-port: $configured_port"
        ports_to_check="$ports_to_check $configured_port"
      fi

      # legacy names: Clawdbot and Moltbot state/config
      local clawdbot_state_dir="${home_dir}/.clawdbot"
      local clawdbot_config_file="${clawdbot_state_dir}/clawdbot.json"
      if [[ -d "$clawdbot_state_dir" ]]; then
        out "clawdbot-state-dir: $clawdbot_state_dir"
        state_found=true
        if $SCAN_SKILLS; then
          if [[ -d "${clawdbot_state_dir}/skills" ]]; then
            collect_installed_skills "${clawdbot_state_dir}/skills"
          fi
          if [[ -d "${clawdbot_state_dir}/extensions" ]]; then
            local ext_dir2
            for ext_dir2 in "${clawdbot_state_dir}/extensions"/*; do
              [[ -d "$ext_dir2/skills" ]] && collect_installed_skills "$ext_dir2/skills"
            done
          fi
        fi
      else
        out "clawdbot-state-dir: not-found"
      fi
      if [[ -f "$clawdbot_config_file" ]]; then
        out "clawdbot-config: $clawdbot_config_file"
        configured_port=$(get_configured_port "$clawdbot_config_file")
        if [[ -n "$configured_port" ]]; then
          out "clawdbot-config-port: $configured_port"
          ports_to_check="$ports_to_check $configured_port"
        fi
      else
        out "clawdbot-config: not-found"
      fi

      local moltbot_state_dir="${home_dir}/.moltbot"
      local moltbot_config_file="${moltbot_state_dir}/moltbot.json"
      if [[ -d "$moltbot_state_dir" ]]; then
        out "moltbot-state-dir: $moltbot_state_dir"
        state_found=true
        if $SCAN_SKILLS; then
          if [[ -d "${moltbot_state_dir}/skills" ]]; then
            collect_installed_skills "${moltbot_state_dir}/skills"
          fi
          if [[ -d "${moltbot_state_dir}/extensions" ]]; then
            local ext_dir3
            for ext_dir3 in "${moltbot_state_dir}/extensions"/*; do
              [[ -d "$ext_dir3/skills" ]] && collect_installed_skills "$ext_dir3/skills"
            done
          fi
        fi
      else
        out "moltbot-state-dir: not-found"
      fi
      if [[ -f "$moltbot_config_file" ]]; then
        out "moltbot-config: $moltbot_config_file"
        configured_port=$(get_configured_port "$moltbot_config_file")
        if [[ -n "$configured_port" ]]; then
          out "moltbot-config-port: $configured_port"
          ports_to_check="$ports_to_check $configured_port"
        fi
      else
        out "moltbot-config: not-found"
      fi
    fi
  done

  # print cli not-found for multi-user if none found
  if $multi_user && ! $cli_found; then
    out "cli: not-found"
    out "cli-version: n/a"
  fi

  case "$platform" in
    darwin)
      local service_result
      service_result=$(check_launchd_service) && service_running=true || service_running=false
      out "gateway-service: $service_result"
      ;;
    linux)
      local service_result
      service_result=$(check_systemd_service) && service_running=true || service_running=false
      out "gateway-service: $service_result"
      ;;
  esac

  # check all unique ports (default + any configured in user configs)
  local unique_ports listening_port=""
  unique_ports=$(echo "$ports_to_check" | tr ' ' '\n' | sort -u | tr '\n' ' ')
  for port in $unique_ports; do
    if check_gateway_port "$port" >/dev/null; then
      port_listening=true
      listening_port="$port"
      break
    fi
  done
  if $port_listening; then
    out "gateway-port: $listening_port"
  else
    out "gateway-port: not-listening"
  fi

  local docker_containers docker_images docker_running=false docker_installed=false
  docker_containers=$(check_docker_containers)
  if [[ -n "$docker_containers" ]]; then
    docker_running=true
    out "docker-container: $docker_containers"
  else
    out "docker-container: not-found"
  fi

  docker_images=$(check_docker_images)
  if [[ -n "$docker_images" ]]; then
    docker_installed=true
    out "docker-image: $docker_images"
  else
    out "docker-image: not-found"
  fi

  local installed=false running=false

  if $cli_found || $app_found || $state_found || $docker_installed; then
    installed=true
  fi

  if $service_running || $port_listening || $docker_running; then
    running=true
  fi

  # skills & malicious skills summary (only if something is installed and scan is enabled)
  local skills_installed_count=0 malicious_skills_count=0
  if $installed && $SCAN_SKILLS; then
    skills_installed_count=${#INSTALLED_SKILLS[@]}
    if (( skills_installed_count > 0 )); then
      load_malicious_skills
      out "skills-installed-count: $skills_installed_count"
      local i
      for i in "${!INSTALLED_SKILLS[@]}"; do
        out "installed-skill: ${INSTALLED_SKILLS[$i]} (path: ${INSTALLED_SKILL_PATHS[$i]})"
      done
      for i in "${!INSTALLED_SKILLS[@]}"; do
        if is_skill_malicious "${INSTALLED_SKILLS[$i]}"; then
          ((malicious_skills_count++))
          malicious_found=true
          out "malicious-skill: ${INSTALLED_SKILLS[$i]} (path: ${INSTALLED_SKILL_PATHS[$i]})"
        fi
      done
      out "malicious-skills-count: $malicious_skills_count"
    fi
  fi

  # exit codes:
  #   0 = not-installed (clean)
  #   1 = installed (non-compliant), no malicious skills
  #   2 = script error
  #   3 = malicious skills installed
  if ! $installed; then
    echo "summary: not-installed"
    printf "%s" "$output"
    exit 0
  elif $malicious_found; then
    if $running; then
      echo "summary: installed-and-running"
    else
      echo "summary: installed-not-running"
    fi
    printf "%s" "$output"
    exit 3
  elif $running; then
    echo "summary: installed-and-running"
    printf "%s" "$output"
    exit 1
  else
    echo "summary: installed-not-running"
    printf "%s" "$output"
    exit 1
  fi
}

main
