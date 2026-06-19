#!/bin/bash
# This is a simple reconnaissance algorithm to gather basic information
# about a desired target, automating the log creation and command calls
# of commonly used commands such as nmap and host.

# List of required system binaries.
REQ_TOOLS=("whois" "nmap" "dig" "host" "curl" "jq")

# Definition of colors for better output.
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[1;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  NC=''
fi

# Definition of functions.
# Function to handle error gracefully.
function handle_error() {
  local exit_code="$1"
  local msg="$2"
  echo -e "${RED}[-] Critical error: $msg (Exit code: $exit_code) [-]${NC}" >&2
  exit "$exit_code"
}

# Function to remove temporary files from given array.
function cleanup_files() {
  local files=("$@")
  for file in "${files[@]}"; do
    [[ -f "$file" ]] &&  rm -f "$file"
  done
}

# Function to check if needed tools are installed.
function check_tools() {
  local missing_tools=()
  for tool in "${REQ_TOOLS[@]}"; do
    if ! type -P $tool &> /dev/null; then
      missing_tools+=("$tool")
    fi
  done
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    handle_error 1 "Missing environment dependencies: ${missing_tools[*]}"
    exit 1
  fi
}

# Function to format log output properly.
function log_creation() {
  local tmp_file="$1"
  local msg="$2"
  {
    echo -e "\n=============="
    echo  "[*] $msg [*]"
    echo -e "==============\n"
    cat "$tmp_file"
  } >> "$LOGPATH"
}

# Function to check if target is up.
function check_target() {
  echo -e "${YELLOW}[*] Validating target's network availability... [*]${NC}\n"
  if nc -zw1 "$target" 80 || nc -zw1 "$target" 443; then
    echo -e "${GREEN}[+] Target $target is responsive. [+]$NC\n"
    return 0
  else
    handle_error 1 "Target $target is unreachable."
    return 1
  fi
}

# Function that validates IPv4 formatting rules.
function validate_ip() {
  local ip="$1"
  local -a octets
  IFS='.' read -r -a octets <<< "$ip"

  [[ ${#octets[@]} -ne 4 ]] && return 1

  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    ((octet >= 0 && octet <= 255)) || return 1
  done

  return 0
}

function is_ip() {
  validate_ip "$1" && return 0 || return 1
}

# Function to perform input formatting/validation.
function validate_entry() {
  local input="$1"
  if [[ -z "$input" ]]; then
    return 1
  fi
  # Format input.
  input=$(echo "$input" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | xargs)
  echo "$input"
  return 0
}

# Function to perform curl request on crt.sh.
function fetch_certificate() {
  if validate_ip "$target"; then
    echo "${YELLOW}[-] Skipping certificate lookup for IP addresses. [-]${NC}" > "$CURL_TMP"
    return 0
  fi

  local response
  for i in {1..3}; do
    response=$(curl -s -m 10 "https://crt.sh/?q=$target&output=json") && break
    sleep 2
  done

  if [[ -z "$response" || "$response" == "[]" ]]; then 
    echo "[-] No SSL certificates found. [-]" > "$CURL_TMP"
  elif echo "$response" | jq . >/dev/null 2>&1; then
    echo "$response" | jq -r '.[] | "Issuer: \(.issuer_name)\nDomains: \(.name_value)\nIssued on: \(.entry_timestamp)\n---"' > "$CURL_TMP"
  else
    echo "[-] Certificate lookup failed. [-]" > "$CURL_TMP"
  fi
  return 0
}


# Trap setup for exception handling.
# Catch any unexpected errors. Delete temporary files on execution finish.
trap 'handle_error $? "An unexpected shell error disrupted execution."' ERR
trap 'cleanup_files "${TMP_FILES[@]}"' EXIT

mkdir -p core/logs

check_tools

# Begin main execution.
if [[ -n "$1" ]]; then
  target=$(validate_entry "$1") || handle_error 1 "Input parameter validation failed."
  check_target
else
  handle_error 1 "Execution failed: No target argument provided."
fi

# Filename assignment
timestamp=$(date +"%m%d%Y_%H%M%S")
LOGPATH="core/logs/${target}_recon_${timestamp}.log"

# Allocate secure in-memory volatile temporary files.
WHOIS_TMP=$(mktemp) || handle_error 1 "Failed to allocate memory file for WHOIS."
NMAP_TMP=$(mktemp) || handle_error 1 "Failed to allocate memory file for Nmap."
DNS_TMP=$(mktemp) || handle_error 1 "Failed to allocate memory file for DNS."
CURL_TMP=$(mktemp) || handle_error 1 "Failed to allocate memory file for Curl."

TMP_FILES=("$WHOIS_TMP" "$NMAP_TMP" "$DNS_TMP" "$CURL_TMP")

echo -e "${YELLOW}[*] Starting reconnaissance. Please wait... [*]$NC\n"

# Run commands in parallel for increased speed.
# WHOIS Lookup.
(whois -H  "$target" | grep -v -E "(^#|Terms of Use|For more information|^$)" |
grep -i -v -f text_pattern.txt) > "$WHOIS_TMP" 2>&1 &
WHOIS_PID=$!

# Nmap ports scan.
(nmap -sT -sC -A -T4 --top-ports 1000 "$target") > "$NMAP_TMP" 2>&1 &
NMAP_PID=$!

# Perform DNS queries with host or dig.
if is_ip "$target"; then
  (host "$target") > "$DNS_TMP" 2>&1 &
  DNS_PID=$!
else
  (
    dig +short A "$target"
    dig +short MX "$target"
    dig +short TXT "$target"
  ) > "$DNS_TMP" 2>&1 &
  DNS_PID=$!

  (fetch_certificate) &
  CURL_PID=$!
fi

# Ensure all parallel executions finish before proceeding.
wait "$WHOIS_PID" || echo "[-] WHOIS collection encountered errors. [-]" > "$WHOIS_TMP"
wait "$NMAP_PID" || echo "[-] Nmap execution encountered errors. [-]" > "$NMAP_TMP"
wait "$DNS_PID" || echo  "[-] DNS resolution encountered errors. [-]" > "$DNS_TMP"
if [[ -n "${CURL_PID:-}" && "$CURL_PID" =~ ^[0-9]+$ ]]; then
  wait "$CURL_PID" || echo  "[-] Certificate mapping encountered errors. [-]" > "$CURL_TMP"
fi

# Create structured log.
[[ -s "$WHOIS_TMP" ]] && log_creation "$WHOIS_TMP" "WHOIS Lookup"
[[ -s "$NMAP_TMP" ]] && log_creation "$NMAP_TMP" "Nmap Scan"
[[ -s "$DNS_TMP" ]] && log_creation "$DNS_TMP" "DNS Lookup"
[[ -s "$CURL_TMP" ]]  && log_creation "$CURL_TMP" "Certificate Lookup"

# Check if scan yielded useful information.
if [[ ! -s "$LOGPATH" ]]; then
  handle_error 1 "Audit complete: No technical artifacts were recovered."
else
  cat "$LOGPATH"
fi
