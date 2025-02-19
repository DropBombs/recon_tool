#!/bin/bash
# This is a simple reconnaissance algorithm to gather basic information
# about a desired target, automating the log creation and command calls
# of commonly used commands such as nmap and host.

# List of used tools.
REQ_TOOLS=("whois" "nmap" "dig" "host" "curl" "jq")

# Definition of functions.
# Function to handle error gracefully.
function handle_error() {
  local exit_code="$1"
  local msg="$2"
  echo "[-] Error occurred: $msg (Exit code: $exit_code) [-]"
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
    if ! type -P $tool &> /dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    echo "[-] The following tools are missing: ${missing_tools[*]}"
    exit 1
  fi
}

# Function to format log output properly.
function log_creation() {
  local tmp_file="$1"
  local msg="$2"
  # Print section header to log file.
  {
    echo -e "\n=============="
    echo  "[*] $msg [*]"
    echo -e "==============\n"
    cat "$tmp_file"
  } >> "$LOGPATH"
}

# Function to check if target is up.
function check_target() {
  echo -e "[*] Verifying target's availability. [*]\n"
  if nc -zw1 "$target" 80 || nc -zw1 "$target" 443; then
    echo -e "[+] Target $target is reachable [+]\n"
    return 0
  else
    echo "[-] Target $target is unreachable. Try again. [-]"
    return 1
  fi
}

# Function to validate IP.
function validate_ip() {
  local ip="$1"
  local -a octets=($ip)
  # Temporarily set IFS but restore after function
  IFS='.' read -r -a octets <<< "$ip"

  [[ ${#octets[@]} -ne 4 ]] && return 1

  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    ((octet >= 0 && octet <= 255)) || return 1
  done

  return 0
}

# Function that returns 0 if input is IP and 1 if not.
function is_ip() {
  validate_ip "$1" && return 0 || return 1
}

# Function to perform input formatting/validation.
function validate_entry() {
  local input="$1"
  if [[ -z "$input" ]]; then
    echo "[-] No IP address/Domain name provided. Try again. [-]"
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
    echo "[-] Skipping certificate lookup for IP addresses. [-]" > "$CURL_TMP"
    return 0
  fi

  local response
  for i in {1..3}; do
    response=$(curl -s "https://crt.sh/?q=$target&output=json") && break
    sleep 2
  done

  [[ -z "$response" || "$response" == "[]" ]] && echo "[-] No certificate found. [-]" > "$CURL_TMP"||
    echo "$response" | jq -r '.[] | "Issuer: \(.issuer_name)\nDomains: \(.name_value)\nIssued on: \(.entry_timestamp)\n---"' > "$CURL_TMP"
  return 0
}


# Setup traps.
# Catch any unexpected errors. Delete temporary files on execution finish.
trap 'handle_error $? "An unexpected error occurred."' ERR
trap 'cleanup_files "${TMP_FILES[@]}"' EXIT

# Create log directory if it doesn't exists.
mkdir -p logs

# Requisites check.
check_tools

# Begin main execution.
# Check if CLI command was provided.
if [[ -n "$1" ]]; then
  target=$(validate_entry "$1") || handle_error $? "[-] Error validating input. Try again. [-]"
# Prompt user for target's IP address or domain name.
else
  while true; do
    read -p "Enter target IP address or domain name: " entry
    target=$(validate_entry "$entry") || continue # Retry if validation fails.
    if [[ -n "$target" ]]; then
      check_target && break # Check if target is reachable, if not, retry.
    fi
  done
fi

# Check if target is reachable.

# Defining output file. Use default if none provided.
timestamp=$(date +"%m%d%Y_%H%M%S") # Default uses current time to create unique filenames.
default_filename="${target}_recon_$timestamp.log"
read -p "Input the output file name (Default: $default_filename): " filename
filename=$(echo "$filename" | tr -d '[:space:]' | tr -d '/\\:*?"<>|')
LOGPATH="logs/${filename:-$default_filename}" # Use default if user presses Enter.

# Create temporary files for each command to better structure the log.
WHOIS_TMP=$(mktemp) || handle_error "Unable to create temp file for WHOIS"
NMAP_TMP=$(mktemp) || handle_error "Unable to create temp file for Nmap"
DNS_TMP=$(mktemp) || handle_error "Unable to create temp file for DNS Lookup"
CURL_TMP=$(mktemp) || handle_error "Unable to create temp file for Curl"

TMP_FILES=("$WHOIS_TMP" "$NMAP_TMP" "$DNS_TMP" "$CURL_TMP")

echo -e "[*] Starting reconnaissance. Please wait... [*]\n"

# Run commands in parallel for increased speed.
# WHOIS Lookup.
(whois -H  "$target" | grep -v -E "(^#|Terms of Use|For more information|^$)" |
grep -i -v -f text_pattern.txt) > "$WHOIS_TMP" &
WHOIS_PID=$!

# Nmap ports scan.
(nmap -sS -sC -A -T4 --top-ports 1000 "$target") > "$NMAP_TMP" &
NMAP_PID=$!

# Perform DNS queries with host or dig.
if is_ip "$target"; then
  (host "$target") > "$DNS_TMP" &
  DNS_PID=$!
else
  (
    dig +short A "$target"
    dig +short MX "$target"
    dig +short TXT "$target"
  ) > "$DNS_TMP" &
  DNS_PID=$!

  (fetch_certificate) &
  CURL_PID=$!
fi

# Ensure all parallel executions finish before proceeding.
wait "$WHOIS_PID" || handle_error $? "WHOIS Lookup failed."
wait "$NMAP_PID" || handle_error $? "Nmap Scan failed."
wait "$DNS_PID" || handle_error $? "DNS Lookup failed."
if [[ -n "${CURL_PID:-}" && "$CURL_PID" =~ ^[0-9]+$ ]]; then
  wait "$CURL_PID" || handle_error $? "Certificate Lookup failed."
fi

# Create structured log.
[[ -s "$WHOIS_TMP" ]] && log_creation "$WHOIS_TMP" "WHOIS Lookup"
[[ -s "$NMAP_TMP" ]] && log_creation "$NMAP_TMP" "Nmap Scan"
[[ -s "$DNS_TMP" ]] && log_creation "$DNS_TMP" "DNS Lookup"
[[ -s "$CURL_TMP" ]]  && log_creation "$CURL_TMP" "Certificate Lookup."

# Check if scan yielded useful information.
if [[ ! -s "$LOGPATH" ]]; then
  echo "[-] No useful information was gathered. Please try again. [-]" >> "$LOGPATH"
else # Display gathered information.
  echo -e "[*] Scan complete. Results saved in $LOGPATH [*]\n"
  echo "[*] Showing first 20 lines [*]"
  head -n 20 "$LOGPATH"
fi

# Prompt user to show entire log file.
echo ""
read -r -p "View full contents of log file? [y/n] " view_log
view_log=$(echo "$view_log" | tr '[:upper:]' '[:lower:]')
[[ "$view_log" == "y" ]] && less "$LOGPATH"
