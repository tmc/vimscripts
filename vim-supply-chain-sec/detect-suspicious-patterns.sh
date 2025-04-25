#!/bin/bash
#
# Vim Plugin Suspicious Pattern Detector
#
# This script scans Vim plugins for suspicious code patterns that might
# indicate malicious activity or a supply chain attack.
#
# Usage: 
#   ./detect-suspicious-patterns.sh [PLUGIN_DIR] [OPTIONS]
#
# Options:
#   --output FILE    Write results to FILE (default: suspicious-patterns.txt)
#   --deep           Perform more thorough but slower analysis
#   --help           Display this help message

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/suspicious-patterns.txt"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")
DEEP_SCAN=false

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Display help message
show_help() {
  echo -e "${BLUE}Vim Plugin Suspicious Pattern Detector${NC}"
  echo -e "This script scans Vim plugins for suspicious code patterns."
  echo ""
  echo -e "Usage: ./detect-suspicious-patterns.sh [PLUGIN_DIR] [OPTIONS]"
  echo ""
  echo -e "Options:"
  echo -e "  --output FILE    Write results to FILE (default: suspicious-patterns.txt)"
  echo -e "  --deep           Perform more thorough but slower analysis"
  echo -e "  --help           Display this help message"
  echo ""
  echo -e "Examples:"
  echo -e "  ./detect-suspicious-patterns.sh ~/.vim/plugged"
  echo -e "  ./detect-suspicious-patterns.sh ~/.vim/plugged --output report.txt --deep"
  exit 0
}

# Check requirements
check_requirements() {
  for tool in rg xxd strings base64; do
    if ! command -v "$tool" &> /dev/null; then
      echo -e "${RED}Error: Required tool not found:${NC} $tool"
      
      if [ "$tool" = "rg" ]; then
        echo "Please install ripgrep (rg) before running the script."
        echo "On macOS: brew install ripgrep"
        echo "On Ubuntu/Debian: sudo apt install ripgrep"
      else
        echo "Please install this tool before running the script."
      fi
      
      exit 1
    fi
  done
}

# Initialize output file
initialize_output() {
  echo "# Vim Plugin Suspicious Pattern Detector" > "$OUTPUT_FILE"
  echo "Date: $SCAN_DATE" >> "$OUTPUT_FILE"
  echo "Target Directory: $PLUGIN_DIR" >> "$OUTPUT_FILE"
  echo "Deep Scan: $DEEP_SCAN" >> "$OUTPUT_FILE"
  echo "----------------------------------------" >> "$OUTPUT_FILE"
}

# Scan for basic suspicious patterns
scan_basic_patterns() {
  echo -e "\n${BLUE}Scanning for basic suspicious patterns...${NC}"
  echo -e "\n## Basic Suspicious Patterns" >> "$OUTPUT_FILE"
  
  # Define patterns to search for
  local patterns=(
    # Obfuscated code execution - CRITICAL THREATS
    "eval.*base64"
    "system.*base64"
    "exec.*base64"
    "execute.*base64"
    "base64.*decode.*execute"
    "base64.*-d.*execute"
    "exec.*fromCharCode"
    "execute.*substitute"
    "exec.*decode"
    "decode.*exec"
    "decode.*execute"
    "let.*encoded.*=.*['\"][A-Za-z0-9+/=]\{20,\}['\"]"
    "execute.*s:decoded"
    "execute.*decoded"
    "eval.*decoded"
    
    # Remote code execution - CRITICAL THREATS
    "curl.*|.*bash"
    "curl.*|.*sh"
    "wget.*|.*bash"
    "wget.*|.*sh"
    "fetch.*|.*bash"
    "curl.*-s.*|"
    "wget.*-q.*|"
    "download.*execute"
    "download.*|.*exec"
    
    # Suspicious network activities
    "curl.*-s"
    "wget.*-q"
    "new WebSocket"
    "fetch.*http"
    "net.*connect"
    "http\.client"
    "httplib"
    "urllib\.request"
    "requests\.get"
    
    # Command execution
    "system([^)]*\\$"
    "exec([^)]*\\$"
    "popen([^)]*\\$"
    "call([^)]*\\$"
    "execute.*\\$"
    "eval.*\\$"
    "!.*>.*[\/]tmp[\/]"
    "feedkeys.*:.*!.*"
    "feedkeys.*silent.*!"
    
    # Suspicious file operations
    "writefile.*\\$"
    "tempname.*execute"
    "tempfile.*system"
    
    # Time bombs and backdoors
    "strftime.*exec"
    "if.*Date.*{.*exec"
    "cron"
    "sleep.*system"
    "setTimeout.*function"
    "if.*=~#.*sync"
    "if.*=~#.*backdoor"
    "if.*=~#.*admin"
    "if.*=~.*help.*!"
  )
  
  for pattern in "${patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$OUTPUT_FILE"
    
    results=$(rg --no-heading --glob "!.git/" -n "$pattern" "$PLUGIN_DIR" 2>/dev/null || echo "")
    
    if [ -n "$results" ]; then
      echo "$results" | head -n 15 >> "$OUTPUT_FILE"
      lines_count=$(echo "$results" | wc -l)
      
      if [ $lines_count -gt 15 ]; then
        echo -e "... ($(($lines_count - 15)) more matches)" >> "$OUTPUT_FILE"
      fi
      
      echo -e "${YELLOW}Found suspicious pattern: $pattern${NC} (${lines_count} matches)"
    else
      echo -e "No matches found." >> "$OUTPUT_FILE"
    fi
  done
}

# Scan for obfuscated strings and encoded data
scan_obfuscated_content() {
  echo -e "\n${BLUE}Scanning for obfuscated strings and encoded data...${NC}"
  echo -e "\n## Obfuscated Content Detection" >> "$OUTPUT_FILE"
  
  # Look for potential hex-encoded strings
  echo -e "\n### Potential Hex-Encoded Strings" >> "$OUTPUT_FILE"
  hex_strings=$(rg --no-heading --glob "!.git/" "[0-9a-fA-F]{24,}" "$PLUGIN_DIR" -n 2>/dev/null | head -n 20 || echo "")
  
  if [ -n "$hex_strings" ]; then
    echo "$hex_strings" >> "$OUTPUT_FILE"
    echo -e "${YELLOW}Found potential hex-encoded strings${NC}"
    
    # Try to decode all hex strings - CRITICAL CHECK, ALWAYS RUN!
    echo -e "\n#### Decoded Hex Samples:" >> "$OUTPUT_FILE"
    
    # Extract the strings and try to decode
    echo "$hex_strings" | grep -o "[0-9a-fA-F]\{24,\}" | head -n 10 | while read -r hex_str; do
      echo -e "\nHex string: ${hex_str:0:32}..." >> "$OUTPUT_FILE"
      decoded=$(echo "$hex_str" | xxd -r -p 2>/dev/null | strings || echo "Unable to decode")
      echo "Decoded: $decoded" >> "$OUTPUT_FILE"
      
      # Check for suspicious content in decoded string - CRITICAL CHECK
      if echo "$decoded" | grep -q -E 'exec|eval|curl|wget|http|bash|system|sh|python|ruby|perl|nc |netcat'; then
        echo -e "${RED}CRITICAL: Malicious content found in decoded hex string!${NC}"
        echo "CRITICAL SECURITY THREAT: Malicious content found in decoded hex!" >> "$OUTPUT_FILE"
        echo "Decoded malicious content: $decoded" >> "$OUTPUT_FILE"
      fi
    done
  else
    echo "No suspicious hex strings found." >> "$OUTPUT_FILE"
  fi
  
  # Look for potential base64-encoded strings - THIS IS CRITICAL TO CHECK
  echo -e "\n### Potential Base64-Encoded Strings" >> "$OUTPUT_FILE"
  base64_strings=$(rg --no-heading --glob "!.git/" "[A-Za-z0-9+/=]{30,}" "$PLUGIN_DIR" -n 2>/dev/null || echo "")
  
  if [ -n "$base64_strings" ]; then
    echo "$base64_strings" | head -n 20 >> "$OUTPUT_FILE"
    echo -e "${YELLOW}Found potential base64-encoded strings${NC}"
    
    # ALWAYS try to decode base64 strings - THIS IS CRITICAL!
    echo -e "\n#### Decoded Base64 Samples:" >> "$OUTPUT_FILE"
    
    # Save full results to a file for reference
    base64_file=$(mktemp)
    echo "$base64_strings" > "$base64_file"
    echo "Full base64 strings saved to: $base64_file" >> "$OUTPUT_FILE"
    
    # Extract the strings and try to decode all of them
    echo "$base64_strings" | grep -o "[A-Za-z0-9+/=]\{30,\}" | while read -r base64_str; do
      # Skip strings that are too long (likely not valid base64)
      if [ ${#base64_str} -gt 1000 ]; then
        continue
      fi
      
      echo -e "\nBase64 string: ${base64_str:0:32}..." >> "$OUTPUT_FILE"
      decoded=$(echo "$base64_str" | base64 -d 2>/dev/null | strings || echo "Unable to decode")
      
      # Skip if we couldn't decode it
      if [ "$decoded" = "Unable to decode" ]; then
        continue
      fi
      
      echo "Decoded: $decoded" >> "$OUTPUT_FILE"
      
      # Check for suspicious content in decoded string - CRITICAL CHECK
      if echo "$decoded" | grep -q -E 'exec|eval|curl|wget|http|bash|system|sh |python|ruby|perl|\.decode|nc |netcat'; then
        echo -e "${RED}CRITICAL: MALICIOUS CODE found in decoded base64 string!${NC}"
        echo "CRITICAL SECURITY THREAT: Malicious code found in decoded base64!" >> "$OUTPUT_FILE"
        echo "Decoded malicious content: $decoded" >> "$OUTPUT_FILE"
        
        # Add location information
        location=$(grep -n "$base64_str" "$base64_file" | head -n 1)
        echo "Located at: $location" >> "$OUTPUT_FILE"
      fi
    done
  else
    echo "No suspicious base64 strings found." >> "$OUTPUT_FILE"
  fi
  
  # Check for multi-step obfuscation (very suspicious)
  echo -e "\n### Multi-Step Obfuscation Detection" >> "$OUTPUT_FILE"
  
  # Find places where variables are assigned encoded content and later executed
  encoded_vars=$(rg --no-heading --glob "!.git/" -n "let\s+[a-zA-Z0-9_:]+\s*=.*['\"][A-Za-z0-9+/=]{20,}['\"]" "$PLUGIN_DIR" 2>/dev/null || echo "")
  
  if [ -n "$encoded_vars" ]; then
    echo "$encoded_vars" >> "$OUTPUT_FILE"
    echo -e "${YELLOW}Found variables containing encoded content${NC}"
    
    # Extract variable names for further analysis
    while read -r line; do
      # Extract filename and line number
      file_info=$(echo "$line" | cut -d':' -f1-2)
      file_path=$(echo "$file_info" | cut -d':' -f1)
      line_num=$(echo "$file_info" | cut -d':' -f2)
      
      # Extract variable name
      var_name=$(echo "$line" | grep -o "let\s\+[a-zA-Z0-9_:]\+" | sed 's/let\s\+//')
      
      # Check next 20 lines for execute/eval of this variable
      next_lines=$(tail -n +$line_num "$file_path" | head -n 20)
      
      echo -e "\nChecking for execution of encoded content in $file_path:$line_num" >> "$OUTPUT_FILE"
      echo "Variable: $var_name" >> "$OUTPUT_FILE"
      
      # Check if the variable is executed
      if echo "$next_lines" | grep -q -E "exec.*$var_name|eval.*$var_name|system.*$var_name"; then
        echo -e "${RED}CRITICAL: Encoded content is executed! Likely malicious code!${NC}"
        echo "CRITICAL SECURITY THREAT: Encoded content is executed in $file_path:$line_num" >> "$OUTPUT_FILE"
        
        # Extract the execution line
        exec_line=$(echo "$next_lines" | grep -E "exec.*$var_name|eval.*$var_name|system.*$var_name" | head -n 1)
        echo "Execution: $exec_line" >> "$OUTPUT_FILE"
        
        # Extract the encoded content
        encoded_content=$(echo "$line" | grep -o "['\"][A-Za-z0-9+/=]\{20,\}['\"]" | sed 's/^['\''"]//;s/['\''"]$//')
        echo "Encoded content: ${encoded_content:0:50}..." >> "$OUTPUT_FILE"
        
        # Try to decode
        decoded=$(echo "$encoded_content" | base64 -d 2>/dev/null | strings || echo "Unable to decode")
        echo "Decoded: $decoded" >> "$OUTPUT_FILE"
      fi
    done <<< "$encoded_vars"
  else
    echo "No variables with encoded content found." >> "$OUTPUT_FILE"
  fi
}

# Scan for suspicious file permissions
scan_suspicious_permissions() {
  echo -e "\n${BLUE}Scanning for suspicious file permissions...${NC}"
  echo -e "\n## Suspicious File Permissions" >> "$OUTPUT_FILE"
  
  # Find executable files outside of expected locations
  echo -e "\n### Unexpected Executable Files" >> "$OUTPUT_FILE"
  # Use platform-appropriate permission test
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS permission check
    unexpected_execs=$(find "$PLUGIN_DIR" -type f -perm +111 -not -path "*/\.git/*" \
      -not -name "*.sh" -not -name "run-*" -not -name "test" \
      -not -name "*.bash" -not -name "*.pl" -not -name "*.py" \
      -not -path "*/bin/*" -not -path "*/node_modules/*" | sort)
  else
    # Linux permission check
    unexpected_execs=$(find "$PLUGIN_DIR" -type f -perm /111 -not -path "*/\.git/*" \
      -not -name "*.sh" -not -name "run-*" -not -name "test" \
      -not -name "*.bash" -not -name "*.pl" -not -name "*.py" \
      -not -path "*/bin/*" -not -path "*/node_modules/*" | sort)
  fi
  
  if [ -n "$unexpected_execs" ]; then
    echo "$unexpected_execs" | sed 's/^/- /' >> "$OUTPUT_FILE"
    echo -e "${YELLOW}Found $(echo "$unexpected_execs" | wc -l | tr -d ' ') files with unexpected executable permissions${NC}"
  else
    echo "No files with unexpected executable permissions found." >> "$OUTPUT_FILE"
  fi
  
  # Find recently modified files
  if [ "$DEEP_SCAN" = true ]; then
    echo -e "\n### Recently Modified Files (last 7 days)" >> "$OUTPUT_FILE"
    recent_files=$(find "$PLUGIN_DIR" -type f -mtime -7 -not -path "*/\.git/*" | sort)
    
    if [ -n "$recent_files" ]; then
      echo "$recent_files" | sed 's/^/- /' >> "$OUTPUT_FILE"
      echo -e "${YELLOW}Found $(echo "$recent_files" | wc -l | tr -d ' ') recently modified files${NC}"
    else
      echo "No recently modified files found." >> "$OUTPUT_FILE"
    fi
  fi
}

# Scan for suspicious URLs
scan_suspicious_urls() {
  echo -e "\n${BLUE}Scanning for suspicious URLs...${NC}"
  echo -e "\n## Suspicious URLs" >> "$OUTPUT_FILE"
  
  # Find URLs in code
  url_pattern='https?://[a-zA-Z0-9./?=_%:-]*'
  urls=$(rg --no-heading --glob "!.git/" "$url_pattern" "$PLUGIN_DIR" -n 2>/dev/null || echo "")
  
  if [ -n "$urls" ]; then
    # Extract unique domains for analysis
    echo -e "\n### Unique Domains" >> "$OUTPUT_FILE"
    echo "$urls" | grep -o "$url_pattern" | 
      sed 's|https\?://\([^:/]*\).*|\1|' | 
      sort | uniq -c | sort -nr |
      head -n 30 >> "$OUTPUT_FILE"
    
    # Look for potentially suspicious domains (uncommon TLDs, etc.)
    echo -e "\n### Potentially Suspicious Domains" >> "$OUTPUT_FILE"
    suspicious_domains=$(echo "$urls" | grep -o "$url_pattern" | 
      grep -i -E '\.xyz|\.top|\.club|\.cc|\.tk|\.ml|\.ga|\.cf|\.gq|\.info|ip address|raw\.githubusercontent\.com' || echo "")
    
    if [ -n "$suspicious_domains" ]; then
      echo "$suspicious_domains" | sort | uniq >> "$OUTPUT_FILE"
      echo -e "${YELLOW}Found potentially suspicious URLs${NC}"
    else
      echo "No suspicious domains found." >> "$OUTPUT_FILE"
    fi
  else
    echo "No URLs found." >> "$OUTPUT_FILE"
  fi
}

# Scan for potential backdoors
scan_backdoors() {
  if [ "$DEEP_SCAN" = true ]; then
    echo -e "\n${BLUE}Scanning for potential backdoors...${NC}"
    echo -e "\n## Potential Backdoors" >> "$OUTPUT_FILE"
    
    # Look for functions that might handle HTTP requests or command execution
    echo -e "\n### Suspicious Function Patterns" >> "$OUTPUT_FILE"
    
    backdoor_patterns=(
      "function.*handle.*request"
      "function.*exec.*command"
      "function.*remote.*command"
      "function.*eval.*input"
      "if.*getenv.*{.*exec"
      "if.*socket.*{.*eval"
    )
    
    for pattern in "${backdoor_patterns[@]}"; do
      echo -e "\n#### Pattern: \`$pattern\`" >> "$OUTPUT_FILE"
      
      results=$(rg --no-heading --glob "!.git/" -n "$pattern" "$PLUGIN_DIR" 2>/dev/null || echo "")
      
      if [ -n "$results" ]; then
        echo "$results" | head -n 10 >> "$OUTPUT_FILE"
        echo -e "${YELLOW}Found potential backdoor pattern: $pattern${NC}"
      else
        echo "No matches found." >> "$OUTPUT_FILE"
      fi
    done
  fi
}

# Generate summary
generate_summary() {
  echo -e "\n${BLUE}Generating summary...${NC}"
  echo -e "\n## Summary" >> "$OUTPUT_FILE"
  
  # Count suspicious findings
  suspicious_patterns=$(grep -c -E 'Found suspicious pattern|WARNING:' "$OUTPUT_FILE" || echo "0")
  executable_files=$(grep -c "files with unexpected executable permissions" "$OUTPUT_FILE" || echo "0")
  suspicious_urls=$(grep -c "Found potentially suspicious URLs" "$OUTPUT_FILE" || echo "0")
  
  echo -e "- Suspicious Code Patterns: $suspicious_patterns" >> "$OUTPUT_FILE"
  echo -e "- Unexpected Executable Files: $executable_files" >> "$OUTPUT_FILE"
  echo -e "- Suspicious URLs: $suspicious_urls" >> "$OUTPUT_FILE"
  
  total_issues=$((suspicious_patterns + executable_files + suspicious_urls))
  
  if [ $total_issues -gt 0 ]; then
    echo -e "\n${YELLOW}Found $total_issues potential security issues.${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "Please review the full report for details." | tee -a "$OUTPUT_FILE"
  else
    echo -e "\n${GREEN}No suspicious patterns detected.${NC}" | tee -a "$OUTPUT_FILE"
  fi
  
  echo -e "\nFull report available at: $OUTPUT_FILE"
}

# Main function
main() {
  # Parse arguments
  PLUGIN_DIR=""
  
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help)
        show_help
        ;;
      --output)
        shift
        OUTPUT_FILE="$1"
        shift
        ;;
      --deep)
        DEEP_SCAN=true
        shift
        ;;
      -*)
        echo -e "${RED}Unknown option:${NC} $1"
        show_help
        ;;
      *)
        if [ -z "$PLUGIN_DIR" ]; then
          PLUGIN_DIR="$1"
        else
          echo -e "${RED}Error: Multiple plugin directories specified${NC}"
          show_help
        fi
        shift
        ;;
    esac
  done
  
  # Set default plugin directory if not specified
  PLUGIN_DIR="${PLUGIN_DIR:-$HOME/.vim/plugged}"
  
  if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${RED}Error: Plugin directory does not exist:${NC} $PLUGIN_DIR"
    exit 1
  fi
  
  echo -e "${BLUE}Vim Plugin Suspicious Pattern Detector${NC}"
  echo -e "Target: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Output: ${YELLOW}$OUTPUT_FILE${NC}"
  echo -e "Deep Scan: ${YELLOW}$DEEP_SCAN${NC}"
  
  check_requirements
  initialize_output
  
  scan_basic_patterns
  scan_obfuscated_content
  scan_suspicious_permissions
  scan_suspicious_urls
  scan_backdoors
  
  generate_summary
  
  echo -e "\n${GREEN}Scan completed!${NC}"
}

# Run the main function with all arguments
main "$@"