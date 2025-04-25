#!/bin/bash
#
# Vim Plugin Feedkeys Backdoor Detector
# 
# This script specializes in detecting feedkeys-based backdoors used
# in malicious Vim plugins to hide command execution.
#
# Usage: ./detect-feedkeys-backdoors.sh [PLUGIN_DIR]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/feedkeys-backdoor-report.txt"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Initialize report
initialize_report() {
  echo "# Vim Plugin Feedkeys Backdoor Detector" > "$REPORT_FILE"
  echo "Date: $SCAN_DATE" >> "$REPORT_FILE"
  echo "Target Directory: $PLUGIN_DIR" >> "$REPORT_FILE"
  echo "----------------------------------------" >> "$REPORT_FILE"
}

# Scan for feedkeys-based backdoors
scan_feedkeys_backdoors() {
  echo -e "\n${BLUE}Scanning for feedkeys-based backdoors...${NC}"
  echo -e "\n## Feedkeys-Based Command Execution" >> "$REPORT_FILE"
  
  # Patterns for feedkeys-based backdoors
  local patterns=(
    # Different variations of feedkeys usage for command execution
    "feedkeys.*:.*!"                           # Feedkeys to execute shell command
    "feedkeys.*:.*system"                      # Feedkeys to execute system command
    "feedkeys.*:.*exec"                        # Feedkeys to execute command
    "feedkeys.*:.*h "                          # Potential help system abuse
    "feedkeys.*:.*help.*|"                     # Help piped to command
    "let.*help_cmd.*=.*['\"]h.*!.*['\"]"      # Help command with shell execution
    "let.*help_cmd.*=.*['\"]h.*|.*['\"]"      # Help command with piped command
    "feedkeys.*CR.*Esc"                        # Complete feedkeys command sequence
  )
  
  local malicious_count=0
  
  for pattern in "${patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$REPORT_FILE"
    
    files=$(find "$PLUGIN_DIR" -name "*.vim" -exec grep -l "$pattern" {} \; 2>/dev/null || echo "")
    
    if [ -n "$files" ]; then
      echo -e "${YELLOW}Found potential feedkeys command execution!${NC}" | tee -a "$REPORT_FILE"
      echo -e "Files:" >> "$REPORT_FILE"
      echo "$files" | sed 's/^/- /' >> "$REPORT_FILE"
      
      # For each file, perform deeper analysis
      for file in $files; do
        echo -e "\nAnalyzing $file:" >> "$REPORT_FILE"
        
        # Extract feedkeys context
        context=$(grep -n -B 5 -A 5 "$pattern" "$file")
        echo -e "Context:" >> "$REPORT_FILE"
        echo "$context" >> "$REPORT_FILE"
        
        # Check for shell command execution via feedkeys
        if grep -q "feedkeys.*:.*!.*>/tmp" "$file" || grep -q "feedkeys.*:.*!.*>/var/tmp" "$file"; then
          echo -e "${RED}CRITICAL: Feedkeys used to write to /tmp or /var/tmp!${NC}" | tee -a "$REPORT_FILE"
          grep -n "feedkeys.*:.*!.*>/tmp\|feedkeys.*:.*!.*>/var/tmp" "$file" >> "$REPORT_FILE"
          malicious_count=$((malicious_count + 1))
        fi
        
        # Check for help system abuse with shell commands
        if grep -q "let.*help_cmd.*=.*['\"]h.*|.*!.*>/tmp" "$file" || grep -q "feedkeys.*:.*h.*|.*!.*>/tmp" "$file"; then
          echo -e "${RED}CRITICAL: Help system being abused to execute shell commands!${NC}" | tee -a "$REPORT_FILE"
          grep -n "let.*help_cmd.*=.*['\"]h.*|.*!.*>/tmp\|feedkeys.*:.*h.*|.*!.*>/tmp" "$file" >> "$REPORT_FILE"
          malicious_count=$((malicious_count + 1))
        fi
        
        # Check for suspicious trigger conditions
        trigger_conditions=$(grep -n -A 5 "if.*=~#.*'[^']*sync[^']*'\|if.*=~#.*\"[^\"]*sync[^\"]*\"" "$file")
        if [ -n "$trigger_conditions" ] && grep -q "feedkeys" "$file"; then
          echo -e "${RED}CRITICAL: Found trigger word with feedkeys execution!${NC}" | tee -a "$REPORT_FILE"
          echo -e "Trigger condition:" >> "$REPORT_FILE"
          echo "$trigger_conditions" >> "$REPORT_FILE"
          
          # Extract the function called by the trigger
          func_name=$(echo "$trigger_conditions" | grep -o "call.*s:[a-zA-Z0-9_]\+" | head -1 | sed 's/call.*s:/s:/')
          
          if [ -n "$func_name" ]; then
            echo -e "Function called by trigger:" >> "$REPORT_FILE"
            grep -n -A 20 "function.*$func_name" "$file" | head -30 >> "$REPORT_FILE"
          fi
          
          malicious_count=$((malicious_count + 1))
        fi
      done
    else
      echo -e "No matches found for this pattern." >> "$REPORT_FILE"
    fi
  done
  
  echo -e "\n${BLUE}Feedkeys Backdoor Summary:${NC}" | tee -a "$REPORT_FILE"
  echo -e "- Malicious Instances Found: ${malicious_count}" | tee -a "$REPORT_FILE"
  
  if [ $malicious_count -gt 0 ]; then
    echo -e "${RED}SECURITY ALERT: Found potential feedkeys-based backdoors!${NC}" | tee -a "$REPORT_FILE"
    echo -e "This technique is used to hide command execution in malicious Vim plugins." | tee -a "$REPORT_FILE"
  else
    echo -e "${GREEN}No feedkeys-based backdoors found.${NC}" | tee -a "$REPORT_FILE"
  fi
}

# Main function
main() {
  # Set plugin directory (default to ~/.vim/plugged if not specified)
  PLUGIN_DIR="${1:-$HOME/.vim/plugged}"
  
  if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${RED}Error: Plugin directory does not exist:${NC} $PLUGIN_DIR"
    exit 1
  fi
  
  echo -e "${BLUE}Vim Plugin Feedkeys Backdoor Detector${NC}"
  echo -e "Target: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Date: ${SCAN_DATE}"
  
  initialize_report
  scan_feedkeys_backdoors
  
  echo -e "\n${GREEN}Scan completed!${NC}"
  echo -e "Report saved to: ${YELLOW}$REPORT_FILE${NC}"
  
  # Return exit code based on findings
  if [ $malicious_count -gt 0 ]; then
    exit 1
  else
    exit 0
  fi
}

# Run the main function with all arguments
main "$@"