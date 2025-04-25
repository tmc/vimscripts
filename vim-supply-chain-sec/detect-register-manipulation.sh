#!/bin/bash
#
# Vim Plugin Register Manipulation Detector
# 
# This script specializes in detecting register manipulation techniques used
# in malicious Vim plugins to hide command execution.
#
# Usage: ./detect-register-manipulation.sh [PLUGIN_DIR]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/register-manipulation-report.txt"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Initialize report
initialize_report() {
  echo "# Vim Plugin Register Manipulation Detector" > "$REPORT_FILE"
  echo "Date: $SCAN_DATE" >> "$REPORT_FILE"
  echo "Target Directory: $PLUGIN_DIR" >> "$REPORT_FILE"
  echo "----------------------------------------" >> "$REPORT_FILE"
}

# Scan for register manipulation techniques
scan_register_manipulation() {
  echo -e "\n${BLUE}Scanning for register manipulation techniques...${NC}"
  echo -e "\n## Register Manipulation Patterns" >> "$REPORT_FILE"
  
  # Patterns for register manipulation
  local patterns=(
    # Setting register content
    "let.*@[a-z].*=.*['\"]!.*['\"]"                # Command execution via register
    "let.*@[a-z].*=.*['\"]call.*['\"]"             # Call command via register
    "let.*@[a-z].*=.*['\"]exec.*['\"]"             # Exec command via register
    "let.*@[a-z].*=.*['\"]sy.*['\"]"               # System command via register
    "let.*@[a-z].*=.*a:action"                     # Variable command passed to register
    
    # Saving and restoring registers - common in malicious code
    "let.*save_reg.*=.*@[a-z]"                     # Save register before manipulation
    "let.*@[a-z].*=.*save_reg"                     # Restore register after manipulation
    
    # Direct register execution
    "normal.*@[a-z]"                               # Execute register content
    "silent.*normal.*@[a-z]"                       # Silently execute register content
  )
  
  local malicious_count=0
  
  for pattern in "${patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$REPORT_FILE"
    
    files=$(find "$PLUGIN_DIR" -name "*.vim" -exec grep -l "$pattern" {} \; 2>/dev/null || echo "")
    
    if [ -n "$files" ]; then
      echo -e "${YELLOW}Found potential register manipulation!${NC}" | tee -a "$REPORT_FILE"
      echo -e "Files:" >> "$REPORT_FILE"
      echo "$files" | sed 's/^/- /' >> "$REPORT_FILE"
      
      # For each file, perform deeper analysis
      for file in $files; do
        echo -e "\nAnalyzing $file:" >> "$REPORT_FILE"
        
        # Extract register manipulation context
        context=$(grep -n -B 5 -A 5 "$pattern" "$file")
        echo -e "Context:" >> "$REPORT_FILE"
        echo "$context" >> "$REPORT_FILE"
        
        # Check for command execution patterns within the same function
        function_name=$(echo "$context" | grep -o "function.*s:[a-zA-Z0-9_]*" | head -1 | sed 's/function[[:space:]]*//')
        
        if [ -n "$function_name" ]; then
          echo -e "Checking function: $function_name" >> "$REPORT_FILE"
          func_content=$(grep -n -A 20 "function.*$function_name" "$file")
          
          # Look for both register setting and execution in the same function
          if echo "$func_content" | grep -q "let.*@[a-z]" && echo "$func_content" | grep -q "normal.*@[a-z]"; then
            echo -e "${RED}CRITICAL: Function contains both register setting AND execution!${NC}" | tee -a "$REPORT_FILE"
            
            # Check if register content includes shell commands
            if echo "$func_content" | grep -q "let.*@[a-z].*=.*['\"]!.*['\"]"; then
              echo -e "${RED}HIGHLY MALICIOUS: Register used to execute shell commands!${NC}" | tee -a "$REPORT_FILE"
              shell_cmd=$(echo "$func_content" | grep "let.*@[a-z].*=.*['\"]!.*['\"]" | grep -o "'![^']*'" | sed "s/'//g")
              echo -e "Shell command: $shell_cmd" >> "$REPORT_FILE"
              malicious_count=$((malicious_count + 1))
            fi
            
            # Check for indirect command construction
            if echo "$func_content" | grep -q "let.*=.*['\"]sh -c"; then
              echo -e "${RED}HIGHLY MALICIOUS: Function constructs shell command!${NC}" | tee -a "$REPORT_FILE"
              echo -e "Command construction:" >> "$REPORT_FILE"
              echo "$func_content" | grep -n "let.*=.*['\"]sh -c" >> "$REPORT_FILE"
              malicious_count=$((malicious_count + 1))
            fi
          fi
        fi
      done
    else
      echo -e "No matches found for this pattern." >> "$REPORT_FILE"
    fi
  done
  
  echo -e "\n${BLUE}Register Manipulation Summary:${NC}" | tee -a "$REPORT_FILE"
  echo -e "- Malicious Instances Found: ${malicious_count}" | tee -a "$REPORT_FILE"
  
  if [ $malicious_count -gt 0 ]; then
    echo -e "${RED}SECURITY ALERT: Found potential malicious register manipulation techniques!${NC}" | tee -a "$REPORT_FILE"
    echo -e "This technique is used to hide command execution in malicious Vim plugins." | tee -a "$REPORT_FILE"
  else
    echo -e "${GREEN}No malicious register manipulation found.${NC}" | tee -a "$REPORT_FILE"
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
  
  echo -e "${BLUE}Vim Plugin Register Manipulation Detector${NC}"
  echo -e "Target: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Date: ${SCAN_DATE}"
  
  initialize_report
  scan_register_manipulation
  
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