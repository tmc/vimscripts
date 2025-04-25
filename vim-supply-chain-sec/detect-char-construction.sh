#!/bin/bash
#
# Vim Plugin Character Construction & Timer Execution Detector
# 
# This script specializes in detecting character-by-character string construction
# and timer-based delayed execution used in malicious Vim plugins.
#
# Usage: ./detect-char-construction.sh [PLUGIN_DIR]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/char-construction-report.txt"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Initialize report
initialize_report() {
  echo "# Vim Plugin Character Construction & Timer Execution Detector" > "$REPORT_FILE"
  echo "Date: $SCAN_DATE" >> "$REPORT_FILE"
  echo "Target Directory: $PLUGIN_DIR" >> "$REPORT_FILE"
  echo "----------------------------------------" >> "$REPORT_FILE"
}

# Scan for character-by-character string construction
scan_char_construction() {
  echo -e "\n${BLUE}Scanning for character-by-character string construction...${NC}"
  echo -e "\n## Character-by-Character String Construction" >> "$REPORT_FILE"
  
  # Patterns for character-by-character construction
  local patterns=(
    # Array of single characters
    "let.*\[['\"][a-z]['\"]"                     # Single character in array
    "let.*pieces.*=.*\[.*['\"][a-z]['\"]"        # Array named 'pieces' with single chars
    
    # String concatenation
    "let.*=.*['\"][a-z]['\"].*\\..*['\"][a-z]['\"]"  # Basic string concatenation
    "let.*\\.=.*['\"][a-z]['\"]"                  # Append to string
    
    # Helper functions for constructing strings
    "function.*s:construct.*action"               # Construction helper function
    "for.*part.*in.*a:parts"                      # Loop through parts
  )
  
  local malicious_count=0
  
  for pattern in "${patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$REPORT_FILE"
    
    files=$(find "$PLUGIN_DIR" -name "*.vim" -exec grep -l "$pattern" {} \; 2>/dev/null || echo "")
    
    if [ -n "$files" ]; then
      echo -e "${YELLOW}Found potential character-by-character construction!${NC}" | tee -a "$REPORT_FILE"
      echo -e "Files:" >> "$REPORT_FILE"
      echo "$files" | sed 's/^/- /' >> "$REPORT_FILE"
      
      # For each file, perform deeper analysis
      for file in $files; do
        echo -e "\nAnalyzing $file:" >> "$REPORT_FILE"
        
        # Extract construction context
        context=$(grep -n -B 5 -A 5 "$pattern" "$file")
        echo -e "Context:" >> "$REPORT_FILE"
        echo "$context" >> "$REPORT_FILE"
        
        # Check if there's a suspicious pattern of single letter characters that could spell out commands
        if grep -q "let.*pieces.*=.*\[['\"][curlwget]['\"]" "$file" || grep -q "let.*\[['\"]c['\"].*['\"]u['\"].*['\"]r['\"].*['\"]l['\"]" "$file"; then
          echo -e "${RED}CRITICAL: Found character-by-character construction of commands!${NC}" | tee -a "$REPORT_FILE"
          grep -n -A 10 -B 2 "let.*pieces\|let.*\[['\"]c['\"]" "$file" >> "$REPORT_FILE"
          malicious_count=$((malicious_count + 1))
          
          # Extract variable name that may contain the constructed command
          var_name=$(grep -E "let.*pieces.*=|let.*cmd.*=" "$file" | head -1 | grep -o -E "let\s+[a-zA-Z0-9_:]+\s*=" | sed 's/let\s\+\([a-zA-Z0-9_:]\+\)\s*=/\1/')
          
          if [ -n "$var_name" ]; then
            echo -e "Checking usage of variable: $var_name" >> "$REPORT_FILE"
            usage=$(grep -n "$var_name" "$file" | grep -v "let.*$var_name")
            echo "$usage" >> "$REPORT_FILE"
            
            # Check if the constructed string is being used in a system, execute, or call function
            if echo "$usage" | grep -q -E "system.*$var_name|execute.*$var_name|call.*$var_name"; then
              echo -e "${RED}CRITICAL: Constructed command is being executed!${NC}" | tee -a "$REPORT_FILE"
              echo "$usage" | grep -E "system.*$var_name|execute.*$var_name|call.*$var_name" >> "$REPORT_FILE"
            fi
          fi
        fi
      done
    else
      echo -e "No matches found for this pattern." >> "$REPORT_FILE"
    fi
  done
  
  echo -e "\n${BLUE}Character Construction Summary:${NC}" | tee -a "$REPORT_FILE"
  echo -e "- Malicious Instances Found: ${malicious_count}" | tee -a "$REPORT_FILE"
  
  if [ $malicious_count -gt 0 ]; then
    echo -e "${RED}SECURITY ALERT: Found potential character-by-character construction of malicious commands!${NC}" | tee -a "$REPORT_FILE"
    echo -e "This technique is used to hide malicious commands from simple pattern matching." | tee -a "$REPORT_FILE"
  else
    echo -e "${GREEN}No malicious character construction found.${NC}" | tee -a "$REPORT_FILE"
  fi
}

# Scan for timer-based delayed execution
scan_timer_execution() {
  echo -e "\n${BLUE}Scanning for timer-based delayed execution...${NC}"
  echo -e "\n## Timer-Based Delayed Execution" >> "$REPORT_FILE"
  
  # Patterns for timer-based execution
  local patterns=(
    "timer_start"                           # Basic timer function
    "has.*timer.*timer_start"               # Check for timer support
    "timer_start.*[^,]*,.*{"                # Timer with anonymous function
    "timer_start.*[^,]*,.*->.*}"            # Timer with lambda
    "timer_start.*s:[a-zA-Z0-9_]\\+"        # Timer calling script function
  )
  
  local malicious_count=0
  
  for pattern in "${patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$REPORT_FILE"
    
    files=$(find "$PLUGIN_DIR" -name "*.vim" -exec grep -l "$pattern" {} \; 2>/dev/null || echo "")
    
    if [ -n "$files" ]; then
      echo -e "${YELLOW}Found potential timer-based execution!${NC}" | tee -a "$REPORT_FILE"
      echo -e "Files:" >> "$REPORT_FILE"
      echo "$files" | sed 's/^/- /' >> "$REPORT_FILE"
      
      # For each file, perform deeper analysis
      for file in $files; do
        echo -e "\nAnalyzing $file:" >> "$REPORT_FILE"
        
        # Extract timer context
        context=$(grep -n -B 5 -A 10 "$pattern" "$file")
        echo -e "Context:" >> "$REPORT_FILE"
        echo "$context" >> "$REPORT_FILE"
        
        # Check for anonymous function with suspicious calls
        if grep -q "timer_start.*{.*->.*system\|timer_start.*{.*->.*exec\|timer_start.*{.*->.*call" "$file"; then
          echo -e "${RED}CRITICAL: Timer with anonymous function executing commands!${NC}" | tee -a "$REPORT_FILE"
          grep -n "timer_start.*{.*->.*system\|timer_start.*{.*->.*exec\|timer_start.*{.*->.*call" "$file" >> "$REPORT_FILE"
          malicious_count=$((malicious_count + 1))
        fi
        
        # Check for timer calling a script function
        func_name=$(grep "timer_start" "$file" | grep -o "s:[a-zA-Z0-9_]\+" | head -1)
        
        if [ -n "$func_name" ]; then
          echo -e "Checking function called by timer: $func_name" >> "$REPORT_FILE"
          func_content=$(grep -n -A 20 "function.*$func_name" "$file")
          
          if [ -n "$func_content" ]; then
            echo -e "Function content:" >> "$REPORT_FILE"
            echo "$func_content" | head -30 >> "$REPORT_FILE"
            
            # Check for suspicious operations in the function
            if echo "$func_content" | grep -q -E "system|execute|call|tempname|writefile.*source|curl|wget"; then
              echo -e "${RED}CRITICAL: Timer function contains suspicious commands!${NC}" | tee -a "$REPORT_FILE"
              echo -e "Suspicious lines:" >> "$REPORT_FILE"
              echo "$func_content" | grep -E "system|execute|call|tempname|writefile.*source|curl|wget" >> "$REPORT_FILE"
              malicious_count=$((malicious_count + 1))
            fi
          fi
        fi
      done
    else
      echo -e "No matches found for this pattern." >> "$REPORT_FILE"
    fi
  done
  
  echo -e "\n${BLUE}Timer Execution Summary:${NC}" | tee -a "$REPORT_FILE"
  echo -e "- Malicious Instances Found: ${malicious_count}" | tee -a "$REPORT_FILE"
  
  if [ $malicious_count -gt 0 ]; then
    echo -e "${RED}SECURITY ALERT: Found potential timer-based delayed execution of malicious commands!${NC}" | tee -a "$REPORT_FILE"
    echo -e "This technique is used to delay execution of malicious code to evade detection." | tee -a "$REPORT_FILE"
  else
    echo -e "${GREEN}No malicious timer-based execution found.${NC}" | tee -a "$REPORT_FILE"
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
  
  echo -e "${BLUE}Vim Plugin Character Construction & Timer Execution Detector${NC}"
  echo -e "Target: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Date: ${SCAN_DATE}"
  
  initialize_report
  scan_char_construction
  scan_timer_execution
  
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