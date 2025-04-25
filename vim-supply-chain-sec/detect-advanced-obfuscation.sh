#!/bin/bash
#
# Advanced Obfuscation Detection for Vim Plugins
#
# This script scans for sophisticated obfuscation techniques
# commonly used in malicious vim plugins and supply chain attacks
#
# Usage: 
#   ./detect-advanced-obfuscation.sh [PLUGIN_DIR] [OPTIONS]
#
# Options:
#   --output FILE    Write results to FILE (default: advanced-obfuscation-report.txt)
#   --deep           Perform more thorough but slower analysis
#   --help           Display this help message

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/advanced-obfuscation-report.txt"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")
DEEP_SCAN=false
RISK_SCORE=0

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Display help message
show_help() {
  echo -e "${BLUE}Advanced Obfuscation Detection for Vim Plugins${NC}"
  echo -e "This script scans for sophisticated obfuscation techniques commonly used in malicious Vim plugins."
  echo ""
  echo -e "Usage: ./detect-advanced-obfuscation.sh [PLUGIN_DIR] [OPTIONS]"
  echo ""
  echo -e "Options:"
  echo -e "  --output FILE    Write results to FILE (default: advanced-obfuscation-report.txt)"
  echo -e "  --deep           Perform more thorough but slower analysis"
  echo -e "  --help           Display this help message"
  echo ""
  echo -e "Examples:"
  echo -e "  ./detect-advanced-obfuscation.sh ~/.vim/plugged"
  echo -e "  ./detect-advanced-obfuscation.sh ~/.vim/plugged --output report.txt --deep"
  exit 0
}

# Initialize output file
initialize_output() {
  echo "# Advanced Obfuscation Detection for Vim Plugins" > "$OUTPUT_FILE"
  echo "Date: $SCAN_DATE" >> "$OUTPUT_FILE"
  echo "Target Directory: $PLUGIN_DIR" >> "$OUTPUT_FILE"
  echo "Deep Scan: $DEEP_SCAN" >> "$OUTPUT_FILE"
  echo "----------------------------------------" >> "$OUTPUT_FILE"
}

# Check for recently modified files
scan_recent_modifications() {
  echo -e "\n${BLUE}Scanning for recently modified files...${NC}"
  echo -e "\n## Recently Modified Files" >> "$OUTPUT_FILE"
  
  # Find files modified in the past 30 days
  recent_files=$(find "$PLUGIN_DIR" -type f -not -path "*/\.git/*" -mtime -30 | sort)
  
  if [ -n "$recent_files" ]; then
    echo "$recent_files" | sed 's/^/- /' >> "$OUTPUT_FILE"
    echo -e "${YELLOW}Found $(echo "$recent_files" | wc -l | tr -d ' ') recently modified files${NC}"
    
    # Get more detailed timestamp info
    echo -e "\n### Detailed Timestamp Analysis" >> "$OUTPUT_FILE"
    
    # Use platform-appropriate stat command
    if [[ "$OSTYPE" == "darwin"* ]]; then
      # macOS
      echo "$recent_files" | xargs stat -f "%m %N" 2>/dev/null | sort -nr | head -20 >> "$OUTPUT_FILE"
    else
      # Linux
      echo "$recent_files" | xargs stat --format="%Y %n" 2>/dev/null | sort -nr | head -20 >> "$OUTPUT_FILE"
    fi
  else
    echo "No recently modified files found." >> "$OUTPUT_FILE"
  fi
}

# Scan for character-by-character command construction
scan_char_by_char() {
  echo -e "\n${BLUE}Scanning for character-by-character command construction...${NC}"
  echo -e "\n## Character-by-Character String Construction" >> "$OUTPUT_FILE"
  
  # Patterns for character concatenation
  concat_patterns=(
    # Array of single characters
    "let.*=[[:space:]]*\['[a-z]'[[:space:]]*,[[:space:]]*'[a-z]'"
    # String concatenation with single characters
    "let.*pieces.*=.*\[.*'[a-z]'"
    # String concatenation in a loop
    "for[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*in.*\.="
    # Common command construction patterns
    "let[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\.="
    # Single character string construction
    "join(.*map(.*,'.*')"
    # Regular string concatenation
    "s:construct.*action"
  )
  
  found_malicious=false
  
  for pattern in "${concat_patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$OUTPUT_FILE"
    
    # Try different grep variants based on availability
    if command -v grep &> /dev/null && grep -q -P '' /dev/null 2>/dev/null; then
      # System has grep with PCRE support
      results=$(grep -r -l -P "$pattern" --include="*.vim" "$PLUGIN_DIR" 2>/dev/null || echo "")
    else
      # Fallback to basic grep with extended regex
      results=$(grep -r -l -E "$pattern" --include="*.vim" "$PLUGIN_DIR" 2>/dev/null || echo "")
    fi
    
    if [ -n "$results" ]; then
      echo "$results" >> "$OUTPUT_FILE"
      echo -e "${RED}SUSPICIOUS: Found character-by-character construction${NC}"
      
      # For each matching file, extract the suspicious lines for context
      for file in $results; do
        echo -e "\nContext from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 5 -B 5 "$pattern" "$file" 2>/dev/null >> "$OUTPUT_FILE"
        
        # Flag especially suspicious files that have both character construction and system/execute
        if grep -q -E "system|execute|curl|wget|http|\!.*command|tempname.*source|writefile.*source" "$file"; then
          echo -e "${RED}CRITICAL: File contains both string construction AND command execution!${NC}" | tee -a "$OUTPUT_FILE"
          grep -n -E "system|execute|curl|wget|http|\!.*command|tempname.*source|writefile.*source" "$file" | head -5 >> "$OUTPUT_FILE"
          
          # Extract the variable being constructed
          var_name=$(grep -E "$pattern" "$file" | head -1 | grep -o -E "let\s+\w+\s*=" | sed -E 's/let\s+(\w+)\s*=/\1/')
          
          if [ -n "$var_name" ]; then
            # Look for where this variable is used
            echo -e "\nUsage of constructed variable:" >> "$OUTPUT_FILE"
            grep -n -E "$var_name.*system|$var_name.*execute|system.*$var_name|execute.*$var_name" "$file" >> "$OUTPUT_FILE"
          fi
          
          found_malicious=true
          RISK_SCORE=$((RISK_SCORE + 100))
        fi
      done
    else
      echo "No matches found for this pattern." >> "$OUTPUT_FILE"
    fi
  done
  
  if [ "$found_malicious" = true ]; then
    echo -e "\n${RED}CRITICAL SECURITY ISSUE: Found malicious character-by-character command construction!${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This is a common technique used to evade detection in malicious Vim plugins." >> "$OUTPUT_FILE"
  fi
}

# Scan for register manipulation for command execution
scan_register_manipulation() {
  echo -e "\n${BLUE}Scanning for register manipulation for command execution...${NC}"
  echo -e "\n## Register Manipulation" >> "$OUTPUT_FILE"
  
  # Look for patterns like: let @z = '!command' followed by normal @z
  echo -e "\n### Register-Based Command Execution" >> "$OUTPUT_FILE"
  
  # Find files with register assignment
  reg_patterns=(
    "let\s+@[a-z]\s*="
    "normal\s+@[a-z]"
    "let\s+@[a-z].*\!"
  )
  
  found_malicious=false
  
  for pattern in "${reg_patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$OUTPUT_FILE"
    
    results=$(grep -r -l -E "$pattern" --include="*.vim" "$PLUGIN_DIR" 2>/dev/null || echo "")
    
    if [ -n "$results" ]; then
      echo "$results" >> "$OUTPUT_FILE"
      
      # For each matching file, extract the suspicious lines for context
      for file in $results; do
        echo -e "\nContext from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 3 -B 3 "$pattern" "$file" 2>/dev/null >> "$OUTPUT_FILE"
        
        # Check if the file contains both register assignment AND normal @reg patterns
        if grep -q -E "let\s+@[a-z]\s*=" "$file" && grep -q -E "normal\s+.*@[a-z]" "$file"; then
          echo -e "${RED}CRITICAL: File contains both register assignment AND execution!${NC}" | tee -a "$OUTPUT_FILE"
          
          # Look for command execution in registers (! prefix indicates shell command)
          if grep -q -E "let\s+@[a-z]\s*=\s*['\"]!.*['\"]" "$file"; then
            echo -e "${RED}HIGHLY MALICIOUS: Register used to hide shell command execution!${NC}" | tee -a "$OUTPUT_FILE"
            grep -n -E "let\s+@[a-z]\s*=\s*['\"]!.*['\"]" "$file" >> "$OUTPUT_FILE"
            found_malicious=true
            RISK_SCORE=$((RISK_SCORE + 100))
          fi
          
          # Extract all register definitions and their usage
          echo -e "\nAll register definitions:" >> "$OUTPUT_FILE"
          grep -n -E "let\s+@[a-z]\s*=" "$file" >> "$OUTPUT_FILE"
          
          echo -e "\nAll register executions:" >> "$OUTPUT_FILE"
          grep -n -E "normal\s+.*@[a-z]" "$file" >> "$OUTPUT_FILE"
        fi
      done
    else
      echo "No matches found for this pattern." >> "$OUTPUT_FILE"
    fi
  done
  
  if [ "$found_malicious" = true ]; then
    echo -e "\n${RED}CRITICAL SECURITY ISSUE: Found malicious register manipulation for command execution!${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This is a dangerous technique used to hide command execution in malicious Vim plugins." >> "$OUTPUT_FILE"
  fi
}

# Scan for timer-based delayed execution
scan_delayed_execution() {
  echo -e "\n${BLUE}Scanning for delayed execution...${NC}"
  echo -e "\n## Delayed Execution Techniques" >> "$OUTPUT_FILE"
  
  delayed_patterns=(
    "timer_start"
    "setTimeout"
    "setInterval"
    "sleep.*system"
    "after.*execute"
    "call.*timer_"
  )
  
  found_malicious=false
  
  for pattern in "${delayed_patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$OUTPUT_FILE"
    
    results=$(grep -r -l -E "$pattern" --include="*.vim" "$PLUGIN_DIR" 2>/dev/null || echo "")
    
    if [ -n "$results" ]; then
      echo "$results" >> "$OUTPUT_FILE"
      echo -e "${YELLOW}Found delayed execution pattern${NC}"
      
      # Extract context for each file
      for file in $results; do
        echo -e "\nContext from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 5 -B 5 "$pattern" "$file" 2>/dev/null >> "$OUTPUT_FILE"
        
        # Check for callback functions or anonymous functions with command execution
        if grep -q -E "timer_start.*{.*->.*}" "$file"; then
          echo -e "${YELLOW}WARNING: Timer used with anonymous function in $file${NC}" | tee -a "$OUTPUT_FILE"
          
          # Extract the anonymous function
          anon_func=$(grep -n -E -A 5 "timer_start.*{.*->.*}" "$file")
          echo -e "\nAnonymous function:" >> "$OUTPUT_FILE"
          echo "$anon_func" >> "$OUTPUT_FILE"
          
          # Check if the anonymous function uses system/exec/call/tempname
          if echo "$anon_func" | grep -q -E "(system|exec|call|curl|wget|writefile.*source|tempname)"; then
            echo -e "${RED}CRITICAL SECURITY THREAT: Timer-based delayed execution of commands!${NC}" | tee -a "$OUTPUT_FILE"
            found_malicious=true
            RISK_SCORE=$((RISK_SCORE + 80))
          fi
        fi
        
        # Check for timer_start with function reference
        if grep -q -E "timer_start.*'s:" "$file"; then
          func_name=$(grep -E "timer_start.*'s:" "$file" | grep -o -E "s:[a-zA-Z0-9_]\+" | head -1)
          
          if [ -n "$func_name" ]; then
            echo -e "\nFunction called by timer:" >> "$OUTPUT_FILE"
            grep -n -A 15 "function.*$func_name" "$file" 2>/dev/null >> "$OUTPUT_FILE"
            
            # Check if the function contains command execution
            if grep -A 15 "function.*$func_name" "$file" 2>/dev/null | grep -q -E "(system|exec|call|curl|wget|tempname)"; then
              echo -e "${RED}CRITICAL SECURITY THREAT: Timer calls function with command execution!${NC}" | tee -a "$OUTPUT_FILE"
              found_malicious=true
              RISK_SCORE=$((RISK_SCORE + 80))
            fi
          fi
        fi
      done
    else
      echo "No matches found for this pattern." >> "$OUTPUT_FILE"
    fi
  done
  
  if [ "$found_malicious" = true ]; then
    echo -e "\n${RED}CRITICAL SECURITY ISSUE: Found delayed execution of malicious commands!${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This is a technique used to delay malicious behavior to evade detection." >> "$OUTPUT_FILE"
  fi
}

# Scan for tempfile execution (write and execute pattern)
scan_tempfile_execution() {
  echo -e "\n${BLUE}Scanning for tempfile execution...${NC}"
  echo -e "\n## Tempfile Execution Patterns" >> "$OUTPUT_FILE"
  
  # Look for tempname() followed by writefile() or source/execute
  tempcmd_files=$(grep -r -l -E "tempname\(\)|tempfile\(\)" --include="*.vim" "$PLUGIN_DIR" 2>/dev/null || echo "")
  
  found_malicious=false
  
  if [ -n "$tempcmd_files" ]; then
    echo -e "${YELLOW}Found files using tempname() or tempfile()${NC}"
    echo -e "Files with tempname/tempfile usage:" >> "$OUTPUT_FILE"
    echo "$tempcmd_files" | sed 's/^/- /' >> "$OUTPUT_FILE"
    
    # Check each file for suspicious patterns
    for file in $tempcmd_files; do
      echo -e "\nAnalyzing $file:" >> "$OUTPUT_FILE"
      
      # Get content
      content=$(cat "$file" 2>/dev/null)
      
      # Check for tempname used with source or execute
      if echo "$content" | grep -E -q "temp\w*.*source|source.*temp|execute.*temp|temp\w*.*execute"; then
        echo -e "${RED}CRITICAL: File appears to write to tempfile and then execute it!${NC}" | tee -a "$OUTPUT_FILE"
        echo -e "Suspicious sections from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 10 -B 10 "temp\w*.*source|source.*temp|execute.*temp|temp\w*.*execute" "$file" >> "$OUTPUT_FILE"
        found_malicious=true
        RISK_SCORE=$((RISK_SCORE + 90))
      fi
      
      # Check for tempname with system commands
      if echo "$content" | grep -E -q "temp\w*.*system|system.*temp"; then
        echo -e "${RED}CRITICAL: File uses tempname with system command execution!${NC}" | tee -a "$OUTPUT_FILE"
        echo -e "Suspicious sections from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 10 -B 10 "temp\w*.*system|system.*temp" "$file" >> "$OUTPUT_FILE"
        found_malicious=true
        RISK_SCORE=$((RISK_SCORE + 90))
      fi
      
      # Check for writefile followed by source or execute
      if echo "$content" | grep -E -q "writefile.*source|writefile.*execute|source.*writefile|execute.*writefile"; then
        echo -e "${RED}CRITICAL: File appears to write to file and then execute it!${NC}" | tee -a "$OUTPUT_FILE"
        echo -e "Suspicious sections from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 10 -B 10 "writefile.*source|writefile.*execute|source.*writefile|execute.*writefile" "$file" >> "$OUTPUT_FILE"
        found_malicious=true
        RISK_SCORE=$((RISK_SCORE + 90))
      fi
      
      # Check for curl/wget followed by source/execute
      if echo "$content" | grep -E -q "(curl|wget).*source|(curl|wget).*execute|source.*(curl|wget)|execute.*(curl|wget)"; then
        echo -e "${RED}CRITICAL: File downloads and executes remote code!${NC}" | tee -a "$OUTPUT_FILE"
        echo -e "Suspicious sections from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 10 -B 10 "(curl|wget).*source|(curl|wget).*execute|source.*(curl|wget)|execute.*(curl|wget)" "$file" >> "$OUTPUT_FILE"
        found_malicious=true
        RISK_SCORE=$((RISK_SCORE + 100))
      fi
    done
  else
    echo "No files using tempname() or tempfile() found." >> "$OUTPUT_FILE"
  fi
  
  if [ "$found_malicious" = true ]; then
    echo -e "\n${RED}CRITICAL SECURITY ISSUE: Found code that creates and executes temporary files!${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This is a common technique for malicious plugins to download and execute arbitrary code." >> "$OUTPUT_FILE"
  fi
}

# Scan for auto-executing code on file operations
scan_auto_execution() {
  echo -e "\n${BLUE}Scanning for auto-executing code...${NC}"
  echo -e "\n## Auto-Executing Code" >> "$OUTPUT_FILE"
  
  # Look for autocmd with file operations
  autocmd_patterns=(
    "autocmd.*BufWritePost"
    "autocmd.*BufWrite"
    "autocmd.*FileChangedShell"
    "autocmd.*FileWritePost"
    "autocmd.*FileAppendPost"
  )
  
  found_malicious=false
  
  for pattern in "${autocmd_patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$OUTPUT_FILE"
    
    results=$(grep -r -l -E "$pattern" --include="*.vim" "$PLUGIN_DIR" 2>/dev/null || echo "")
    
    if [ -n "$results" ]; then
      echo "$results" >> "$OUTPUT_FILE"
      
      # For each matching file, extract the suspicious lines for context
      for file in $results; do
        echo -e "\nContext from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 3 -B 3 "$pattern" "$file" 2>/dev/null >> "$OUTPUT_FILE"
        
        # Extract the function that gets called in the autocmd
        autocmd_line=$(grep -E "$pattern" "$file" | head -1)
        function_call=$(echo "$autocmd_line" | grep -o -E "call\s+[a-zA-Z0-9_:]\+" | sed -E 's/call\s+//')
        
        if [ -n "$function_call" ]; then
          echo -e "\nFunction called by autocmd: $function_call" >> "$OUTPUT_FILE"
          
          # Find the function definition
          func_def=$(grep -n -A 15 "function.*$function_call" "$file" 2>/dev/null)
          if [ -n "$func_def" ]; then
            echo -e "Function definition:" >> "$OUTPUT_FILE"
            echo "$func_def" >> "$OUTPUT_FILE"
            
            # Check if the function contains suspicious code
            if echo "$func_def" | grep -q -E "(system|exec|curl|wget|tempname.*source|writefile.*source)"; then
              echo -e "${RED}CRITICAL: Auto-executing function contains suspicious code!${NC}" | tee -a "$OUTPUT_FILE"
              echo -e "Suspicious code in function:" >> "$OUTPUT_FILE"
              echo "$func_def" | grep -E "(system|exec|curl|wget|tempname.*source|writefile.*source)" >> "$OUTPUT_FILE"
              found_malicious=true
              RISK_SCORE=$((RISK_SCORE + 80))
            fi
          fi
        fi
      done
    else
      echo "No matches found for this pattern." >> "$OUTPUT_FILE"
    fi
  done
  
  if [ "$found_malicious" = true ]; then
    echo -e "\n${RED}CRITICAL SECURITY ISSUE: Found auto-executing code with suspicious behavior!${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This is a technique used to execute malicious code when users perform normal operations." >> "$OUTPUT_FILE"
  fi
}

# Scan for command injection through feedkeys and indirect execution
scan_indirect_command_execution() {
  echo -e "\n${BLUE}Scanning for indirect command execution...${NC}"
  echo -e "\n## Indirect Command Execution" >> "$OUTPUT_FILE"
  
  patterns=(
    "feedkeys.*:.*!"
    "feedkeys.*silent.*!"
    "feedkeys.*system"
    "feedkeys.*execute"
    "if.*=~#.*sync"
    "if.*=~#.*admin"
    "let.*help_cmd.*!.*>/tmp"
    "let.*cmd.*=.*\(['\"]h\s+.*\|\s*!.*['\"]"
  )
  
  found_malicious=false
  
  for pattern in "${patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$OUTPUT_FILE"
    
    results=$(grep -r -l -E "$pattern" --include="*.vim" "$PLUGIN_DIR" 2>/dev/null || echo "")
    
    if [ -n "$results" ]; then
      echo "$results" >> "$OUTPUT_FILE"
      echo -e "${RED}SUSPICIOUS: Found indirect command execution pattern${NC}"
      
      # Check each file for context
      for file in $results; do
        echo -e "\nContext from $file:" >> "$OUTPUT_FILE"
        grep -n -E -A 5 -B 5 "$pattern" "$file" 2>/dev/null >> "$OUTPUT_FILE"
        
        # Look for suspicious trigger patterns followed by calling suspicious functions
        if grep -q -E "if.*=~#.*'.*sync.*'|if.*==.*'trigger'" "$file" && grep -q -E "call\s+s:" "$file"; then
          echo -e "${RED}CRITICAL: Found potential backdoor with specific trigger word!${NC}" | tee -a "$OUTPUT_FILE"
          
          # Extract the trigger condition
          trigger=$(grep -E "if.*=~#.*'.*sync.*'|if.*==.*'trigger'" "$file" | head -1)
          echo -e "Trigger condition: $trigger" >> "$OUTPUT_FILE"
          
          # Extract the function that gets called after the trigger
          func_call=$(grep -A 3 -E "if.*=~#.*'.*sync.*'|if.*==.*'trigger'" "$file" | grep -o -E "call\s+s:[a-zA-Z0-9_]\+" | head -1 | sed -E 's/call\s+//')
          
          if [ -n "$func_call" ]; then
            # Find and extract the function definition
            func_def=$(grep -n -A 15 "function.*$func_call" "$file" 2>/dev/null)
            if [ -n "$func_def" ]; then
              echo -e "Function called by trigger:" >> "$OUTPUT_FILE"
              echo "$func_def" >> "$OUTPUT_FILE"
              
              # Check if this function contains command execution
              if echo "$func_def" | grep -q -E "(system|exec|curl|wget|!.*>/tmp|feedkeys.*!)"; then
                echo -e "${RED}CRITICAL SECURITY THREAT: Backdoor with trigger word and command execution!${NC}" | tee -a "$OUTPUT_FILE"
                found_malicious=true
                RISK_SCORE=$((RISK_SCORE + 100))
              fi
            fi
          fi
        fi
        
        if grep -q -E "h.*\|.*!.*>/tmp" "$file"; then
          echo -e "${RED}CRITICAL: Abuse of help system to execute commands!${NC}" | tee -a "$OUTPUT_FILE"
          grep -n -E "h.*\|.*!.*>/tmp" "$file" >> "$OUTPUT_FILE"
          found_malicious=true
          RISK_SCORE=$((RISK_SCORE + 90))
        fi
      done
    else
      echo "No matches found for this pattern." >> "$OUTPUT_FILE"
    fi
  done
  
  if [ "$found_malicious" = true ]; then
    echo -e "\n${RED}CRITICAL SECURITY ISSUE: Found indirect command execution techniques!${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This is a sophisticated technique used to hide malicious commands through Vim's feedkeys or help system." >> "$OUTPUT_FILE"
  fi
}

# Scan plugins with suspicious names
scan_suspicious_names() {
  echo -e "\n${BLUE}Scanning plugins with suspicious names...${NC}"
  echo -e "\n## Plugins with Suspicious Names" >> "$OUTPUT_FILE"
  
  # List of suspicious keywords in plugin names
  suspicious_names=(
    "system"
    "security"
    "performance"
    "util"
    "utils"
    "daemon"
    "manager"
    "helper"
  )
  
  found_suspicious=false
  
  for keyword in "${suspicious_names[@]}"; do
    # Find directories with suspicious names
    suspicious_dirs=$(find "$PLUGIN_DIR" -maxdepth 1 -type d -name "*$keyword*" 2>/dev/null)
    
    if [ -n "$suspicious_dirs" ]; then
      found_suspicious=true
      echo -e "\nPlugins containing '$keyword' in name:" >> "$OUTPUT_FILE"
      echo "$suspicious_dirs" | sed 's/^/- /' >> "$OUTPUT_FILE"
      
      echo -e "${YELLOW}Found plugins with '$keyword' in name. Performing deep scan...${NC}"
      
      # Perform deep scan on these plugins
      for dir in $suspicious_dirs; do
        plugin_name=$(basename "$dir")
        echo -e "\nDeep scan of plugin: $plugin_name" >> "$OUTPUT_FILE"
        
        # Search for suspicious patterns in this plugin
        suspicious_code=$(find "$dir" -type f -name "*.vim" -exec grep -l -E "(system|exec|call|curl|wget|timer_start|tempname.*execute)" {} \; 2>/dev/null)
        
        if [ -n "$suspicious_code" ]; then
          echo -e "${RED}CRITICAL: Suspicious plugin name '$plugin_name' contains potentially malicious code!${NC}" | tee -a "$OUTPUT_FILE"
          echo "Suspicious files:" >> "$OUTPUT_FILE"
          echo "$suspicious_code" | sed 's/^/- /' >> "$OUTPUT_FILE"
          
          # For each suspicious file, show context
          for file in $suspicious_code; do
            echo -e "\nSuspicious patterns in $file:" >> "$OUTPUT_FILE"
            grep -n -E "(system|exec|call|curl|wget|timer_start|tempname.*execute)" "$file" | head -10 >> "$OUTPUT_FILE"
          done
          
          RISK_SCORE=$((RISK_SCORE + 50))
        else
          echo "No suspicious code found in plugin." >> "$OUTPUT_FILE"
        fi
      done
    fi
  done
  
  if [ "$found_suspicious" = false ]; then
    echo "No plugins with suspicious names found." >> "$OUTPUT_FILE"
  fi
}

# Generate report summary
generate_summary() {
  echo -e "\n${BLUE}Generating summary...${NC}"
  echo -e "\n## Security Risk Assessment" >> "$OUTPUT_FILE"
  
  # Count critical findings
  critical_findings=$(grep -c "CRITICAL:" "$OUTPUT_FILE" || echo "0")
  security_threats=$(grep -c "CRITICAL SECURITY" "$OUTPUT_FILE" || echo "0")
  warnings=$(grep -c "WARNING:" "$OUTPUT_FILE" || echo "0")
  
  echo -e "- Critical Findings: $critical_findings" >> "$OUTPUT_FILE"
  echo -e "- Security Threats: $security_threats" >> "$OUTPUT_FILE"
  echo -e "- Warnings: $warnings" >> "$OUTPUT_FILE"
  echo -e "- Risk Score: $RISK_SCORE" >> "$OUTPUT_FILE"
  
  # Risk assessment based on findings
  if [ $RISK_SCORE -gt 90 ]; then
    echo -e "\n${RED}CRITICAL SECURITY RISK DETECTED!${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This plugin collection contains code that is HIGHLY likely to be malicious." >> "$OUTPUT_FILE"
    echo -e "Immediate action required - remove suspicious plugins identified in this report." >> "$OUTPUT_FILE"
    
    # List high-risk plugins
    echo -e "\n### High-Risk Plugins:" >> "$OUTPUT_FILE"
    grep -B 1 "CRITICAL SECURITY THREAT:" "$OUTPUT_FILE" | grep "Analyzing" | sed -E 's/Analyzing //' | sort | uniq >> "$OUTPUT_FILE"
  elif [ $RISK_SCORE -gt 50 ]; then
    echo -e "\n${RED}HIGH SECURITY RISK DETECTED!${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This plugin collection contains code that exhibits suspicious behavior." >> "$OUTPUT_FILE"
    echo -e "Review the findings carefully and consider removing suspicious plugins." >> "$OUTPUT_FILE"
  elif [ $RISK_SCORE -gt 20 ]; then
    echo -e "\n${YELLOW}MODERATE SECURITY RISK DETECTED.${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "This plugin collection contains some suspicious code patterns that warrant investigation." >> "$OUTPUT_FILE"
  else
    echo -e "\n${GREEN}LOW SECURITY RISK DETECTED.${NC}" | tee -a "$OUTPUT_FILE"
    echo -e "No significant obfuscation or malicious code patterns detected." >> "$OUTPUT_FILE"
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
  
  echo -e "${BLUE}Advanced Obfuscation Detection for Vim Plugins${NC}"
  echo -e "Target: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Output: ${YELLOW}$OUTPUT_FILE${NC}"
  echo -e "Deep Scan: ${YELLOW}$DEEP_SCAN${NC}"
  
  initialize_output
  
  # Run specialized scans
  scan_char_by_char
  scan_register_manipulation
  scan_delayed_execution
  scan_tempfile_execution
  scan_auto_execution
  scan_indirect_command_execution  # Add our new scan for feedkeys and help system backdoors
  scan_suspicious_names
  scan_recent_modifications
  
  generate_summary
  
  echo -e "\n${GREEN}Advanced scan completed!${NC}"
  echo -e "Report saved to: ${YELLOW}$OUTPUT_FILE${NC}"
  
  # Return different exit codes based on risk level
  if [ $RISK_SCORE -gt 90 ]; then
    echo -e "${RED}CRITICAL security issues detected!${NC}"
    exit 3
  elif [ $RISK_SCORE -gt 50 ]; then
    echo -e "${RED}HIGH security risk detected!${NC}"
    exit 2
  elif [ $RISK_SCORE -gt 20 ]; then
    echo -e "${YELLOW}MODERATE security risk detected.${NC}"
    exit 1
  else
    echo -e "${GREEN}No significant security issues detected.${NC}"
    exit 0
  fi
}

# Run the main function with all arguments
main "$@"
