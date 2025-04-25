#!/bin/bash
#
# Vim Plugin Security Scanner
# 
# This script performs comprehensive security scanning of Vim plugins
# to detect potential supply chain attacks and security vulnerabilities.
#
# Usage: ./scan-vim-plugins.sh [PLUGIN_DIR]
#   - If PLUGIN_DIR is not specified, defaults to ~/.vim/plugged

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHA_DATABASE="${SCRIPT_DIR}/vim-plugin-shas.json"
REPORT_FILE="${SCRIPT_DIR}/security-scan-report.txt"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Ensure required tools are installed
check_requirements() {
  local missing_tools=()
  
  for tool in git rg jq xxd strings base64; do
    if ! command -v "$tool" &> /dev/null; then
      missing_tools+=("$tool")
    fi
  done
  
  if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e "${RED}Missing required tools:${NC} ${missing_tools[*]}"
    echo "Please install these tools before running the scanner."
    if [[ "$OSTYPE" == "darwin"* ]]; then
      echo "On macOS, you can install them with: brew install ${missing_tools[*]}"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
      echo "On Ubuntu/Debian, you can install them with: sudo apt install ${missing_tools[*]}"
    fi
    exit 1
  fi
}

# Create or read the SHA database
initialize_sha_database() {
  if [ ! -f "$SHA_DATABASE" ]; then
    echo "{}" > "$SHA_DATABASE"
    echo -e "${YELLOW}Created new SHA database at:${NC} $SHA_DATABASE"
  else
    echo -e "${GREEN}Using existing SHA database:${NC} $SHA_DATABASE"
  fi
}

# Initialize scan report
initialize_report() {
  echo "# Vim Plugin Security Scan Report" > "$REPORT_FILE"
  echo "Date: $SCAN_DATE" >> "$REPORT_FILE"
  echo "Scanner Version: 1.0.0" >> "$REPORT_FILE"
  echo "Target Directory: $PLUGIN_DIR" >> "$REPORT_FILE"
  echo "----------------------------------------" >> "$REPORT_FILE"
}

# Scan git repositories for unexpected changes
scan_git_repositories() {
  echo -e "\n${BLUE}Scanning git repositories for unexpected changes...${NC}"
  echo -e "\n## Git Repository Analysis" >> "$REPORT_FILE"
  
  local high_risk_count=0
  local warning_count=0
  
  for plugin_dir in "$PLUGIN_DIR"/*; do
    if [ -d "$plugin_dir/.git" ]; then
      plugin_name=$(basename "$plugin_dir")
      echo -e "Checking ${YELLOW}$plugin_name${NC}..."
      
      # Get current commit hash
      cd "$plugin_dir"
      current_hash=$(git rev-parse HEAD)
      remote_url=$(git config --get remote.origin.url)
      
      # Get stored hash from database if it exists
      stored_hash=$(jq -r ".[\"$plugin_name\"].hash // \"none\"" "$SHA_DATABASE")
      stored_remote=$(jq -r ".[\"$plugin_name\"].remote // \"none\"" "$SHA_DATABASE")
      
      echo -e "### $plugin_name" >> "$REPORT_FILE"
      echo -e "- Current Hash: \`$current_hash\`" >> "$REPORT_FILE"
      echo -e "- Remote URL: $remote_url" >> "$REPORT_FILE"
      
      if [ "$stored_hash" == "none" ]; then
        echo -e "- Status: ${YELLOW}New plugin, not previously tracked${NC}" | tee -a "$REPORT_FILE"
        warning_count=$((warning_count + 1))
      elif [ "$stored_hash" != "$current_hash" ]; then
        echo -e "- Status: ${RED}Hash mismatch!${NC}" | tee -a "$REPORT_FILE"
        echo -e "  - Stored Hash: \`$stored_hash\`" >> "$REPORT_FILE"
        
        # Check if current hash exists in the remote repository
        if git merge-base --is-ancestor "$current_hash" "origin/HEAD" 2>/dev/null || \
           git merge-base --is-ancestor "$current_hash" "origin/master" 2>/dev/null || \
           git merge-base --is-ancestor "$current_hash" "origin/main" 2>/dev/null; then
          echo -e "  - Verification: Current hash exists in official repository history" >> "$REPORT_FILE"
          echo -e "  - Risk Level: ${YELLOW}MEDIUM${NC} - Hash differs but exists in official repo" | tee -a "$REPORT_FILE"
          warning_count=$((warning_count + 1))
        else
          echo -e "  - Verification: ${RED}Current hash NOT found in official repository history${NC}" | tee -a "$REPORT_FILE"
          echo -e "  - Risk Level: ${RED}HIGH${NC} - Hash differs and not found in official repo" | tee -a "$REPORT_FILE"
          high_risk_count=$((high_risk_count + 1))
        fi
      else
        echo -e "- Status: ${GREEN}Hash matches database${NC}" | tee -a "$REPORT_FILE"
      fi
      
      # Check if remote URL has changed
      if [ "$stored_remote" != "none" ] && [ "$stored_remote" != "$remote_url" ]; then
        echo -e "- Remote URL Change: ${RED}YES${NC} (was: $stored_remote)" | tee -a "$REPORT_FILE"
        echo -e "- Risk Level: ${RED}HIGH${NC} - Remote repository URL has changed" | tee -a "$REPORT_FILE"
        high_risk_count=$((high_risk_count + 1))
      fi
      
      echo "" >> "$REPORT_FILE"
    fi
  done
  
  echo -e "\n${BLUE}Git Repository Summary:${NC}" | tee -a "$REPORT_FILE"
  echo -e "- High Risk Issues: ${RED}$high_risk_count${NC}" | tee -a "$REPORT_FILE"
  echo -e "- Warnings: ${YELLOW}$warning_count${NC}" | tee -a "$REPORT_FILE"
  
  echo -e "----------------------------------------" >> "$REPORT_FILE"
}

# Scan for suspicious code patterns
scan_suspicious_patterns() {
  echo -e "\n${BLUE}Scanning for suspicious code patterns...${NC}"
  echo -e "\n## Suspicious Code Pattern Analysis" >> "$REPORT_FILE"
  
  local patterns=(
    # CRITICAL: Obfuscated code execution
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
    
    # CRITICAL: Remote code execution
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
    "system.*\$"
    "exec.*\$"
    "popen.*\$"
    "call.*\$"
    "execute.*\$"
    "eval.*\$"
    
    # Encoding/obfuscation techniques
    "[0-9a-fA-F]{24,}"
    "[A-Za-z0-9+/=]{30,}"
  )
  
  local suspicious_count=0
  
  for pattern in "${patterns[@]}"; do
    echo -e "Searching for pattern: ${YELLOW}$pattern${NC}"
    echo -e "\n### Pattern: \`$pattern\`" >> "$REPORT_FILE"
    
    results=$(rg --glob "!*.git/*" -n "$pattern" "$PLUGIN_DIR" 2>/dev/null || echo "")
    
    if [ -n "$results" ]; then
      echo "$results" | head -n 10 >> "$REPORT_FILE"
      lines_count=$(echo "$results" | wc -l)
      
      if [ $lines_count -gt 10 ]; then
        echo -e "... ($(($lines_count - 10)) more matches)" >> "$REPORT_FILE"
      fi
      
      echo -e "${YELLOW}Found suspicious pattern: $pattern${NC}"
      suspicious_count=$((suspicious_count + 1))
    else
      echo -e "No matches found for this pattern." >> "$REPORT_FILE"
    fi
  done
  
  echo -e "\n${BLUE}Suspicious Pattern Summary:${NC}" | tee -a "$REPORT_FILE"
  echo -e "- Suspicious Pattern Matches: ${YELLOW}$suspicious_count${NC}" | tee -a "$REPORT_FILE"
  
  echo -e "----------------------------------------" >> "$REPORT_FILE"
}

# Scan for binary files and analyze them
scan_binary_files() {
  echo -e "\n${BLUE}Scanning for binary files...${NC}"
  echo -e "\n## Binary File Analysis" >> "$REPORT_FILE"
  
  binary_files=$(find "$PLUGIN_DIR" -type f -not -path "*/\.git/*" -exec file {} \; | grep -E "ELF|PE32|Mach-O|compiled|binary" | cut -d: -f1)
  
  if [ -z "$binary_files" ]; then
    echo -e "No binary files found." | tee -a "$REPORT_FILE"
    return
  fi
  
  echo -e "Found $(echo "$binary_files" | wc -l | tr -d ' ') binary files." | tee -a "$REPORT_FILE"
  
  for file in $binary_files; do
    echo -e "\n### Binary: $(basename "$file")" >> "$REPORT_FILE"
    echo -e "- Path: $file" >> "$REPORT_FILE"
    
    # Check file type
    file_type=$(file "$file" | cut -d: -f2-)
    echo -e "- Type: $file_type" >> "$REPORT_FILE"
    
    # Check permissions
    permissions=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%p" "$file" | cut -c 3-5)
    echo -e "- Permissions: $permissions" >> "$REPORT_FILE"
    
    if [ "$permissions" = "755" ] || [ "$permissions" = "777" ]; then
      echo -e "- ${YELLOW}Warning: File has executable permissions${NC}" | tee -a "$REPORT_FILE"
    fi
    
    # Extract suspicious strings
    echo -e "- Suspicious Strings:" >> "$REPORT_FILE"
    suspicious_strings=$(strings "$file" | grep -E 'http|curl|wget|bash|exec|system|socket|connect|eval|base64' | head -n 10)
    
    if [ -n "$suspicious_strings" ]; then
      echo "$suspicious_strings" | sed 's/^/  - /' >> "$REPORT_FILE"
      echo -e "${YELLOW}Found suspicious strings in binary: $(basename "$file")${NC}"
    else
      echo -e "  None detected" >> "$REPORT_FILE"
    fi
  done
  
  echo -e "----------------------------------------" >> "$REPORT_FILE"
}

# Scan for unusual permissions
scan_permissions() {
  echo -e "\n${BLUE}Scanning for unusual file permissions...${NC}"
  echo -e "\n## Unusual Permission Analysis" >> "$REPORT_FILE"
  
  # Find executable files outside of expected locations
  # Use platform-appropriate permission test
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS permission check
    unusual_execs=$(find "$PLUGIN_DIR" -type f -perm +111 -not -path "*/\.git/*" -not -name "*.sh" -not -name "run-*" -not -name "test" -not -name "*.bash" -not -name "*.pl" -not -name "*.py" | sort)
  else
    # Linux permission check
    unusual_execs=$(find "$PLUGIN_DIR" -type f -perm /111 -not -path "*/\.git/*" -not -name "*.sh" -not -name "run-*" -not -name "test" -not -name "*.bash" -not -name "*.pl" -not -name "*.py" | sort)
  fi
  
  if [ -n "$unusual_execs" ]; then
    echo -e "${YELLOW}Found $(echo "$unusual_execs" | wc -l | tr -d ' ') files with unusual executable permissions:${NC}" | tee -a "$REPORT_FILE"
    echo "$unusual_execs" | sed 's/^/- /' >> "$REPORT_FILE"
  else
    echo -e "No files with unusual executable permissions found." | tee -a "$REPORT_FILE"
  fi
  
  # Find hidden files and directories (excluding .git)
  hidden_files=$(find "$PLUGIN_DIR" -name ".*" -not -name ".git" -not -name ".gitignore" -not -name ".github" -not -name ".gitattributes" -not -name ".editorconfig" | sort)
  
  if [ -n "$hidden_files" ]; then
    echo -e "\n### Hidden Files and Directories:" >> "$REPORT_FILE"
    echo "$hidden_files" | sed 's/^/- /' >> "$REPORT_FILE"
  else
    echo -e "\nNo suspicious hidden files found." >> "$REPORT_FILE"
  fi
  
  echo -e "----------------------------------------" >> "$REPORT_FILE"
}

# Update the SHA database with current values
update_sha_database() {
  echo -e "\n${BLUE}Updating SHA database...${NC}"
  
  temp_db=$(mktemp)
  cp "$SHA_DATABASE" "$temp_db"
  
  for plugin_dir in "$PLUGIN_DIR"/*; do
    if [ -d "$plugin_dir/.git" ]; then
      plugin_name=$(basename "$plugin_dir")
      cd "$plugin_dir"
      
      current_hash=$(git rev-parse HEAD)
      remote_url=$(git config --get remote.origin.url)
      last_commit_date=$(git log -1 --format=%cd --date=iso)
      
      # Update database with jq
      jq --arg name "$plugin_name" \
         --arg hash "$current_hash" \
         --arg remote "$remote_url" \
         --arg date "$last_commit_date" \
         --arg scan_date "$SCAN_DATE" \
         '.[$name] = {hash: $hash, remote: $remote, commit_date: $date, last_scan: $scan_date}' \
         "$temp_db" > "${temp_db}.new" && mv "${temp_db}.new" "$temp_db"
    fi
  done
  
  mv "$temp_db" "$SHA_DATABASE"
  echo -e "${GREEN}SHA database updated successfully.${NC}"
}

# Scan for suspicious plugin names that could be impersonating system utilities
scan_suspicious_plugin_names() {
  echo -e "\n${BLUE}Scanning for suspicious plugin names...${NC}"
  echo -e "\n## Suspicious Plugin Names" >> "$REPORT_FILE"
  
  # List of suspicious keywords in plugin names (commonly used for masquerading)
  local suspicious_names=(
    "system"
    "terminal"
    "profile"
    "util"
    "utils"
    "security"
    "access"
    "admin"
    "monitor"
    "network"
    "process"
    "kernel"
    "service"
    "helper"
    "daemon"
    "manager"
    "enhance"
    "performance"
    "update"
    "note"
    "sync"
    "clipboard"
    "help"
  )
  
  local suspicious_found=0
  
  for plugin_dir in "$PLUGIN_DIR"/*; do
    if [ -d "$plugin_dir" ]; then
      plugin_name=$(basename "$plugin_dir")
      
      for keyword in "${suspicious_names[@]}"; do
        if [[ "$plugin_name" == *"$keyword"* ]]; then
          echo -e "- Found suspicious plugin name: ${RED}$plugin_name${NC} (contains keyword '$keyword')" | tee -a "$REPORT_FILE"
          
          # Check if the plugin also has suspicious content
          suspicious_content=$(find "$plugin_dir" -type f -name "*.vim" -o -name "*.sh" -o -name "runme" | xargs grep -l -E "eval.*base64|curl.*\|.*bash|wget.*\|.*sh|execute.*decoded" 2>/dev/null)
          
          if [ -n "$suspicious_content" ]; then
            echo -e "  ${RED}CRITICAL: $plugin_name has both suspicious name AND suspicious content!${NC}" | tee -a "$REPORT_FILE"
            echo -e "  Suspicious files:" >> "$REPORT_FILE"
            echo "$suspicious_content" | sed 's/^/  - /' >> "$REPORT_FILE"
            suspicious_found=$((suspicious_found + 1))
          fi
          
          # Only match once per plugin
          break
        fi
      done
    fi
  done
  
  if [ $suspicious_found -eq 0 ]; then
    echo -e "No plugins with suspicious names and content found." >> "$REPORT_FILE"
  else
    echo -e "${RED}Found $suspicious_found plugins with suspicious names AND suspicious content!${NC}" | tee -a "$REPORT_FILE"
  fi
  
  echo -e "----------------------------------------" >> "$REPORT_FILE"
}

# Scan specifically for the most critical threats
scan_critical_threats() {
  echo -e "\n${BLUE}Scanning for CRITICAL security threats...${NC}"
  echo -e "\n## CRITICAL Security Threats" >> "$REPORT_FILE"
  
  # Check for decoded base64 execution (like in system-profiler)
  echo -e "\n### Obfuscated Code Execution" >> "$REPORT_FILE"
  
  # Find patterns like variable = base64 string followed by decode and exec
  critical_patterns=(
    # Base64 decode and execute - HIGHEST RISK
    "let.*=.*['\"][A-Za-z0-9+/=]\{20,\}['\"].*base64.*execute"
    "base64.*-d.*execute"
    "base64.*decode.*execute"
    "echo.*base64.*\|.*exec"
    
    # Direct download and execute - HIGHEST RISK
    "curl.*\|.*bash"
    "wget.*\|.*sh"
    "curl.*\|.*sh"
    "wget.*\|.*bash"
  )
  
  critical_found=0
  
  for pattern in "${critical_patterns[@]}"; do
    echo -e "Searching for critical pattern: ${RED}$pattern${NC}"
    echo -e "\n#### Critical Pattern: \`$pattern\`" >> "$REPORT_FILE"
    
    results=$(find "$PLUGIN_DIR" -type f -not -path "*/\.git/*" -exec grep -l -E "$pattern" {} \; 2>/dev/null || echo "")
    
    if [ -n "$results" ]; then
      echo "$results" | sed 's/^/- /' >> "$REPORT_FILE"
      critical_found=$((critical_found + 1))
      file_count=$(echo "$results" | wc -l)
      
      echo -e "${RED}CRITICAL: Found pattern '$pattern' in $file_count files!${NC}" | tee -a "$REPORT_FILE"
      
      # For each matching file, extract the matching line for context
      for file in $results; do
        echo -e "\nContext from $file:" >> "$REPORT_FILE"
        grep -n -E -A 2 -B 2 "$pattern" "$file" 2>/dev/null >> "$REPORT_FILE"
      done
    else
      echo -e "No matches found for this critical pattern." >> "$REPORT_FILE"
    fi
  done
  
  # Check for scripts that download and execute content
  echo -e "\n### Remote Code Execution Scripts" >> "$REPORT_FILE"
  
  download_exec_scripts=$(find "$PLUGIN_DIR" -type f -not -path "*/\.git/*" -perm +111 -exec grep -l -E "curl.*\|.*[bs]h|wget.*\|.*[bs]h" {} \; 2>/dev/null || echo "")
  
  # Check for character-by-character command construction
  echo -e "\n### Character-by-Character Command Construction" >> "$REPORT_FILE"
  char_construction=$(find "$PLUGIN_DIR" -name "*.vim" -exec grep -l -E "let.*pieces.*=.*\[.*'[a-z]'" {} \; 2>/dev/null || echo "")
  
  if [ -n "$char_construction" ]; then
    echo -e "${RED}CRITICAL: Found character-by-character command construction!${NC}" | tee -a "$REPORT_FILE"
    echo "$char_construction" | sed 's/^/- /' >> "$REPORT_FILE"
    
    # For each matching file, check if it also contains tempname/system/execution
    for file in $char_construction; do
      if grep -q -E "tempname|system|execute|timer_start" "$file"; then
        echo -e "${RED}HIGH RISK: File uses character-by-character construction with execution!${NC}" | tee -a "$REPORT_FILE"
        echo -e "\nContext from $file:" >> "$REPORT_FILE"
        grep -n -E -A 10 -B 10 "let.*pieces.*=.*\[.*'[a-z]'" "$file" >> "$REPORT_FILE"
        critical_found=$((critical_found + 1))
      fi
    done
  else
    echo "No character-by-character construction found." >> "$REPORT_FILE"
  fi
  
  # Check for tempfile execution chains
  echo -e "\n### Tempfile Execution Chains" >> "$REPORT_FILE"
  tempfile_execution=$(find "$PLUGIN_DIR" -name "*.vim" -exec grep -l -E "tempname.*\.vim|writefile.*source|writefile.*execute" {} \; 2>/dev/null || echo "")
  
  if [ -n "$tempfile_execution" ]; then
    echo -e "${RED}CRITICAL: Found tempfile execution chains!${NC}" | tee -a "$REPORT_FILE"
    echo "$tempfile_execution" | sed 's/^/- /' >> "$REPORT_FILE"
    critical_found=$((critical_found + 1))
  else
    echo "No tempfile execution chains found." >> "$REPORT_FILE"
  fi
  
  if [ -n "$download_exec_scripts" ]; then
    echo -e "${RED}CRITICAL: Found scripts that download and execute remote code!${NC}" | tee -a "$REPORT_FILE"
    echo "$download_exec_scripts" | sed 's/^/- /' >> "$REPORT_FILE"
    critical_found=$((critical_found + 1))
    
    # For each matching file, extract the matching line for context
    for file in $download_exec_scripts; do
      echo -e "\nContext from $file:" >> "$REPORT_FILE"
      grep -n -E -A 2 -B 2 "curl.*\|.*[bs]h|wget.*\|.*[bs]h" "$file" 2>/dev/null >> "$REPORT_FILE"
    done
  else
    echo -e "No scripts with download and execute patterns found." >> "$REPORT_FILE"
  fi
  
  # Search for multi-stage code execution (encoded content in variable being executed)
  echo -e "\n### Multi-Stage Code Execution" >> "$REPORT_FILE"
  
  for plugin_dir in "$PLUGIN_DIR"/*; do
    if [ -d "$plugin_dir" ]; then
      plugin_name=$(basename "$plugin_dir")
      
      # Find all .vim files with encoded strings
      encoded_files=$(find "$plugin_dir" -name "*.vim" -exec grep -l -E "let.*=.*['\"][A-Za-z0-9+/=]{20,}['\"]" {} \; 2>/dev/null)
      
      for file in $encoded_files; do
        # Check if the same file has execute
        if grep -q -E "execute.*s:.*|execute.*decoded|eval.*decoded" "$file"; then
          echo -e "${RED}CRITICAL: Multi-stage code execution detected in $plugin_name!${NC}" | tee -a "$REPORT_FILE"
          echo -e "- File: $file" >> "$REPORT_FILE"
          
          # Extract the encoded variable and any execute statements
          echo -e "- Encoded variable:" >> "$REPORT_FILE"
          grep -n -E "let.*=.*['\"][A-Za-z0-9+/=]{20,}['\"]" "$file" | head -n 3 >> "$REPORT_FILE"
          
          echo -e "- Execution:" >> "$REPORT_FILE"
          grep -n -E "execute.*s:.*|execute.*decoded|eval.*decoded" "$file" | head -n 3 >> "$REPORT_FILE"
          
          critical_found=$((critical_found + 1))
        fi
      done
    fi
  done
  
  # Summary of critical findings
  if [ $critical_found -eq 0 ]; then
    echo -e "\n${GREEN}No critical security threats detected.${NC}" | tee -a "$REPORT_FILE"
  else
    echo -e "\n${RED}CRITICAL: Found $critical_found patterns indicating serious security threats!${NC}" | tee -a "$REPORT_FILE"
    echo -e "These findings indicate likely malicious code that requires immediate investigation." | tee -a "$REPORT_FILE"
  fi
  
  echo -e "----------------------------------------" >> "$REPORT_FILE"
}

# Generate report summary
generate_summary() {
  echo -e "\n${BLUE}Generating report summary...${NC}"
  echo -e "\n## Scan Summary" >> "$REPORT_FILE"
  
  # Count high risk issues
  critical_threats=$(grep -c "CRITICAL:" "$REPORT_FILE" || echo "0")
  high_risk=$(grep -c "Risk Level: HIGH" "$REPORT_FILE" || echo "0")
  warnings=$(grep -c "Risk Level: MEDIUM\|Warning:" "$REPORT_FILE" || echo "0")
  suspicious_patterns=$(grep -A1 "Suspicious Pattern Summary" "$REPORT_FILE" | grep -o "[0-9]\+" || echo "0")
  
  echo -e "- Critical Security Threats: ${critical_threats}" >> "$REPORT_FILE"
  echo -e "- High Risk Issues: ${high_risk}" >> "$REPORT_FILE"
  echo -e "- Warnings: ${warnings}" >> "$REPORT_FILE"
  echo -e "- Suspicious Pattern Matches: ${suspicious_patterns}" >> "$REPORT_FILE"
  
  echo -e "\n### Conclusion" >> "$REPORT_FILE"
  
  if [ "$critical_threats" -gt 0 ]; then
    echo -e "${RED}CRITICAL SECURITY THREATS DETECTED!${NC} Immediate action required!" | tee -a "$REPORT_FILE"
    echo -e "The scan detected patterns that strongly indicate malicious code. Remove or isolate these plugins immediately." >> "$REPORT_FILE"
  elif [ "$high_risk" -gt 0 ]; then
    echo -e "${RED}HIGH RISK ISSUES DETECTED!${NC} Please review the full report for details." | tee -a "$REPORT_FILE"
    echo -e "Immediate investigation recommended for potential supply chain attack indicators." >> "$REPORT_FILE"
  elif [ "$warnings" -gt 0 ] || [ "$suspicious_patterns" -gt 0 ]; then
    echo -e "${YELLOW}POTENTIAL ISSUES DETECTED.${NC} Review the full report for details." | tee -a "$REPORT_FILE"
    echo -e "Some items may require further investigation, but could be normal plugin behavior." >> "$REPORT_FILE"
  else
    echo -e "${GREEN}NO SIGNIFICANT ISSUES DETECTED.${NC}" | tee -a "$REPORT_FILE"
    echo -e "Scan completed successfully with no high-risk findings." >> "$REPORT_FILE"
  fi
  
  echo -e "\nFull report available at: ${REPORT_FILE}" | tee -a "$REPORT_FILE"
}

# Main function
main() {
  # Set plugin directory (default to ~/.vim/plugged if not specified)
  PLUGIN_DIR="${1:-$HOME/.vim/plugged}"
  
  if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${RED}Error: Plugin directory does not exist:${NC} $PLUGIN_DIR"
    exit 1
  fi
  
  echo -e "${BLUE}Vim Plugin Security Scanner${NC}"
  echo -e "Target: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Date: ${SCAN_DATE}"
  
  check_requirements
  initialize_sha_database
  initialize_report
  
  # New function to check for suspicious plugin names
  scan_suspicious_plugin_names
  scan_git_repositories
  scan_suspicious_patterns
  scan_binary_files
  scan_permissions
  
  # Perform specific checks for critical threats
  scan_critical_threats
  
  # Run specialized detection scripts for advanced obfuscation techniques
  echo -e "\n${BLUE}Running specialized detection for advanced obfuscation techniques...${NC}"
  echo -e "\n## Advanced Obfuscation Detection Results" >> "$REPORT_FILE"
  
  # Make scripts executable
  chmod +x "$SCRIPT_DIR/detect-register-manipulation.sh" 2>/dev/null || true
  chmod +x "$SCRIPT_DIR/detect-feedkeys-backdoors.sh" 2>/dev/null || true
  chmod +x "$SCRIPT_DIR/detect-char-construction.sh" 2>/dev/null || true
  chmod +x "$SCRIPT_DIR/detect-advanced-obfuscation.sh" 2>/dev/null || true
  
  # Run specialized detection scripts
  echo -e "Running register manipulation detector..." | tee -a "$REPORT_FILE"
  "$SCRIPT_DIR/detect-register-manipulation.sh" "$PLUGIN_DIR" || echo -e "${RED}Detected register manipulation techniques!${NC}" | tee -a "$REPORT_FILE"
  
  echo -e "Running feedkeys backdoor detector..." | tee -a "$REPORT_FILE"
  "$SCRIPT_DIR/detect-feedkeys-backdoors.sh" "$PLUGIN_DIR" || echo -e "${RED}Detected feedkeys-based backdoors!${NC}" | tee -a "$REPORT_FILE"
  
  echo -e "Running character construction detector..." | tee -a "$REPORT_FILE"
  "$SCRIPT_DIR/detect-char-construction.sh" "$PLUGIN_DIR" || echo -e "${RED}Detected character-by-character construction of malicious commands!${NC}" | tee -a "$REPORT_FILE"
  
  echo -e "Running advanced obfuscation detector..." | tee -a "$REPORT_FILE"
  "$SCRIPT_DIR/detect-advanced-obfuscation.sh" "$PLUGIN_DIR" || echo -e "${RED}Detected advanced obfuscation techniques!${NC}" | tee -a "$REPORT_FILE"
  
  # Insert links to detailed reports
  echo -e "\nDetailed reports available at:" >> "$REPORT_FILE"
  echo -e "- Register Manipulation: $SCRIPT_DIR/register-manipulation-report.txt" >> "$REPORT_FILE"
  echo -e "- Feedkeys Backdoors: $SCRIPT_DIR/feedkeys-backdoor-report.txt" >> "$REPORT_FILE"
  echo -e "- Character Construction: $SCRIPT_DIR/char-construction-report.txt" >> "$REPORT_FILE"
  echo -e "- Advanced Obfuscation: $SCRIPT_DIR/advanced-obfuscation-report.txt" >> "$REPORT_FILE"
  
  generate_summary
  update_sha_database
  
  echo -e "\n${GREEN}Scan completed!${NC}"
  echo -e "Report saved to: ${YELLOW}$REPORT_FILE${NC}"
}

# Run the main function with all arguments
main "$@"