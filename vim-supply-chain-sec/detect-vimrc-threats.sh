#!/bin/bash
#
# Vim Plugin VimRC Threats Detector
#
# This script specializes in detecting advanced threats that exploit
# .vimrc configuration and Vim's runtime environment
#
# Usage: ./detect-vimrc-threats.sh [VIMRC_FILE] [PLUGIN_DIR]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/vimrc-threats-report.txt"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Initialize report
initialize_report() {
  echo "# Vim RC Configuration Threats Detector" > "$REPORT_FILE"
  echo "Date: $SCAN_DATE" >> "$REPORT_FILE"
  echo "Target VimRC: $VIMRC_FILE" >> "$REPORT_FILE"
  echo "Target Plugin Directory: $PLUGIN_DIR" >> "$REPORT_FILE"
  echo "----------------------------------------" >> "$REPORT_FILE"
}

# Scan for bootstrap vulnerabilities
scan_bootstrap_exploits() {
  echo -e "\n${BLUE}Scanning for bootstrap vulnerabilities...${NC}"
  echo -e "\n## Bootstrap Vulnerabilities" >> "$REPORT_FILE"
  
  # Check for curl/wget in vimrc
  echo -e "\n### Bootstrap Download Commands" >> "$REPORT_FILE"
  if grep -q "curl\|wget" "$VIMRC_FILE"; then
    echo -e "${YELLOW}Found bootstrap download mechanisms!${NC}" | tee -a "$REPORT_FILE"
    grep -n "curl\|wget" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Look for plugins that might tamper with network settings
    echo -e "\n### Plugins that may tamper with bootstrap" >> "$REPORT_FILE"
    find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "proxy\|curl\|wget\|http\|url" {} \; | while read -r file; do
      echo -e "${YELLOW}Suspicious plugin may interfere with bootstrap:${NC} $file" | tee -a "$REPORT_FILE"
      grep -n "proxy\|curl\|wget\|http\|url" "$file" | head -5 >> "$REPORT_FILE"
    done
  else
    echo "No bootstrap download mechanisms found." >> "$REPORT_FILE"
  fi
}

# Scan for autocommand cascade vulnerabilities
scan_autocommand_cascades() {
  echo -e "\n${BLUE}Scanning for autocommand cascade vulnerabilities...${NC}"
  echo -e "\n## Autocommand Cascade Vulnerabilities" >> "$REPORT_FILE"
  
  # Extract autocommands from vimrc
  echo -e "\n### Autocommands in VimRC" >> "$REPORT_FILE"
  if grep -q "autocmd\|au\s\+\w\+" "$VIMRC_FILE"; then
    echo -e "${YELLOW}Found autocommands in vimrc!${NC}" | tee -a "$REPORT_FILE"
    grep -n "autocmd\|au\s\+\w\+" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Look for plugins that might chain onto these autocommands
    echo -e "\n### Plugins that may exploit autocommands" >> "$REPORT_FILE"
    vimrc_events=$(grep -o "autocmd\s\+\w\+\|au\s\+\w\+" "$VIMRC_FILE" | awk '{print $2}' | sort | uniq)
    
    for event in $vimrc_events; do
      find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "autocmd\s\+$event\|au\s\+$event" {} \; | while read -r file; do
        echo -e "${YELLOW}Plugin hooks into $event event from vimrc:${NC} $file" | tee -a "$REPORT_FILE"
        grep -n "autocmd\s\+$event\|au\s\+$event" "$file" | head -5 >> "$REPORT_FILE"
        
        # Check for suspicious system calls within the same file
        if grep -q "system\|exec\|call" "$file"; then
          echo -e "${RED}CRITICAL: Plugin with autocommand also contains system execution!${NC}" | tee -a "$REPORT_FILE"
          grep -n "system\|exec\|call" "$file" | head -5 >> "$REPORT_FILE"
        fi
      done
    done
  else
    echo "No autocommands found in vimrc." >> "$REPORT_FILE"
  fi
  
  # Look for counter-based triggers in plugins
  echo -e "\n### Counter-based autocommand triggers" >> "$REPORT_FILE"
  find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "let.*g:.*=.*g:.*+\|let.*s:.*=.*s:.*+" {} \; | while read -r file; do
    if grep -q "autocmd\|au\s\+\w\+" "$file"; then
      echo -e "${RED}CRITICAL: Plugin uses counter variables with autocommands:${NC} $file" | tee -a "$REPORT_FILE"
      grep -n "let.*g:.*=.*g:.*+\|let.*s:.*=.*s:.*+" "$file" | head -5 >> "$REPORT_FILE"
      grep -n "autocmd\|au\s\+\w\+" "$file" | head -5 >> "$REPORT_FILE"
    fi
  done
}

# Scan for exrc and modeline exploits
scan_exrc_modeline_exploits() {
  echo -e "\n${BLUE}Scanning for exrc and modeline vulnerabilities...${NC}"
  echo -e "\n## Exrc and Modeline Vulnerabilities" >> "$REPORT_FILE"
  
  # Check if exrc is enabled in vimrc
  if grep -q "set\s\+exrc" "$VIMRC_FILE"; then
    echo -e "${YELLOW}SECURITY RISK: 'exrc' is enabled, allowing execution of local .vimrc files!${NC}" | tee -a "$REPORT_FILE"
    grep -n "set\s\+exrc" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Check if secure is also set
    if ! grep -q "set\s\+secure" "$VIMRC_FILE"; then
      echo -e "${RED}CRITICAL: 'exrc' is enabled without 'secure' option!${NC}" | tee -a "$REPORT_FILE"
      echo "This allows arbitrary command execution from local .vimrc files" >> "$REPORT_FILE"
    fi
  fi
  
  # Check if modeline is enabled
  if grep -q "set\s\+modeline" "$VIMRC_FILE" || ! grep -q "set\s\+nomodeline" "$VIMRC_FILE"; then
    echo -e "${YELLOW}SECURITY RISK: 'modeline' is enabled, allowing execution from file comments!${NC}" | tee -a "$REPORT_FILE"
    if grep -q "set\s\+modeline" "$VIMRC_FILE"; then
      grep -n "set\s\+modeline" "$VIMRC_FILE" >> "$REPORT_FILE"
    else
      echo "Modeline is enabled by default (no 'nomodeline' found)" >> "$REPORT_FILE"
    fi
  fi
  
  # Look for plugins that might generate files with modelines or local vimrc
  echo -e "\n### Plugins that may exploit exrc/modeline" >> "$REPORT_FILE"
  find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "writefile\|new\s\+file\|system.*>\|call.*>\|create.*file" {} \; | while read -r file; do
    echo -e "${YELLOW}Plugin may generate files (potential exrc/modeline risk):${NC} $file" | tee -a "$REPORT_FILE"
    grep -n "writefile\|new\s\+file\|system.*>\|call.*>\|create.*file" "$file" | head -5 >> "$REPORT_FILE"
  done
}

# Scan for plugin fetch redirectors
scan_plugin_fetch_redirectors() {
  echo -e "\n${BLUE}Scanning for plugin fetch redirector vulnerabilities...${NC}"
  echo -e "\n## Plugin Fetch Redirector Vulnerabilities" >> "$REPORT_FILE"
  
  # Check for plugin commands that fetch external content
  echo -e "\n### External fetching commands in vimrc" >> "$REPORT_FILE"
  if grep -q "UpdateRemotePlugins\|PlugUpdate\|PlugUpgrade\|GoUpdateBinaries\|CocUpdate\|install" "$VIMRC_FILE"; then
    echo -e "${YELLOW}Found commands that fetch external content!${NC}" | tee -a "$REPORT_FILE"
    grep -n "UpdateRemotePlugins\|PlugUpdate\|PlugUpgrade\|GoUpdateBinaries\|CocUpdate\|install" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Look for plugins that might tamper with these processes
    echo -e "\n### Plugins that may redirect fetches" >> "$REPORT_FILE"
    find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "PlugUpdate\|UpdateRemotePlugins\|PlugUpgrade\|GoUpdateBinaries\|CocUpdate\|install\|UpdateRemotePlugins" {} \; | while read -r file; do
      echo -e "${YELLOW}Plugin may interfere with update process:${NC} $file" | tee -a "$REPORT_FILE"
      grep -n "PlugUpdate\|UpdateRemotePlugins\|PlugUpgrade\|GoUpdateBinaries\|CocUpdate\|install\|UpdateRemotePlugins" "$file" | head -5 >> "$REPORT_FILE"
    done
  else
    echo "No external fetching commands found in vimrc." >> "$REPORT_FILE"
  fi
  
  # Look for plugins that override environment variables
  echo -e "\n### Environment variable tampering" >> "$REPORT_FILE"
  find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "let\s\+\$\w\+\|system.*PROXY\|let.*proxy\|system.*proxy" {} \; | while read -r file; do
    echo -e "${RED}CRITICAL: Plugin manipulates environment variables:${NC} $file" | tee -a "$REPORT_FILE"
    grep -n "let\s\+\$\w\+\|system.*PROXY\|let.*proxy\|system.*proxy" "$file" | head -5 >> "$REPORT_FILE"
  done
}

# Scan for mapping shadow exploits
scan_mapping_shadow_exploits() {
  echo -e "\n${BLUE}Scanning for mapping shadow vulnerabilities...${NC}"
  echo -e "\n## Mapping Shadow Vulnerabilities" >> "$REPORT_FILE"
  
  # Extract mappings from vimrc
  echo -e "\n### Mappings in VimRC" >> "$REPORT_FILE"
  if grep -q "map\|noremap\|nmap\|vmap\|imap" "$VIMRC_FILE"; then
    echo -e "${YELLOW}Found key mappings in vimrc!${NC}" | tee -a "$REPORT_FILE"
    grep -n "map\|noremap\|nmap\|vmap\|imap" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Extract leader key if defined
    leader_key="'\\\'"  # Default leader
    if grep -q "let\s\+mapleader" "$VIMRC_FILE"; then
      leader_key=$(grep "let\s\+mapleader" "$VIMRC_FILE" | sed -E 's/.*let\s+mapleader\s*=\s*["'"'"'](.)["'"'"'].*/\1/')
      echo -e "Leader key defined as: $leader_key" >> "$REPORT_FILE"
    fi
    
    # Look for plugins that override these mappings
    echo -e "\n### Plugins that may shadow mappings" >> "$REPORT_FILE"
    # Extract mapped keys
    mapped_keys=$(grep -o "map\s\+<\?\w*-\?\w*>\?\s\+\w\+" "$VIMRC_FILE" | awk '{print $2}')
    
    for key in $mapped_keys; do
      find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "map\s\+$key\|noremap\s\+$key\|nmap\s\+$key\|vmap\s\+$key\|imap\s\+$key" {} \; | while read -r file; do
        echo -e "${YELLOW}Plugin overrides mapping for $key:${NC} $file" | tee -a "$REPORT_FILE"
        grep -n "map\s\+$key\|noremap\s\+$key\|nmap\s\+$key\|vmap\s\+$key\|imap\s\+$key" "$file" | head -5 >> "$REPORT_FILE"
        
        # Check for suspicious system calls within the same file
        if grep -q "system\|exec\|call" "$file"; then
          echo -e "${RED}CRITICAL: Plugin with mapping override also contains system execution!${NC}" | tee -a "$REPORT_FILE"
          grep -n "system\|exec\|call" "$file" | head -5 >> "$REPORT_FILE"
        fi
      done
    done
    
    # Look for leader-based mappings in plugins
    echo -e "\n### Leader-based mapping shadowing" >> "$REPORT_FILE"
    find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "map\s\+<Leader>\|noremap\s\+<Leader>\|nmap\s\+<Leader>\|vmap\s\+<Leader>\|imap\s\+<Leader>" {} \; | while read -r file; do
      echo -e "${YELLOW}Plugin uses leader-based mappings:${NC} $file" | tee -a "$REPORT_FILE"
      grep -n "map\s\+<Leader>\|noremap\s\+<Leader>\|nmap\s\+<Leader>\|vmap\s\+<Leader>\|imap\s\+<Leader>" "$file" | head -5 >> "$REPORT_FILE"
      
      # Check for suspicious system calls within the same file
      if grep -q "system\|exec\|call\s\+system" "$file"; then
        echo -e "${RED}CRITICAL: Plugin with leader mappings also contains system execution!${NC}" | tee -a "$REPORT_FILE"
        grep -n "system\|exec\|call\s\+system" "$file" | head -5 >> "$REPORT_FILE"
      fi
    done
  else
    echo "No key mappings found in vimrc." >> "$REPORT_FILE"
  fi
}

# Scan for wildmenu and path expansion exploits
scan_wildmenu_path_exploits() {
  echo -e "\n${BLUE}Scanning for wildmenu and path expansion vulnerabilities...${NC}"
  echo -e "\n## Wildmenu and Path Expansion Vulnerabilities" >> "$REPORT_FILE"
  
  # Check if path expansion is enabled
  if grep -q "set\s\+path+" "$VIMRC_FILE"; then
    echo -e "${YELLOW}CAUTION: Path expansion is enabled!${NC}" | tee -a "$REPORT_FILE"
    grep -n "set\s\+path+" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Check if wildmenu is also enabled
    if grep -q "set\s\+wildmenu" "$VIMRC_FILE"; then
      echo -e "${YELLOW}CAUTION: Wildmenu is also enabled!${NC}" | tee -a "$REPORT_FILE"
      grep -n "set\s\+wildmenu" "$VIMRC_FILE" >> "$REPORT_FILE"
    fi
    
    # Look for deeply nested plugin files that might be triggered via path completion
    echo -e "\n### Deeply nested files in plugins" >> "$REPORT_FILE"
    find "$PLUGIN_DIR" -mindepth 5 -type f -name "*.vim" | while read -r file; do
      echo -e "${YELLOW}Suspicious deeply nested vim file:${NC} $file" | tee -a "$REPORT_FILE"
      
      # Check content for suspicious code
      if grep -q "system\|exec\|call\s\+system" "$file"; then
        echo -e "${RED}CRITICAL: Deeply nested file contains system execution!${NC}" | tee -a "$REPORT_FILE"
        grep -n "system\|exec\|call\s\+system" "$file" | head -5 >> "$REPORT_FILE"
      fi
    done
  else
    echo "Path expansion not explicitly enabled in vimrc." >> "$REPORT_FILE"
  fi
  
  # Look for plugins that might create deep directory structures
  echo -e "\n### Plugins that may create deep directory structures" >> "$REPORT_FILE"
  find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "mkdir\|system.*mkdir\|call.*mkdir" {} \; | while read -r file; do
    echo -e "${YELLOW}Plugin may create directories:${NC} $file" | tee -a "$REPORT_FILE"
    grep -n "mkdir\|system.*mkdir\|call.*mkdir" "$file" | head -5 >> "$REPORT_FILE"
  done
}

# Scan for undo directory exploits
scan_undo_directory_exploits() {
  echo -e "\n${BLUE}Scanning for undo directory vulnerabilities...${NC}"
  echo -e "\n## Undo Directory Vulnerabilities" >> "$REPORT_FILE"
  
  # Check if undofile is enabled
  if grep -q "set\s\+undofile" "$VIMRC_FILE"; then
    echo -e "${YELLOW}CAUTION: Persistent undo is enabled!${NC}" | tee -a "$REPORT_FILE"
    grep -n "set\s\+undofile" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Check if undodir is set
    if grep -q "set\s\+undodir" "$VIMRC_FILE"; then
      undodir=$(grep "set\s\+undodir" "$VIMRC_FILE" | sed -E 's/.*set\s+undodir=([^ ]*).*/\1/')
      echo -e "Undo directory set to: $undodir" >> "$REPORT_FILE"
      
      # Check if undo directory exists and has unusual files
      if [[ -d "$undodir" ]]; then
        echo -e "\n### Suspicious files in undo directory" >> "$REPORT_FILE"
        find "$undodir" -type f -not -name "*.un~" -not -name "*.swp" | while read -r file; do
          echo -e "${RED}SUSPICIOUS: Non-undo file in undo directory:${NC} $file" | tee -a "$REPORT_FILE"
          head -n 10 "$file" >> "$REPORT_FILE"
        done
      fi
    fi
  else
    echo "Persistent undo not explicitly enabled in vimrc." >> "$REPORT_FILE"
  fi
  
  # Look for plugins that might interact with undo files
  echo -e "\n### Plugins that may interact with undo files" >> "$REPORT_FILE"
  find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "undo\|undofile\|undodir\|readfile" {} \; | while read -r file; do
    echo -e "${YELLOW}Plugin interacts with undo functionality:${NC} $file" | tee -a "$REPORT_FILE"
    grep -n "undo\|undofile\|undodir\|readfile" "$file" | head -5 >> "$REPORT_FILE"
    
    # Check for suspicious system calls within the same file
    if grep -q "system\|exec\|call\s\+system" "$file"; then
      echo -e "${RED}CRITICAL: Plugin with undo interaction also contains system execution!${NC}" | tee -a "$REPORT_FILE"
      grep -n "system\|exec\|call\s\+system" "$file" | head -5 >> "$REPORT_FILE"
    fi
  done
}

# Scan for external command chaining
scan_external_command_chaining() {
  echo -e "\n${BLUE}Scanning for external command chaining vulnerabilities...${NC}"
  echo -e "\n## External Command Chaining Vulnerabilities" >> "$REPORT_FILE"
  
  # Check for external commands in vimrc
  echo -e "\n### External commands in VimRC" >> "$REPORT_FILE"
  if grep -q "!\|system\|:r!" "$VIMRC_FILE"; then
    echo -e "${YELLOW}Found external command execution in vimrc!${NC}" | tee -a "$REPORT_FILE"
    grep -n "!\|system\|:r!" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Extract command patterns
    command_patterns=$(grep -o "!\s*\w\+" "$VIMRC_FILE" | sed 's/!\s*//' | sort | uniq)
    
    # Look for plugins that might chain onto these commands
    echo -e "\n### Plugins that may chain onto external commands" >> "$REPORT_FILE"
    for cmd in $command_patterns; do
      find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "system.*$cmd\|!.*$cmd\|call.*$cmd" {} \; | while read -r file; do
        echo -e "${YELLOW}Plugin references command '$cmd' from vimrc:${NC} $file" | tee -a "$REPORT_FILE"
        grep -n "system.*$cmd\|!.*$cmd\|call.*$cmd" "$file" | head -5 >> "$REPORT_FILE"
        
        # Check for command chaining or shell metacharacters
        if grep -q "system.*$cmd.*[&|;]\|!.*$cmd.*[&|;]" "$file"; then
          echo -e "${RED}CRITICAL: Plugin chains commands with '$cmd':${NC}" | tee -a "$REPORT_FILE"
          grep -n "system.*$cmd.*[&|;]\|!.*$cmd.*[&|;]" "$file" | head -5 >> "$REPORT_FILE"
        fi
      done
    done
  else
    echo "No external commands found in vimrc." >> "$REPORT_FILE"
  fi
  
  # Look for plugins that modify shell options
  echo -e "\n### Shell option manipulation" >> "$REPORT_FILE"
  find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "set\s\+shell\|&shell\|let\s\+&shell\|set\s\+shellcmdflag\|&shellcmdflag" {} \; | while read -r file; do
    echo -e "${RED}CRITICAL: Plugin modifies shell options:${NC} $file" | tee -a "$REPORT_FILE"
    grep -n "set\s\+shell\|&shell\|let\s\+&shell\|set\s\+shellcmdflag\|&shellcmdflag" "$file" | head -5 >> "$REPORT_FILE"
  done
}

# Scan for linter payload exploits
scan_linter_payload_exploits() {
  echo -e "\n${BLUE}Scanning for linter payload vulnerabilities...${NC}"
  echo -e "\n## Linter Payload Vulnerabilities" >> "$REPORT_FILE"
  
  # Check for linters in vimrc
  echo -e "\n### Linter configurations in VimRC" >> "$REPORT_FILE"
  if grep -q "ale_\|syntastic_\|neomake_\|linter\|fixer" "$VIMRC_FILE"; then
    echo -e "${YELLOW}Found linter configurations in vimrc!${NC}" | tee -a "$REPORT_FILE"
    grep -n "ale_\|syntastic_\|neomake_\|linter\|fixer" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Look for plugins that might tamper with linter configurations
    echo -e "\n### Plugins that may tamper with linters" >> "$REPORT_FILE"
    find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "ale_\|syntastic_\|neomake_\|linter\|fixer" {} \; | while read -r file; do
      echo -e "${YELLOW}Plugin interacts with linter configuration:${NC} $file" | tee -a "$REPORT_FILE"
      grep -n "ale_\|syntastic_\|neomake_\|linter\|fixer" "$file" | head -5 >> "$REPORT_FILE"
      
      # Check for suspicious system calls within the same file
      if grep -q "system\|exec\|call\s\+system" "$file"; then
        echo -e "${RED}CRITICAL: Plugin with linter interaction also contains system execution!${NC}" | tee -a "$REPORT_FILE"
        grep -n "system\|exec\|call\s\+system" "$file" | head -5 >> "$REPORT_FILE"
      fi
    done
  else
    echo "No linter configurations found in vimrc." >> "$REPORT_FILE"
  fi
  
  # Look for plugins that might modify PATH or environment
  echo -e "\n### PATH or environment manipulation" >> "$REPORT_FILE"
  find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "let\s\+\$PATH\|system.*PATH\|let.*plugin_path\|LINTER_\|set\s\+makeprg" {} \; | while read -r file; do
    echo -e "${RED}CRITICAL: Plugin manipulates PATH or environment:${NC} $file" | tee -a "$REPORT_FILE"
    grep -n "let\s\+\$PATH\|system.*PATH\|let.*plugin_path\|LINTER_\|set\s\+makeprg" "$file" | head -5 >> "$REPORT_FILE"
  done
}

# Scan for VCS hook injection
scan_vcs_hook_injection() {
  echo -e "\n${BLUE}Scanning for VCS hook injection vulnerabilities...${NC}"
  echo -e "\n## VCS Hook Injection Vulnerabilities" >> "$REPORT_FILE"
  
  # Check for VCS plugins in vimrc
  echo -e "\n### VCS plugins in VimRC" >> "$REPORT_FILE"
  if grep -q "fugitive\|gina\|git\|vcscommand\|svn\|gitgutter" "$VIMRC_FILE"; then
    echo -e "${YELLOW}Found VCS plugins in vimrc!${NC}" | tee -a "$REPORT_FILE"
    grep -n "fugitive\|gina\|git\|vcscommand\|svn\|gitgutter" "$VIMRC_FILE" >> "$REPORT_FILE"
    
    # Look for plugins that might inject into VCS hooks
    echo -e "\n### Plugins that may inject VCS hooks" >> "$REPORT_FILE"
    find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "\.git/hooks\|fugitive\|gina\|git\.\|hook\|system.*git\|call.*git\|Git\s\+commit" {} \; | while read -r file; do
      echo -e "${YELLOW}Plugin interacts with Git functionality:${NC} $file" | tee -a "$REPORT_FILE"
      grep -n "\.git/hooks\|fugitive\|gina\|git\.\|hook\|system.*git\|call.*git\|Git\s\+commit" "$file" | head -5 >> "$REPORT_FILE"
      
      # Check for file writing operations
      if grep -q "writefile\|system.*>\|call.*>" "$file"; then
        echo -e "${RED}CRITICAL: Plugin with Git interaction also writes files!${NC}" | tee -a "$REPORT_FILE"
        grep -n "writefile\|system.*>\|call.*>" "$file" | head -5 >> "$REPORT_FILE"
      fi
    done
  else
    echo "No VCS plugins found in vimrc." >> "$REPORT_FILE"
  fi
  
  # Look for direct hook file manipulation
  echo -e "\n### Direct hook file manipulation" >> "$REPORT_FILE"
  find "$PLUGIN_DIR" -type f -name "*.vim" -exec grep -l "\.git/hooks\|post-commit\|pre-commit\|post-receive\|pre-receive" {} \; | while read -r file; do
    echo -e "${RED}CRITICAL: Plugin directly manipulates Git hooks:${NC} $file" | tee -a "$REPORT_FILE"
    grep -n "\.git/hooks\|post-commit\|pre-commit\|post-receive\|pre-receive" "$file" | head -5 >> "$REPORT_FILE"
  done
}

# Generate summary
generate_summary() {
  echo -e "\n${BLUE}Generating summary...${NC}"
  echo -e "\n## Summary" >> "$REPORT_FILE"
  
  # Count critical findings
  critical_findings=$(grep -c "CRITICAL:" "$REPORT_FILE")
  
  # Count security risks
  security_risks=$(grep -c "SECURITY RISK:" "$REPORT_FILE")
  
  # Count cautions
  cautions=$(grep -c "CAUTION:" "$REPORT_FILE")
  
  echo -e "- Critical Findings: $critical_findings" >> "$REPORT_FILE"
  echo -e "- Security Risks: $security_risks" >> "$REPORT_FILE"
  echo -e "- Cautions: $cautions" >> "$REPORT_FILE"
  
  total_issues=$((critical_findings + security_risks + cautions))
  
  if [ $total_issues -gt 0 ]; then
    echo -e "\n${YELLOW}Found $total_issues potential security issues related to Vim configuration.${NC}" | tee -a "$REPORT_FILE"
    
    if [ $critical_findings -gt 0 ]; then
      echo -e "${RED}$critical_findings CRITICAL issues found!${NC}" | tee -a "$REPORT_FILE"
    fi
    
    echo -e "Please review the full report for details." | tee -a "$REPORT_FILE"
  else
    echo -e "\n${GREEN}No VimRC-related security issues detected.${NC}" | tee -a "$REPORT_FILE"
  fi
  
  echo -e "\nFull report available at: $REPORT_FILE"
}

# Main function
main() {
  # Set vimrc file and plugin directory
  VIMRC_FILE="${1:-$HOME/.vimrc}"
  PLUGIN_DIR="${2:-$HOME/.vim/plugged}"
  
  if [ ! -f "$VIMRC_FILE" ]; then
    echo -e "${RED}Error: VimRC file does not exist:${NC} $VIMRC_FILE"
    exit 1
  fi
  
  if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${RED}Error: Plugin directory does not exist:${NC} $PLUGIN_DIR"
    exit 1
  fi
  
  echo -e "${BLUE}Vim RC Configuration Threats Detector${NC}"
  echo -e "Target VimRC: ${YELLOW}$VIMRC_FILE${NC}"
  echo -e "Target Plugin Directory: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Date: ${SCAN_DATE}"
  
  initialize_report
  
  # Run all scans
  scan_bootstrap_exploits
  scan_autocommand_cascades
  scan_exrc_modeline_exploits
  scan_plugin_fetch_redirectors
  scan_mapping_shadow_exploits
  scan_wildmenu_path_exploits
  scan_undo_directory_exploits
  scan_external_command_chaining
  scan_linter_payload_exploits
  scan_vcs_hook_injection
  
  generate_summary
  
  echo -e "\n${GREEN}Scan completed!${NC}"
}

# Run the main function with all arguments
main "$@"