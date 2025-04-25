#!/bin/bash
#
# Path Update Script for vim-plugin-security
#
# This script updates path references in the security scanning scripts
# to match the new organized plugin structure.

set -e

# Define colors for output
GREEN='\033[0;32m'
BLUE='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PLUGIN_HOME="${HOME}/.vim/plugged/vim-plugin-security"
SCRIPTS_DIR="${PLUGIN_HOME}/scripts"
DATA_DIR="${PLUGIN_HOME}/data"

echo -e "${BLUE}Updating path references in scripts...${NC}"

# Function to update paths in a script
update_paths() {
  local script_file="$1"
  local script_name=$(basename "$script_file")
  
  echo -e "${YELLOW}Updating paths in ${script_name}...${NC}"
  
  # Create a backup
  cp "$script_file" "${script_file}.bak"
  
  # Update database path references
  sed -i.tmp "s|vim-plugin-shas.json|${DATA_DIR}/vim-plugin-shas.json|g" "$script_file"
  
  # Update report path references
  sed -i.tmp "s|security-scan-report.txt|${DATA_DIR}/reports/security-scan-report.txt|g" "$script_file"
  sed -i.tmp "s|suspicious-patterns.txt|${DATA_DIR}/reports/suspicious-patterns.txt|g" "$script_file"
  
  # Update script path references
  sed -i.tmp "s|./detect-suspicious-patterns.sh|${SCRIPTS_DIR}/detect-suspicious-patterns.sh|g" "$script_file"
  sed -i.tmp "s|./track-git-shas.sh|${SCRIPTS_DIR}/track-git-shas.sh|g" "$script_file"
  sed -i.tmp "s|./scan-vim-plugins.sh|${SCRIPTS_DIR}/scan-vim-plugins.sh|g" "$script_file"
  
  # Update directory references
  if [[ "$script_name" == "scan-vim-plugins.sh" ]]; then
    # Create reports directory
    mkdir -p "${DATA_DIR}/reports"
    
    # Update report file initialization
    sed -i.tmp "s|REPORT_FILE=\"\${SCRIPT_DIR}/security-scan-report.txt\"|REPORT_FILE=\"${DATA_DIR}/reports/security-scan-report.txt\"|g" "$script_file"
  elif [[ "$script_name" == "detect-suspicious-patterns.sh" ]]; then
    # Update output file initialization
    sed -i.tmp "s|OUTPUT_FILE=\"\${SCRIPT_DIR}/suspicious-patterns.txt\"|OUTPUT_FILE=\"${DATA_DIR}/reports/suspicious-patterns.txt\"|g" "$script_file"
  elif [[ "$script_name" == "track-git-shas.sh" ]]; then
    # Update database file initialization
    sed -i.tmp "s|SHA_DATABASE=\"\${SCRIPT_DIR}/vim-plugin-shas.json\"|SHA_DATABASE=\"${DATA_DIR}/vim-plugin-shas.json\"|g" "$script_file"
  fi
  
  # Remove temporary files
  rm -f "${script_file}.tmp"
}

# Update paths in all scripts
update_paths "${SCRIPTS_DIR}/scan-vim-plugins.sh"
update_paths "${SCRIPTS_DIR}/detect-suspicious-patterns.sh"
update_paths "${SCRIPTS_DIR}/track-git-shas.sh"

echo -e "${GREEN}Path updates complete!${NC}"
echo -e "All scripts now use the new plugin directory structure."