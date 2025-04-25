#!/bin/bash
#
# Vim Plugin Security - Installation Script
#
# This script sets up the vim-plugin-security by:
# 1. Creating the necessary directory structure
# 2. Moving scripts to the appropriate locations
# 3. Setting up configuration files

set -e

# Define colors for output
GREEN='\033[0;32m'
BLUE='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Define the plugin's home directory
PLUGIN_HOME="${HOME}/.vim/plugged/vim-plugin-security"

echo -e "${BLUE}Installing Vim Plugin Security Scanner...${NC}"

# Create directory structure if it doesn't exist
echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p "${PLUGIN_HOME}/scripts"
mkdir -p "${PLUGIN_HOME}/docs"
mkdir -p "${PLUGIN_HOME}/data"
mkdir -p "${PLUGIN_HOME}/autoload"
mkdir -p "${PLUGIN_HOME}/plugin"

# Copy scripts to the scripts directory
echo -e "${YELLOW}Copying scripts...${NC}"
cp "$(dirname "$0")/scan-vim-plugins.sh" "${PLUGIN_HOME}/scripts/"
cp "$(dirname "$0")/detect-suspicious-patterns.sh" "${PLUGIN_HOME}/scripts/"
cp "$(dirname "$0")/track-git-shas.sh" "${PLUGIN_HOME}/scripts/"

# Copy this script itself
cp "$(dirname "$0")/install.sh" "${PLUGIN_HOME}/scripts/"

# Create cleanup script
echo -e "${YELLOW}Creating cleanup script...${NC}"
cat > "${PLUGIN_HOME}/scripts/cleanup.sh" << EOF
#!/bin/bash
#
# Cleanup script for vim-plugin-security
#
# This script removes the original scripts from the main plugin directory
# after they have been properly installed in the scripts/ subdirectory.

echo "Cleaning up original files..."
rm -f "${PLUGIN_HOME}/scan-vim-plugins.sh"
rm -f "${PLUGIN_HOME}/detect-suspicious-patterns.sh"
rm -f "${PLUGIN_HOME}/track-git-shas.sh"
rm -f "${PLUGIN_HOME}/CLAUDE.md"
rm -f "${PLUGIN_HOME}/install.sh"

echo "Cleanup complete."
EOF

chmod +x "${PLUGIN_HOME}/scripts/cleanup.sh"

# Copy documentation
echo -e "${YELLOW}Copying documentation...${NC}"
cp "$(dirname "$0")/CLAUDE.md" "${PLUGIN_HOME}/docs/security-guide.md"

# Create autoload file for the plugin
echo -e "${YELLOW}Setting up plugin files...${NC}"
cat > "${PLUGIN_HOME}/autoload/plugin_security.vim" << EOF
" plugin_security.vim - Vim Plugin Security Scanner
" Maintainer: Security Team
" Version: 1.0.0

" Integration with vim-plug
function! plugin_security#vim_plug_integration()
  " Run security check before loading plugins
  let l:plugin_dir = expand('~/.vim/plugged')
  let l:script_path = expand('~/.vim/plugged/vim-plugin-security/scripts/scan-vim-plugins.sh')
  
  " Check if the script exists
  if !filereadable(l:script_path)
    echohl WarningMsg
    echo "Warning: Security scanner not found at " . l:script_path
    echohl None
    return
  endif
  
  " Run the security scan
  echo "Running security scan on vim plugins..."
  let l:cmd = l:script_path . ' ' . l:plugin_dir
  let l:output = system(l:cmd)
  
  " Check if any critical security issues were found
  if l:output =~ "CRITICAL"
    echohl ErrorMsg
    echo "CRITICAL SECURITY THREAT DETECTED IN PLUGINS!"
    echo "Check the security report for details."
    echo "Some plugins may be compromised and have been blocked from loading."
    echohl None
    
    " Here you could add code to block loading of suspicious plugins
    return 1
  elseif l:output =~ "HIGH RISK"
    echohl WarningMsg
    echo "HIGH RISK ISSUES DETECTED IN PLUGINS!"
    echo "Check the security report for details."
    echohl None
  endif
  
  return 0
endfunction

" Run a focused security scan on a single plugin
function! plugin_security#scan_plugin(plugin_name)
  let l:plugin_path = expand('~/.vim/plugged/' . a:plugin_name)
  let l:script_path = expand('~/.vim/plugged/vim-plugin-security/scripts/scan-vim-plugins.sh')
  
  if !isdirectory(l:plugin_path)
    echohl ErrorMsg
    echo "Plugin not found: " . a:plugin_name
    echohl None
    return
  endif
  
  echo "Scanning plugin: " . a:plugin_name
  let l:cmd = l:script_path . ' ' . l:plugin_path
  let l:output = system(l:cmd)
  
  echo l:output
endfunction

" Decode and analyze a suspicious string
function! plugin_security#decode_suspicious(encoded_string)
  " Try to decode the string using base64
  let l:cmd = "echo '" . a:encoded_string . "' | base64 -d"
  let l:decoded = system(l:cmd)
  
  echo "Analyzing suspicious string..."
  echo "Original: " . a:encoded_string
  echo "Decoded: " . l:decoded
  
  " Check for suspicious patterns in the decoded content
  if l:decoded =~ "\\(eval\\|exec\\|system\\|curl\\|wget\\|bash\\|sh\\)"
    echohl ErrorMsg
    echo "WARNING: This string decodes to potentially malicious content!"
    echohl None
  endif
  
  return l:decoded
endfunction
EOF

# Create plugin file
cat > "${PLUGIN_HOME}/plugin/vim_plugin_security.vim" << EOF
" vim_plugin_security.vim - Security scanning for vim plugins
" Maintainer: Security Team
" Version: 1.0.0

if exists("g:loaded_vim_plugin_security")
  finish
endif
let g:loaded_vim_plugin_security = 1

" Plugin configuration
let g:plugin_security_auto_scan = get(g:, 'plugin_security_auto_scan', 1)
let g:plugin_security_block_suspicious = get(g:, 'plugin_security_block_suspicious', 0)
let g:plugin_security_scan_on_startup = get(g:, 'plugin_security_scan_on_startup', 0)

" Commands
command! -nargs=0 SecurityScanAll call plugin_security#vim_plug_integration()
command! -nargs=1 SecurityScanPlugin call plugin_security#scan_plugin(<f-args>)
command! -nargs=1 SecurityDecodeString call plugin_security#decode_suspicious(<f-args>)

" Auto scan on startup if enabled
if g:plugin_security_scan_on_startup
  augroup PluginSecurityStartup
    autocmd!
    autocmd VimEnter * call plugin_security#vim_plug_integration()
  augroup END
endif

" Inform user the plugin is loaded
echohl MoreMsg
echo "Vim Plugin Security Scanner loaded."
echohl None
EOF

# Set up default configuration
echo -e "${YELLOW}Setting up configuration...${NC}"
cat > "${PLUGIN_HOME}/data/config.json" << EOF
{
  "scan_options": {
    "deep_scan": false,
    "decode_strings": true,
    "check_permissions": true,
    "check_signatures": true,
    "check_git_history": true
  },
  "reporting": {
    "report_dir": "${PLUGIN_HOME}/data/reports",
    "database_file": "${PLUGIN_HOME}/data/vim-plugin-shas.json",
    "notification_level": "warning" 
  },
  "plugin_actions": {
    "block_critical": true,
    "warn_high_risk": true,
    "log_all_issues": true
  }
}
EOF

# Make sure all scripts are executable
chmod +x "${PLUGIN_HOME}/scripts/"*.sh

echo -e "${GREEN}Installation complete!${NC}"
echo -e "To use the plugin with vim-plug, add these lines to your vimrc:"
echo -e "${BLUE}"
echo '  " Load security plugin first'
echo '  Plug '"'"'~/.vim/plugged/vim-plugin-security'"'"
echo '  '
echo '  " Run security checks before loading other plugins'
echo '  call plugin_security#vim_plug_integration()'
echo '  '
echo '  " Continue with regular plugins'
echo '  Plug '"'"'tpope/vim-fugitive'"'"
echo '  " etc.'
echo -e "${NC}"
echo -e "To clean up the original files, run:"
echo -e "${BLUE}  cd ${PLUGIN_HOME} && ./scripts/cleanup.sh${NC}"