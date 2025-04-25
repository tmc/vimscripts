#!/bin/bash
#
# Vim Plugin Runtime Behavior Detector
#
# This script specializes in detecting runtime behavior of Vim plugins
# by executing them in a controlled environment and monitoring system calls.
#
# Usage: ./detect-runtime-behavior.sh [PLUGIN_DIR]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/runtime-behavior-report.txt"
TEMP_DIR=$(mktemp -d)
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
  rm -rf "$TEMP_DIR"
}

# Set trap to ensure cleanup on exit
trap cleanup EXIT

# Initialize report
initialize_report() {
  echo "# Vim Plugin Runtime Behavior Detector" > "$REPORT_FILE"
  echo "Date: $SCAN_DATE" >> "$REPORT_FILE"
  echo "Target Directory: $PLUGIN_DIR" >> "$REPORT_FILE"
  echo "----------------------------------------" >> "$REPORT_FILE"
}

# Create instrumentation script
create_instrumentation() {
  cat > "$TEMP_DIR/instrumentation.vim" << 'EOF'
" Runtime Behavior Instrumentation Script

" Global trackers
let g:cmd_executed = []
let g:files_accessed = []
let g:network_activity = []
let g:system_calls = []
let g:register_ops = []
let g:option_changes = []
let g:mapping_changes = []
let g:buffer_vars = []
let g:suspicious_behaviors = []

" Directory for logs
let s:log_dir = expand('<sfile>:p:h')
let s:results_file = s:log_dir . '/runtime_results.json'

" Hook system function
let s:original_system = function('system')
function! InterceptSystem(cmd, ...)
  call add(g:system_calls, {'cmd': a:cmd, 'time': localtime()})
  
  " Check for suspicious patterns
  if a:cmd =~# '>\s*/tmp\|>\s*/var/tmp\|curl\|wget\|chmod\|sudo\|rm\s\+'
    call add(g:suspicious_behaviors, {'type': 'system_call', 'cmd': a:cmd, 'severity': 'HIGH'})
  endif
  
  " Execute actual command with original system()
  if a:0 > 0
    return s:original_system(a:cmd, a:1)
  else
    return s:original_system(a:cmd)
  endif
endfunction

" Remap system function
let g:system = function('InterceptSystem')

" Hook execute function
let s:original_execute = function('execute')
function! InterceptExecute(cmd, ...)
  call add(g:cmd_executed, {'cmd': a:cmd, 'time': localtime()})
  
  " Check for suspicious patterns
  if a:cmd =~# '!\|system\|call\s\+system'
    call add(g:suspicious_behaviors, {'type': 'execute', 'cmd': a:cmd, 'severity': 'MEDIUM'})
  endif
  
  " Execute with original function
  if a:0 > 0
    return s:original_execute(a:cmd, a:1)
  else
    return s:original_execute(a:cmd)
  endif
endfunction

" Remap execute function
let g:execute = function('InterceptExecute')

" Track option changes
function! s:TrackOptionChange(option, oldval, newval)
  call add(g:option_changes, {'option': a:option, 'old': a:oldval, 'new': a:newval, 'time': localtime()})
  
  " Check for suspicious option changes
  if a:option =~# 'shell\|shellcmdflag\|makeprg\|grepprg' && a:newval =~# '!\|system\|exec\|;\|&\||\|>'
    call add(g:suspicious_behaviors, {'type': 'option_change', 'option': a:option, 'value': a:newval, 'severity': 'HIGH'})
  endif
endfunction

" Track register changes
function! s:TrackRegisterChange()
  for reg in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
              \'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    let l:content = getreg(reg)
    if !empty(l:content) && (!exists('s:last_reg_' . reg) || eval('s:last_reg_' . reg) !=# l:content)
      let s:last_reg_{reg} = l:content
      call add(g:register_ops, {'register': reg, 'content': l:content, 'time': localtime()})
      
      " Check for suspicious register content
      if l:content =~# '^!\|^:.*!\|^:.*call\s\+system\|^:.*execute'
        call add(g:suspicious_behaviors, {'type': 'register_manipulation', 'register': reg, 'content': l:content, 'severity': 'HIGH'})
      endif
    endif
  endfor
endfunction

" Track buffer variables
function! s:TrackBufferVars()
  for [key, val] in items(b:)
    " Skip standard variables
    if key =~# '^\(changedtick\|fileformat\|filetype\)$'
      continue
    endif
    
    let s:var_key = 'b:' . key
    call add(g:buffer_vars, {'var': s:var_key, 'value': string(val), 'time': localtime()})
    
    " Check for suspicious values
    if type(val) == type('') && val =~# 'system\|exec\|!\|call\s\+system'
      call add(g:suspicious_behaviors, {'type': 'buffer_var', 'var': s:var_key, 'value': val, 'severity': 'MEDIUM'})
    endif
  endfor
endfunction

" Track mapping changes
function! s:TrackMappings()
  let l:output = execute('map')
  let l:maps = split(l:output, "\n")
  for l:map in l:maps
    if l:map =~# '^[nvoicst]'
      call add(g:mapping_changes, {'mapping': l:map, 'time': localtime()})
      
      " Check for suspicious mappings
      if l:map =~# '!\|system\|call\s\+system\|execute'
        call add(g:suspicious_behaviors, {'type': 'mapping', 'mapping': l:map, 'severity': 'MEDIUM'})
      endif
    endif
  endfor
endfunction

" Track file access
function! s:TrackFileAccess()
  let l:file = expand('%:p')
  if !empty(l:file)
    call add(g:files_accessed, {'file': l:file, 'time': localtime()})
    
    " Check for suspicious file access
    if l:file =~# '^/tmp\|^/var/tmp\|\.git/hooks\|\.ssh\|\.bash'
      call add(g:suspicious_behaviors, {'type': 'file_access', 'file': l:file, 'severity': 'MEDIUM'})
    endif
  endif
endfunction

" Set up event listeners
augroup RuntimeBehaviorMonitor
  autocmd!
  autocmd OptionSet * call s:TrackOptionChange(expand('<amatch>'), v:option_old, v:option_new)
  autocmd CursorMoved * call s:TrackRegisterChange()
  autocmd BufEnter,BufWritePost * call s:TrackBufferVars()
  autocmd BufEnter * call s:TrackFileAccess()
  autocmd VimEnter * call s:TrackMappings()
  autocmd VimLeavePre * call s:SaveResults()
augroup END

" Simulate user actions to trigger potential behaviors
function! s:SimulateUserActions()
  " Simulate various mappings with leader key
  for key in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
              \'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    silent! execute 'normal \' . key
    sleep 100m
  endfor
  
  " Simulate search pattern changes
  let @/ = 'test'
  sleep 100m
  let @/ = 'fold'
  sleep 100m
  let @/ = 'sync'
  sleep 100m
  
  " Simulate buffer variable changes
  let b:count = 0
  sleep 100m
  let b:count = 1
  sleep 100m
  let b:count = 2
  sleep 100m
  let b:count = 3
  sleep 100m
  
  " Simulate colorscheme changes
  silent! colorscheme default
  sleep 100m
  silent! colorscheme desert
  sleep 100m
  
  " Simulate window operations
  silent! vsplit
  sleep 100m
  silent! split
  sleep 100m
  silent! close
  sleep 100m
endfunction

" Save results to file for external processing
function! s:SaveResults()
  let l:results = {
        \ 'system_calls': g:system_calls,
        \ 'cmd_executed': g:cmd_executed,
        \ 'files_accessed': g:files_accessed,
        \ 'network_activity': g:network_activity,
        \ 'register_ops': g:register_ops,
        \ 'option_changes': g:option_changes,
        \ 'mapping_changes': g:mapping_changes,
        \ 'buffer_vars': g:buffer_vars,
        \ 'suspicious_behaviors': g:suspicious_behaviors
        \ }
  
  " Convert to JSON and write to file
  let l:json = json_encode(l:results)
  call writefile([l:json], s:results_file)
endfunction

" Call simulation after a short delay
call timer_start(1000, {-> s:SimulateUserActions()})

" Exit Vim after simulation is complete
call timer_start(5000, {-> execute('qa!')})
EOF
}

# Create empty test file
create_test_file() {
  cat > "$TEMP_DIR/test.txt" << 'EOF'
This is a test file for runtime behavior analysis.
EOF
}

# Run Vim with instrumentation
run_instrumented_vim() {
  echo -e "\n${BLUE}Running Vim with instrumentation...${NC}"
  
  # Create instrumentation and test file
  create_instrumentation
  create_test_file
  
  # Run Vim with minimal configuration and instrumentation
  VIMINIT="source $TEMP_DIR/instrumentation.vim" vim -N -X -u NONE -n \
    --not-a-term --noplugin --cmd "set rtp+=$PLUGIN_DIR" \
    -S "$TEMP_DIR/instrumentation.vim" "$TEMP_DIR/test.txt" >/dev/null 2>&1
  
  # Check if results file was created
  if [ ! -f "$TEMP_DIR/runtime_results.json" ]; then
    echo -e "${RED}Failed to generate runtime results.${NC}"
    echo "Runtime analysis failed - no results generated." >> "$REPORT_FILE"
    return 1
  fi
  
  return 0
}

# Analyze collected runtime data
analyze_runtime_data() {
  echo -e "\n${BLUE}Analyzing runtime behavior data...${NC}"
  echo -e "\n## Runtime Behavior Analysis" >> "$REPORT_FILE"
  
  # Check if results file exists
  if [ ! -f "$TEMP_DIR/runtime_results.json" ]; then
    echo -e "${RED}No runtime results found for analysis.${NC}"
    echo "No runtime results available." >> "$REPORT_FILE"
    return 1
  fi
  
  # Extract suspicious behaviors
  echo -e "\n### Suspicious Behaviors Detected" >> "$REPORT_FILE"
  suspicious_count=$(jq '.suspicious_behaviors | length' "$TEMP_DIR/runtime_results.json")
  
  if [ "$suspicious_count" -gt 0 ]; then
    echo -e "${YELLOW}Found $suspicious_count suspicious runtime behaviors!${NC}"
    echo -e "Detected $suspicious_count suspicious runtime behaviors:" >> "$REPORT_FILE"
    
    jq -r '.suspicious_behaviors[] | "- TYPE: " + .type + ", SEVERITY: " + .severity + (if .cmd then ", COMMAND: " + .cmd else "" end) + (if .option then ", OPTION: " + .option + ", VALUE: " + .value else "" end) + (if .register then ", REGISTER: " + .register + ", CONTENT: " + .content else "" end) + (if .var then ", VARIABLE: " + .var + ", VALUE: " + .value else "" end) + (if .mapping then ", MAPPING: " + .mapping else "" end) + (if .file then ", FILE: " + .file else "" end)' "$TEMP_DIR/runtime_results.json" >> "$REPORT_FILE"
  else
    echo -e "${GREEN}No suspicious runtime behaviors detected.${NC}"
    echo "No suspicious runtime behaviors detected." >> "$REPORT_FILE"
  fi
  
  # Analyze system calls
  echo -e "\n### System Calls Executed" >> "$REPORT_FILE"
  system_call_count=$(jq '.system_calls | length' "$TEMP_DIR/runtime_results.json")
  
  if [ "$system_call_count" -gt 0 ]; then
    echo -e "${YELLOW}Plugin executed $system_call_count system calls!${NC}"
    echo -e "Plugin executed $system_call_count system calls:" >> "$REPORT_FILE"
    
    jq -r '.system_calls[] | "- " + .cmd' "$TEMP_DIR/runtime_results.json" >> "$REPORT_FILE"
  else
    echo "No system calls executed." >> "$REPORT_FILE"
  fi
  
  # Analyze option changes
  echo -e "\n### Option Changes" >> "$REPORT_FILE"
  option_count=$(jq '.option_changes | length' "$TEMP_DIR/runtime_results.json")
  
  if [ "$option_count" -gt 0 ]; then
    echo -e "Plugin changed $option_count Vim options:" >> "$REPORT_FILE"
    
    jq -r '.option_changes[] | "- " + .option + ": \"" + .old + "\" -> \"" + .new + "\""' "$TEMP_DIR/runtime_results.json" >> "$REPORT_FILE"
    
    # Check for security-sensitive options
    sensitive_options=$(jq -r '.option_changes[] | select(.option=="shell" or .option=="shellcmdflag" or .option=="makeprg" or .option=="grepprg") | .option + " = " + .new' "$TEMP_DIR/runtime_results.json")
    
    if [ -n "$sensitive_options" ]; then
      echo -e "${RED}CRITICAL: Plugin modified security-sensitive options!${NC}"
      echo -e "\nCRITICAL: Plugin modified security-sensitive options:" >> "$REPORT_FILE"
      echo "$sensitive_options" >> "$REPORT_FILE"
    fi
  else
    echo "No option changes detected." >> "$REPORT_FILE"
  fi
  
  # Analyze register operations
  echo -e "\n### Register Operations" >> "$REPORT_FILE"
  register_count=$(jq '.register_ops | length' "$TEMP_DIR/runtime_results.json")
  
  if [ "$register_count" -gt 0 ]; then
    echo -e "Plugin modified $register_count registers:" >> "$REPORT_FILE"
    
    # Check for suspicious register content
    suspicious_registers=$(jq -r '.register_ops[] | select(.content | test("^!|^:|system|exec|call")) | "- @" + .register + ": " + .content' "$TEMP_DIR/runtime_results.json")
    
    if [ -n "$suspicious_registers" ]; then
      echo -e "${RED}CRITICAL: Plugin wrote suspicious content to registers!${NC}"
      echo -e "\nCRITICAL: Suspicious register content:" >> "$REPORT_FILE"
      echo "$suspicious_registers" >> "$REPORT_FILE"
    else
      echo "No suspicious register content detected." >> "$REPORT_FILE"
    fi
  else
    echo "No register operations detected." >> "$REPORT_FILE"
  fi
  
  # Analyze buffer variables
  echo -e "\n### Buffer Variables" >> "$REPORT_FILE"
  buffer_var_count=$(jq '.buffer_vars | length' "$TEMP_DIR/runtime_results.json")
  
  if [ "$buffer_var_count" -gt 0 ]; then
    echo -e "Plugin set $buffer_var_count buffer variables:" >> "$REPORT_FILE"
    
    # Check for suspicious variable values
    suspicious_vars=$(jq -r '.buffer_vars[] | select(.value | test("system|exec|!|call")) | "- " + .var + ": " + .value' "$TEMP_DIR/runtime_results.json")
    
    if [ -n "$suspicious_vars" ]; then
      echo -e "${RED}CRITICAL: Plugin set suspicious buffer variables!${NC}"
      echo -e "\nCRITICAL: Suspicious buffer variables:" >> "$REPORT_FILE"
      echo "$suspicious_vars" >> "$REPORT_FILE"
    else
      echo "No suspicious buffer variables detected." >> "$REPORT_FILE"
    fi
  else
    echo "No buffer variables set." >> "$REPORT_FILE"
  fi
}

# Generate summary
generate_summary() {
  echo -e "\n${BLUE}Generating summary...${NC}"
  echo -e "\n## Summary" >> "$REPORT_FILE"
  
  # Count suspicious behaviors by severity
  high_severity=$(jq -r '.suspicious_behaviors[] | select(.severity=="HIGH") | .type' "$TEMP_DIR/runtime_results.json" | wc -l)
  medium_severity=$(jq -r '.suspicious_behaviors[] | select(.severity=="MEDIUM") | .type' "$TEMP_DIR/runtime_results.json" | wc -l)
  
  # Count system calls
  system_calls=$(jq '.system_calls | length' "$TEMP_DIR/runtime_results.json")
  
  # Count security-sensitive option changes
  sensitive_options=$(jq -r '.option_changes[] | select(.option=="shell" or .option=="shellcmdflag" or .option=="makeprg" or .option=="grepprg") | .option' "$TEMP_DIR/runtime_results.json" | wc -l)
  
  echo -e "- High Severity Issues: $high_severity" >> "$REPORT_FILE"
  echo -e "- Medium Severity Issues: $medium_severity" >> "$REPORT_FILE"
  echo -e "- System Calls: $system_calls" >> "$REPORT_FILE"
  echo -e "- Security-Sensitive Option Changes: $sensitive_options" >> "$REPORT_FILE"
  
  total_issues=$((high_severity + medium_severity))
  
  if [ $total_issues -gt 0 ]; then
    echo -e "\n${YELLOW}Found $total_issues runtime security issues.${NC}" | tee -a "$REPORT_FILE"
    
    if [ $high_severity -gt 0 ]; then
      echo -e "${RED}$high_severity HIGH severity issues found!${NC}" | tee -a "$REPORT_FILE"
    fi
    
    echo -e "Please review the full report for details." | tee -a "$REPORT_FILE"
  else
    echo -e "\n${GREEN}No runtime security issues detected.${NC}" | tee -a "$REPORT_FILE"
  fi
  
  echo -e "\nFull report available at: $REPORT_FILE"
}

# Main function
main() {
  # Set plugin directory
  PLUGIN_DIR="${1:-$HOME/.vim/plugged}"
  
  if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${RED}Error: Plugin directory does not exist:${NC} $PLUGIN_DIR"
    exit 1
  fi
  
  echo -e "${BLUE}Vim Plugin Runtime Behavior Detector${NC}"
  echo -e "Target: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Date: ${SCAN_DATE}"
  
  initialize_report
  
  # Run Vim with instrumentation
  if run_instrumented_vim; then
    # Analyze the collected data
    analyze_runtime_data
    
    # Generate summary
    generate_summary
  else
    echo -e "${RED}Runtime analysis failed.${NC}"
  fi
  
  echo -e "\n${GREEN}Scan completed!${NC}"
}

# Run the main function with all arguments
main "$@"