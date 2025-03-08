" vim_git_backups
" uses git to maintain backups of your files and .viminfo
augroup custom_backup
  autocmd!
  autocmd BufWritePost * call BackupCurrentFile()
augroup end

let s:custom_backup_dir=expand(get(g:, 'vim_git_backups_directory', '~/.vim-git-backups'))
let s:ignore_paths=get(g:, 'vim_git_backups_ignore_paths', [])
let s:debug=get(g:, 'vim_git_backups_debug', 0)

function! s:log(msg)
  if s:debug
    let timestamp = strftime('%H:%M:%S')
    echom "[git-backups " . timestamp . "] " . a:msg
  endif
endfunction

function! s:normalize_path(base_path, rel_path)
  " Determine path separator based on OS
  let path_sep = has('win32') ? '\' : '/'
  
  " Ensure base path has trailing slash/backslash
  let norm_base = a:base_path
  if norm_base !~ escape(path_sep, '\') . '$'
    let norm_base .= path_sep
  endif
  
  " Handle absolute paths to avoid double slashes/backslashes
  let norm_rel = a:rel_path
  
  if has('win32')
    " Handle Windows paths (both C:\ style and UNC paths)
    if norm_rel =~ '^[A-Za-z]:'
      " For paths with drive letter (C:\path\file)
      " Extract drive letter and keep it
      let drive = matchstr(norm_rel, '^[A-Za-z]:')
      let path = strpart(norm_rel, 2) " Skip drive letter and colon
      
      " Remove leading slash/backslash if present
      if path =~ '^[/\\]'
        let path = strpart(path, 1)
      endif
      
      " Construct normalized path with drive letter
      let norm_rel = drive . path
    elseif norm_rel =~ '^[/\\]'
      " For paths starting with \ or / but without drive letter
      let norm_rel = strpart(norm_rel, 1)
    endif
    
    " Replace forward slashes with backslashes for Windows
    let norm_rel = substitute(norm_rel, '/', '\', 'g')
    
    " Clean up any double backslashes in the normalized path
    let result = norm_base . norm_rel
    if result =~ '\\\\'
      let result = substitute(result, '\\\\', '\', 'g')
    endif
  else
    " Unix-like systems
    if norm_rel =~ '^/'
      let norm_rel = strpart(norm_rel, 1)
    endif
    
    " Combine and clean up any double slashes
    let result = norm_base . norm_rel
    if result =~ '//'
      let result = substitute(result, '//', '/', 'g')
    endif
  endif
  
  return result
endfunction

function! s:get_command_prefix()
  " Use appropriate command depending on OS
  if has('win32')
    return 'cmd /c '
  else
    return ''
  endif
endfunction

function! s:get_viminfo_path()
  " Use appropriate viminfo path depending on OS
  if has('win32')
    return expand('~/_viminfo')
  else
    return expand('~/.viminfo')
  endif
endfunction

function! s:fix_path_for_shell(path)
  " Fix path for shell commands depending on OS
  let fixed_path = a:path
  if has('win32')
    " Escape backslashes for Windows commands
    let fixed_path = substitute(fixed_path, '\\', '\\\\', 'g')
  endif
  return fixed_path
endfunction

function! BackupCurrentFile()
  call s:log("Starting backup for file: " . expand('%:p'))
  
  if !isdirectory(expand(s:custom_backup_dir))
    call s:log("Creating backup directory: " . s:custom_backup_dir)
    
    if has('win32')
      " Windows version
      let cmd = 'mkdir "' . s:custom_backup_dir . '" & '
      let cmd .= 'cd /d "' . s:custom_backup_dir . '" & '
      let cmd .= 'git init'
    else
      " Unix version
      let cmd = 'mkdir -p ' . shellescape(s:custom_backup_dir) . ';'
      let cmd .= 'cd ' . shellescape(s:custom_backup_dir) . ';'
      let cmd .= 'git init;'
    endif
    
    if s:debug
      let output = system(s:get_command_prefix() . cmd)
      call s:log("Init result code: " . v:shell_error)
      call s:log("Init output: " . output)
    else
      call system(s:get_command_prefix() . cmd)
    endif
  endif
  
  let file = expand('%:p')
  call s:log("Processing file: " . file)
  
  " Check if file should be ignored
  if file =~ fnamemodify(s:custom_backup_dir, ':t')
    call s:log("Skipping - file is in backup dir")
    return 
  endif
  
  for ignore_path in s:ignore_paths
    if file =~ '^' . ignore_path
      call s:log("Skipping - file matches ignore pattern: " . ignore_path)
      return
    endif
  endfor
  
  " Use normalized paths
  let file_dir = s:normalize_path(s:custom_backup_dir, expand('%:p:h'))
  let backup_file = s:normalize_path(s:custom_backup_dir, file)
  
  call s:log("Backup dir: " . file_dir)
  call s:log("Backup file: " . backup_file)
  
  let cmd = ''
  if !isdirectory(expand(file_dir))
    call s:log("Creating backup file directory")
    if has('win32')
      " Windows version
      let cmd .= 'mkdir "' . s:fix_path_for_shell(file_dir) . '" & '
    else
      " Unix version
      let cmd .= 'mkdir -p ' . shellescape(file_dir) . ';'
    endif
  endif
  
  call s:log("Building backup command")
  
  let viminfo_path = s:get_viminfo_path()
  
  if has('win32')
    " Windows version using copy commands
    let cmd .= 'copy "' . s:fix_path_for_shell(viminfo_path) . '" "' . s:fix_path_for_shell(s:custom_backup_dir) . '" /Y & '
    let cmd .= 'copy "' . s:fix_path_for_shell(file) . '" "' . s:fix_path_for_shell(backup_file) . '" /Y & '
    let cmd .= 'cd /d "' . s:fix_path_for_shell(s:custom_backup_dir) . '" & '
    let cmd .= 'git add ' . (has('win32') ? '_viminfo' : '.viminfo') . ' & '
    let cmd .= 'git add "' . s:fix_path_for_shell(backup_file) . '" & '
    let cmd .= 'git commit --no-gpg-sign -m "Backup - %DATE% %TIME%"'
  else
    " Unix version
    let cmd .= 'cp ' . shellescape(viminfo_path) . ' ' . shellescape(s:custom_backup_dir) . ';'
    let cmd .= 'cp ' . shellescape(file) . ' ' . shellescape(backup_file) . ';'
    let cmd .= 'cd ' . shellescape(s:custom_backup_dir) . ';'
    let cmd .= 'git add .viminfo;'
    let cmd .= 'git add ' . shellescape(backup_file) . ';'
    let cmd .= 'git commit --no-gpg-sign -m "Backup - $(date)";'
  endif
  
  call s:log("Executing command: " . cmd)
  
  let job_options = {
    \ 'exit_cb': function('s:BackupCompletionCallback')
    \ }
    
  if s:debug
    let job_options['out_cb'] = function('s:JobStdoutCallback')
    let job_options['err_cb'] = function('s:JobStderrCallback')
  endif
  
  if has('win32')
    call job_start(['cmd', '/c', cmd], job_options)
  else
    call job_start(['sh', '-c', cmd], job_options)
  endif
endfunction

function! s:BackupCompletionCallback(channel, exit_status)
  call s:log("Backup completed with status: " . a:exit_status)
endfunction

function! s:JobStdoutCallback(channel, msg)
  call s:log("STDOUT: " . a:msg)
endfunction

function! s:JobStderrCallback(channel, msg)
  call s:log("STDERR: " . a:msg)
endfunction

function! OpenCurrentFileBackupHistory()
  let backup_dir = s:normalize_path(s:custom_backup_dir, expand('%:p:h'))
  let cmd = ""
  
  call s:log("Opening history from: " . backup_dir)
  
  if has('win32')
    " Windows version
    let cmd = "cd /d " . '"' . s:fix_path_for_shell(backup_dir) . '"'
    let cmd .= " & git log -p --since=\"1 month\" " . '"' . expand('%:t') . '"'
  else
    " Unix version
    let cmd = "cd " . shellescape(backup_dir)
    let cmd .= "; git log -p --since='1 month' " . shellescape(expand('%:t'))
  endif

  silent! exe "noautocmd botright pedit vim_git_backups"
  noautocmd wincmd P
  set buftype=nofile
  
  if s:debug
    call s:log("Executing history command: " . cmd)
    let output = system(s:get_command_prefix() . cmd)
    call s:log("History command result code: " . v:shell_error)
    if v:shell_error != 0
      call s:log("History command error: " . output)
    endif
  endif
  
  if has('win32')
    exe "noautocmd r! " . cmd
  else
    exe "noautocmd r! " . cmd
  endif
  
  exe "normal! gg"
  noautocmd wincmd p
endfunction
