" vim_git_backups
" uses git to maintain backups of your files and .viminfo
augroup custom_backup
  autocmd!
  autocmd BufWritePost * call BackupCurrentFile()
augroup end

let s:custom_backup_dir=get(g:, 'vim_git_backups_directory', '~/.vim-git-backups')

function! BackupCurrentFile()
  if !isdirectory(expand(s:custom_backup_dir))
    let cmd = 'mkdir -p ' . s:custom_backup_dir . ';'
    let cmd .= 'cd ' . s:custom_backup_dir . ';'
    let cmd .= 'git init;'
    call system(cmd)
  endif
  let file = expand('%:p')
  if file =~ fnamemodify(s:custom_backup_dir, ':t') | return | endif
  let file_dir = s:custom_backup_dir . expand('%:p:h')
  let backup_file = s:custom_backup_dir . file
  let cmd = ''
  if !isdirectory(expand(file_dir))
    let cmd .= 'mkdir -p ' . file_dir . ';'
  endif
  let cmd .= 'cp ~/.viminfo ' . s:custom_backup_dir . ';'
  let cmd .= 'cp ' . file . ' ' . backup_file . ';'
  let cmd .= 'cd ' . s:custom_backup_dir . ';'
  let cmd .= 'git add .viminfo;'
  let cmd .= 'git add ' . backup_file . ';'
  let cmd .= 'git commit -m "Backup - `date`";'
  call job_start(['sh', '-c', cmd])
endfunction

function! OpenCurrentFileBackupHistory()
  let backup_dir = expand(s:custom_backup_dir . expand('%:p:h'))
  let cmd = "cd " . backup_dir
  let cmd .= "; git log -p --since='1 month' " . expand('%:t')

  silent! exe "noautocmd botright pedit vim_git_backups"
  noautocmd wincmd P
  set buftype=nofile
  exe "noautocmd r! ".cmd
  exe "normal! gg"
  noautocmd wincmd p
endfunction
