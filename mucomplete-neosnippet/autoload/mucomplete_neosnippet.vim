" mucomplete neosnippet completions
function! mucomplete_neosnippet#complete() abort
	let l:snippets = neosnippet#helpers#get_snippets()
	if empty(l:snippets)
		return ''
	endif

	let l:pat = matchstr(getline('.'), '\S\+\%'.col('.').'c')
	let l:candidates = map(filter(keys(l:snippets), 'stridx(v:val,l:pat)==0'),
				\  '{
				\      "word": v:val,
				\      "menu": "[neo] ". get(l:snippets[v:val], "description", ""),
				\      "dup" : 1
				\   }')
	if !empty(l:candidates)
		call complete(col('.') - len(l:pat), l:candidates)
	endif
	return ''
endfunction
