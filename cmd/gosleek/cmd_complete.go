package main

import "fmt"

func printCompletion() {
	fmt.Print(`
_gosleek_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="scan list validate replay version help"
    local flags="-t --target -l --list -T --templates -id --tid --tags --severity -e --exclude -v --verbose -vv --silent -o --output -f --format -c --concurrency -r --rate-limit --timeout -p --proxy -k --verify-ssl --oob --oob-provider --ceye-key --ceye-domain --allow-external-hosts --resume --log-file --log-level --plugins-only --plugin --redact -s --filter-severity --filter-tags --follow-redirects -H --header --output-dir --wordlist-dir"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
    else
        COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
    fi
}
complete -F _gosleek_complete gosleek
`)
}
