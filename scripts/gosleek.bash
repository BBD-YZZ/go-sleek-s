# gosleek bash completion
# 安装: echo 'source <(gosleek completion bash)' >> ~/.bashrc && source ~/.bashrc

_gosleek_complete() {
    local cur prev words cword
    COMPREPLY=()

    # 获取当前输入的词
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # 获取之前的所有词
    words=("${COMP_WORDS[@]}")
    cword=${COMP_CWORD}

    # 顶层命令
    local commands="scan list validate replay version help completion"

    # Scan flags (按顺序排列，方便部分匹配)
    local scan_flags="-t --target -l --list -T --templates -id --tid --tags --severity -e --exclude -v -vv --silent -o --output -f --format -c --concurrency -r --rate-limit --timeout -p --proxy -k --verify-ssl --oob --ceye-key --ceye-domain --resume --log-file --log-level --plugins-only --plugin --redact -s --filter-severity --filter-tags --follow-redirects -H --header --output-dir --wordlist-dir -h --help"

    # List flags
    local list_flags="-T --templates --plugins-only -id --tid --tags --severity -e --exclude -h --help"

    # Validate flags
    local validate_flags="-h --help"

    # Replay flags
    local replay_flags="-t --target -e --edit -o --output-dir -p --pretty -h --help"

    # 如果当前词以 - 开头，补全 flag
    if [[ "${cur}" == -* ]]; then
        local flags=""
        # 检查当前在哪个子命令下
        for word in "${words[@]:1:$((cword-1))}"; do
            case "${word}" in
                scan)
                    flags="${scan_flags}"
                    break
                    ;;
                list)
                    flags="${list_flags}"
                    break
                    ;;
                validate)
                    flags="${validate_flags}"
                    break
                    ;;
                replay)
                    flags="${replay_flags}"
                    break
                    ;;
            esac
        done
        COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
        return
    fi

    # 如果前一个词是值类型的 flag，补全文件/目录
    local prev_word="${words[$((cword-1))]}"
    case "${prev_word}" in
        -t|--target|-l|--list|-T|--templates|-o|--output|-f|--format|-p|--proxy|\
        --ceye-key|--ceye-domain|--resume|--log-file|--log-level|--output-dir|\
        --wordlist-dir|-c|--concurrency|-r|--rate-limit|--timeout|\
        -e|--exclude|--tid|-id|--plugin)
            return
            ;;
    esac

    # 检查当前是否在子命令下（检查所有之前的词）
    local found_subcmd=""
    for word in "${words[@]:1:${cword}}"; do
        case "${word}" in
            scan|list|validate|replay)
                found_subcmd="${word}"
                ;;
        esac
    done

    if [[ -n "${found_subcmd}" ]]; then
        # 在子命令下，只补全 flag
        case "${found_subcmd}" in
            scan)
                COMPREPLY=( $(compgen -W "${scan_flags}" -- "${cur}") )
                ;;
            list)
                COMPREPLY=( $(compgen -W "${list_flags}" -- "${cur}") )
                ;;
            validate)
                COMPREPLY=( $(compgen -W "${validate_flags}" -- "${cur}") )
                ;;
            replay)
                COMPREPLY=( $(compgen -W "${replay_flags}" -- "${cur}") )
                ;;
        esac
    else
        # 顶层，补全命令
        COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
    fi
}

complete -F _gosleek_complete gosleek
