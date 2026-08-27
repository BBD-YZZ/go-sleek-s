# gosleek zsh completion
# 安装: echo 'source <(gosleek completion zsh)' >> ~/.zshrc && source ~/.zshrc

#compdef gosleek

_gosleek() {
    local -a commands
    commands=(
        'scan:扫描目标漏洞'
        'list:列出/筛选可用模板'
        'validate:校验模板语法'
        'replay:复放命中的请求'
        'version:显示版本信息'
        'help:显示帮助信息'
        'completion:生成补全脚本'
    )

    local -a scan_flags
    scan_flags=(
        '-t+[单个目标 URL]:TARGET:-'
        '--target+[单个目标 URL]:TARGET:-'
        '-l+[目标列表文件]:FILE:-'
        '--list+[目标列表文件]:FILE:-'
        '-T+[模板目录]:DIR:-'
        '--templates+[模板目录]:DIR:-'
        '-id+[按 ID 筛选]:ID:-'
        '--tid+[按 ID 筛选]:ID:-'
        '--tags+[按标签筛选]:TAGS:-'
        '--severity+[按严重度筛选]:SEVERITY:-'
        '-e+[排除指定 ID]:ID:-'
        '--exclude+[排除指定 ID]:ID:-'
        '-v:[详细输出]'
        '--silent:[静默模式]'
        '-o+[结果输出文件]:FILE:-'
        '--output+[结果输出文件]:FILE:-'
        '-f+[输出格式]:FORMAT:(json txt sarif html csv markdown)'
        '--format+[输出格式]:FORMAT:(json txt sarif html csv markdown)'
        '-c+[并发数]:NUMBER:-'
        '--concurrency+[并发数]:NUMBER:-'
        '-r+[速率限制]:NUMBER:-'
        '--rate-limit+[速率限制]:NUMBER:-'
        '--timeout+[请求超时秒数]:NUMBER:-'
        '-p+[代理地址]:PROXY:-'
        '--proxy+[代理地址]:PROXY:-'
        '-k:[启用 TLS 证书校验]'
        '--verify-ssl:[启用 TLS 证书校验]'
        '--oob:[启用 OOB 占位符]'
        '--ceye-key+[ceye.io API Token]:KEY:-'
        '--ceye-domain+[ceye.io 识别域名]:DOMAIN:-'
        '--resume+[从保存的状态断点续扫]:FILE:-'
        '--log-file+[日志文件]:FILE:-'
        '--log-level+[日志级别]:LEVEL:(debug info warn error)'
        '--plugins-only:[仅使用 Go 插件扫描]'
        '--plugin+[指定 Go 插件 ID]:ID:-'
        '--redact:[脱敏输出]'
        '-s+[结果过滤:仅保留指定严重度]:SEVERITY:-'
        '--filter-severity+[结果过滤:仅保留指定严重度]:SEVERITY:-'
        '--filter-tags+[结果过滤:仅保留指定标签]:TAGS:-'
        '--follow-redirects:[全局跟随重定向]'
        '-H+[全局请求头注入]:HEADER:-'
        '--header+[全局请求头注入]:HEADER:-'
        '--output-dir+[结果输出目录]:DIR:-'
        '--wordlist-dir+[wordlist 基础目录]:DIR:-'
        '-h:[显示帮助信息]'
        '--help:[显示帮助信息]'
    )

    local -a list_flags
    list_flags=(
        '-T+[模板目录]:DIR:-'
        '--templates+[模板目录]:DIR:-'
        '--plugins-only:[仅列出 Go 插件]'
        '-id+[按 ID 筛选]:ID:-'
        '--tid+[按 ID 筛选]:ID:-'
        '--tags+[按标签筛选]:TAGS:-'
        '--severity+[按严重度筛选]:SEVERITY:-'
        '-e+[排除指定 ID]:ID:-'
        '--exclude+[排除指定 ID]:ID:-'
        '-h:[显示帮助信息]'
        '--help:[显示帮助信息]'
    )

    local -a replay_flags
    replay_flags=(
        '-t+[指定目标 URL]:TARGET:-'
        '--target+[指定目标 URL]:TARGET:-'
        '-e:[编辑请求后再发送]'
        '--edit:[编辑请求后再发送]'
        '-o+[保存响应到指定目录]:DIR:-'
        '--output-dir+[保存响应到指定目录]:DIR:-'
        '-p:[美化 JSON 输出]'
        '--pretty:[美化 JSON 输出]'
        '-h:[显示帮助信息]'
        '--help:[显示帮助信息]'
    )

    local state
    _arguments -C -s \
        '1:command:->commands' \
        '*:arg:->args'

    case "${state}" in
        commands)
            _describe 'command' commands
            ;;
        args)
            case "${words[1]}" in
                scan)
                    _arguments -C -s ${scan_flags[@]}
                    ;;
                list)
                    _arguments -C -s ${list_flags[@]}
                    ;;
                validate)
                    _arguments -C -s \
                        '-h:[显示帮助信息]' \
                        '--help:[显示帮助信息]' \
                        '1:file:_files'
                    ;;
                replay)
                    _arguments -C -s ${replay_flags[@]} \
                        '1:file:_files'
                    ;;
                completion)
                    _describe 'shell' '(bash zsh powershell)'
                    ;;
            esac
            ;;
    esac
}
