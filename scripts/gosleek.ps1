# gosleek PowerShell completion
# 安装: echo 'gosleek completion powershell | Out-String | Invoke-Expression' >> $PROFILE
# 然后重启 PowerShell

Register-ArgumentCompleter -Native -CommandName gosleek -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)

    $commands = @('scan', 'list', 'validate', 'replay', 'version', 'help', 'completion')

    $wordToCompleteLower = $wordToComplete.ToLower()

    # 解析当前命令行
    $line = $null
    $parseError = $null
    [System.Management.Automation.Language.Parser]::ParseInput($psEditor.Editor.GetContents(), [ref]$line, [ref]$parseError)

    $tokens = $line.Tokens

    # 找到子命令
    $subCommand = $null
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if ($tokens[$i].Kind -eq 'CommandName') {
            $subCommand = $tokens[$i].Value.ToLower()
            break
        }
    }

    # 根据子命令补全
    switch ($subCommand) {
        'scan' {
            $flags = @(
                '-t', '--target',
                '-l', '--list',
                '-T', '--templates',
                '-id', '--tid',
                '--tags',
                '--severity',
                '-e', '--exclude',
                '-v', '--silent',
                '-o', '--output',
                '-f', '--format',
                '-c', '--concurrency',
                '-r', '--rate-limit',
                '--timeout',
                '-p', '--proxy',
                '-k', '--verify-ssl',
                '--oob',
                '--ceye-key',
                '--ceye-domain',
                '--resume',
                '--log-file',
                '--log-level',
                '--plugins-only',
                '--plugin',
                '--redact',
                '-s', '--filter-severity',
                '--filter-tags',
                '--follow-redirects',
                '-H', '--header',
                '--output-dir',
                '--wordlist-dir',
                '-h', '--help'
            )
            $formatOptions = @('json', 'txt', 'sarif', 'html', 'csv', 'markdown')
            $levelOptions = @('debug', 'info', 'warn', 'error')

            $candidates = @()
            foreach ($flag in $flags) {
                if ($flag -like "${wordToCompleteLower}*") {
                    $candidates += $flag
                }
            }
            foreach ($fmt in $formatOptions) {
                if ($fmt -like "${wordToCompleteLower}*") {
                    $candidates += $fmt
                }
            }
            foreach ($lvl in $levelOptions) {
                if ($lvl -like "${wordToCompleteLower}*") {
                    $candidates += $lvl
                }
            }
            return $candidates | Sort-Object -Unique | ForEach-Object {
                [System.Management.Automation.CompletionText]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'list' {
            $flags = @('-T', '--templates', '--plugins-only', '-id', '--tid', '--tags', '--severity', '-e', '--exclude', '-h', '--help')
            $candidates = @()
            foreach ($flag in $flags) {
                if ($flag -like "${wordToCompleteLower}*") {
                    $candidates += $flag
                }
            }
            return $candidates | ForEach-Object {
                [System.Management.Automation.CompletionText]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'replay' {
            $flags = @('-t', '--target', '-e', '--edit', '-o', '--output-dir', '-p', '--pretty', '-h', '--help')
            $candidates = @()
            foreach ($flag in $flags) {
                if ($flag -like "${wordToCompleteLower}*") {
                    $candidates += $flag
                }
            }
            return $candidates | ForEach-Object {
                [System.Management.Automation.CompletionText]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'completion' {
            $shells = @('bash', 'zsh', 'powershell')
            return $shells | Where-Object { $_ -like "${wordToCompleteLower}*" } | ForEach-Object {
                [System.Management.Automation.CompletionText]::new($_, $_, 'ParameterValue', $_)
            }
        }
        default {
            return $commands | Where-Object { $_ -like "${wordToCompleteLower}*" } | ForEach-Object {
                [System.Management.Automation.CompletionText]::new($_, $_, 'CommandName', $_)
            }
        }
    }
}
