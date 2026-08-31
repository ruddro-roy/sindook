package main

import (
	"fmt"
	"os"
)

const usageCompletion = `usage: sindook completion (bash | zsh | fish | powershell)

Print a shell completion script to stdout.

install:
  bash:  sindook completion bash >> ~/.bash_completion
  zsh:   sindook completion zsh > "${fpath[1]}/_sindook"
  fish:  sindook completion fish > ~/.config/fish/completions/sindook.fish
  pwsh:  sindook completion powershell | Add-Content $PROFILE
`

const bashCompletion = `_sindook() {
    local cur cmd
    cur="${COMP_WORDS[COMP_CWORD]}"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "keygen init pubkey contacts config paths seal open verify inspect rewrap rotate shred scan selftest doctor completion version help" -- "$cur"))
        return
    fi
    cmd="${COMP_WORDS[1]}"
    case "$cmd" in
        completion)
            COMPREPLY=($(compgen -W "bash zsh fish powershell" -- "$cur")); return ;;
        contacts)
            COMPREPLY=($(compgen -W "list add show remove group -json -f" -- "$cur")); return ;;
        config)
            COMPREPLY=($(compgen -W "list get set unset -json" -- "$cur")); return ;;
        scan)
            COMPREPLY=($(compgen -W "tls files -json -timeout" -- "$cur")); return ;;
        help)
            COMPREPLY=($(compgen -W "keygen init pubkey contacts config paths seal open verify inspect rewrap rotate shred scan selftest doctor completion version" -- "$cur")); return ;;
    esac
    if [[ "$cur" == -* ]]; then
        local opts=""
        case "$cmd" in
            keygen)  opts="-o -p -passfile -f" ;;
            init)    opts="-i -o -p -passfile -identity-passfile -f" ;;
            pubkey)  opts="-identity-passfile" ;;
            seal)    opts="-r -R -p -passfile -glob -a -z -o -f" ;;
            open)    opts="-i -p -passfile -identity-passfile -glob -o -f -z -max-decompressed" ;;
            verify)  opts="-i -p -passfile -identity-passfile -glob -jobs -json -z -max-decompressed -save -baseline" ;;
            inspect) opts="-json -glob" ;;
            paths)   opts="-json" ;;
			doctor)  opts="-json -check-version" ;;
			rewrap)  opts="-i -p -passfile -identity-passfile -r -R -new-passphrase -new-passfile -glob -deep -o -f" ;;
		rotate)  opts="-i -identity-passfile -to -deep -jobs -json -glob" ;;
			shred)   opts="-n -glob" ;;
        esac
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    else
        COMPREPLY=($(compgen -f -- "$cur"))
    fi
}
complete -o filenames -F _sindook sindook
`

const zshCompletion = `#compdef sindook
_sindook() {
    local -a cmds
    cmds=(
        'keygen:create an identity'
        'init:create or select the default identity'
        'pubkey:print the public key of an identity'
        'contacts:save and use named recipient public keys and groups'
        'config:inspect and change saved settings'
        'paths:show Sindook configuration locations'
        'seal:encrypt to recipients and/or a passphrase'
        'open:decrypt with an identity or passphrase'
        'verify:confirm sealed files decrypt cleanly'
        'inspect:show sealed-file metadata'
        'rewrap:rotate recipients, passphrases, or the file key'
        'rotate:retire an old identity across many sealed files'
        'shred:overwrite and delete regular plaintext files'
        'scan:audit TLS endpoints and local keys for weak crypto'
        'selftest:run a fast built-in cryptographic sanity check'
        'doctor:diagnose the local installation and configuration'
        'completion:print a shell completion script'
        'version:print version and build provenance'
        'help:show help for a command'
    )
    if (( CURRENT == 2 )); then
        _describe 'command' cmds
        return
    fi
    case "$words[2]" in
        completion) _values 'shell' bash zsh fish powershell ;;
        help)       _values 'command' keygen init pubkey contacts config paths seal open verify inspect rewrap rotate shred scan selftest doctor completion version ;;
        contacts)   _values 'subcommand' list add show remove group add-member remove-member -json -f ;;
        config)     _values 'subcommand' list get set unset -json ;;
        scan)       _values 'mode' tls files -json -timeout ;;
        *)          _files ;;
    esac
}
_sindook "$@"
`

const fishCompletion = `complete -c sindook -f -n '__fish_use_subcommand' -a keygen -d 'create an identity'
complete -c sindook -f -n '__fish_use_subcommand' -a init -d 'create or select the default identity'
complete -c sindook -f -n '__fish_use_subcommand' -a pubkey -d 'print the public key of an identity'
complete -c sindook -f -n '__fish_use_subcommand' -a contacts -d 'save and use named recipient public keys and groups'
complete -c sindook -f -n '__fish_use_subcommand' -a config -d 'inspect and change saved settings'
complete -c sindook -f -n '__fish_use_subcommand' -a paths -d 'show Sindook configuration locations'
complete -c sindook -f -n '__fish_use_subcommand' -a seal -d 'encrypt to recipients and/or a passphrase'
complete -c sindook -f -n '__fish_use_subcommand' -a open -d 'decrypt with an identity or passphrase'
complete -c sindook -f -n '__fish_use_subcommand' -a verify -d 'confirm sealed files decrypt cleanly'
complete -c sindook -f -n '__fish_use_subcommand' -a inspect -d 'show sealed-file metadata'
complete -c sindook -f -n '__fish_use_subcommand' -a rewrap -d 'rotate recipients, passphrases, or the file key'
complete -c sindook -f -n '__fish_use_subcommand' -a rotate -d 'retire an old identity across many sealed files'
complete -c sindook -f -n '__fish_use_subcommand' -a shred -d 'overwrite and delete regular plaintext files'
complete -c sindook -f -n '__fish_use_subcommand' -a scan -d 'audit TLS endpoints and local keys for weak crypto'
complete -c sindook -f -n '__fish_use_subcommand' -a selftest -d 'run a fast built-in cryptographic sanity check'
complete -c sindook -f -n '__fish_use_subcommand' -a doctor -d 'diagnose the local installation and configuration'
complete -c sindook -f -n '__fish_use_subcommand' -a completion -d 'print a shell completion script'
complete -c sindook -f -n '__fish_use_subcommand' -a version -d 'print version and build provenance'
complete -c sindook -f -n '__fish_use_subcommand' -a help -d 'show help for a command'
complete -c sindook -f -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish powershell'
complete -c sindook -f -n '__fish_seen_subcommand_from help' -a 'keygen init pubkey contacts config paths seal open verify inspect rewrap rotate shred scan selftest doctor completion version'
complete -c sindook -f -n '__fish_seen_subcommand_from scan' -a 'tls files'
complete -c sindook -n '__fish_seen_subcommand_from seal open verify inspect rewrap rotate shred pubkey scan' -F
`

const powershellCompletion = `$sindookCommands = @(
    [pscustomobject]@{ Name = 'keygen'; Description = 'create an identity' }
    [pscustomobject]@{ Name = 'init'; Description = 'create or select the default identity' }
    [pscustomobject]@{ Name = 'pubkey'; Description = 'print the public key of an identity' }
    [pscustomobject]@{ Name = 'contacts'; Description = 'save and use named recipient public keys and groups' }
    [pscustomobject]@{ Name = 'config'; Description = 'inspect and change saved settings' }
    [pscustomobject]@{ Name = 'paths'; Description = 'show Sindook configuration locations' }
    [pscustomobject]@{ Name = 'seal'; Description = 'encrypt to recipients and/or a passphrase' }
    [pscustomobject]@{ Name = 'open'; Description = 'decrypt with an identity or passphrase' }
    [pscustomobject]@{ Name = 'verify'; Description = 'confirm sealed files decrypt cleanly' }
    [pscustomobject]@{ Name = 'inspect'; Description = 'show sealed-file metadata' }
    [pscustomobject]@{ Name = 'rewrap'; Description = 'rotate recipients, passphrases, or the file key' }
    [pscustomobject]@{ Name = 'rotate'; Description = 'retire an old identity across many sealed files' }
    [pscustomobject]@{ Name = 'shred'; Description = 'overwrite and delete regular plaintext files' }
    [pscustomobject]@{ Name = 'scan'; Description = 'audit TLS endpoints and local keys for weak crypto' }
    [pscustomobject]@{ Name = 'selftest'; Description = 'run a fast built-in cryptographic sanity check' }
    [pscustomobject]@{ Name = 'doctor'; Description = 'diagnose the local installation and configuration' }
    [pscustomobject]@{ Name = 'completion'; Description = 'print a shell completion script' }
    [pscustomobject]@{ Name = 'version'; Description = 'print version and build provenance' }
    [pscustomobject]@{ Name = 'help'; Description = 'show help for a command' }
)

Register-ArgumentCompleter -Native -CommandName sindook -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $elements = @($commandAst.CommandElements | ForEach-Object { $_.Extent.Text })
    if ($elements.Count -le 2) {
        foreach ($candidate in $sindookCommands | Where-Object { $_.Name -like "$wordToComplete*" }) {
            [System.Management.Automation.CompletionResult]::new($candidate.Name, $candidate.Name, 'ParameterValue', $candidate.Description)
        }
        return
    }

    $command = $elements[1]
    $candidates = switch ($command) {
        'completion' { @('bash', 'zsh', 'fish', 'powershell') }
        'help' { @($sindookCommands.Name) }
        'contacts' { @('list', 'add', 'show', 'remove', 'group', 'add-member', 'remove-member', '-json', '-f') }
        'config' { @('list', 'get', 'set', 'unset', '-json') }
        'keygen' { @('-o', '-p', '-passfile', '-f') }
        'init' { @('-i', '-o', '-p', '-passfile', '-identity-passfile', '-f') }
        'pubkey' { @('-identity-passfile') }
        'seal' { @('-r', '-R', '-p', '-passfile', '-glob', '-a', '-z', '-o', '-f') }
        'open' { @('-i', '-p', '-passfile', '-identity-passfile', '-glob', '-o', '-f', '-z', '-max-decompressed') }
        'verify' { @('-i', '-p', '-passfile', '-identity-passfile', '-glob', '-jobs', '-json', '-z', '-max-decompressed', '-save', '-baseline') }
        'inspect' { @('-json', '-glob') }
        'paths' { @('-json') }
        'scan' { @('tls', 'files', '-json', '-timeout') }
        'doctor' { @('-json', '-check-version') }
        'rewrap' { @('-i', '-p', '-passfile', '-identity-passfile', '-r', '-R', '-new-passphrase', '-new-passfile', '-glob', '-deep', '-o', '-f') }
        'rotate' { @('-i', '-identity-passfile', '-to', '-deep', '-jobs', '-json', '-glob') }
        'shred' { @('-n', '-glob') }
        default { @() }
    }
    foreach ($candidate in $candidates | Where-Object { $_ -like "$wordToComplete*" }) {
        [System.Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
    }
}
`

func cmdCompletion(args []string) error {
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, usageCompletion)
		os.Exit(2)
	}
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	case "powershell", "pwsh":
		fmt.Print(powershellCompletion)
	default:
		return usagef("unknown shell %q, expected bash, zsh, fish, or powershell", args[0])
	}
	return nil
}
