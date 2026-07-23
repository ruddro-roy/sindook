package main

import (
	"fmt"
	"os"
)

const usageCompletion = `usage: sindook completion (bash | zsh | fish)

Print a shell completion script to stdout.

install:
  bash:  sindook completion bash >> ~/.bash_completion
  zsh:   sindook completion zsh > "${fpath[1]}/_sindook"
  fish:  sindook completion fish > ~/.config/fish/completions/sindook.fish
`

const bashCompletion = `_sindook() {
    local cur cmd
    cur="${COMP_WORDS[COMP_CWORD]}"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "keygen pubkey seal open verify inspect rewrap completion version help" -- "$cur"))
        return
    fi
    cmd="${COMP_WORDS[1]}"
    case "$cmd" in
        completion)
            COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")); return ;;
        help)
            COMPREPLY=($(compgen -W "keygen pubkey seal open verify inspect rewrap completion version" -- "$cur")); return ;;
    esac
    if [[ "$cur" == -* ]]; then
        local opts=""
        case "$cmd" in
            keygen)  opts="-o -p -passfile -f" ;;
            seal)    opts="-r -R -p -passfile -a -o -f" ;;
            open)    opts="-i -p -passfile -o -f" ;;
            verify)  opts="-i -p -passfile" ;;
            inspect) opts="-json" ;;
            rewrap)  opts="-i -p -passfile -r -R -new-passphrase -new-passfile -deep -o -f" ;;
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
        'pubkey:print the public key of an identity'
        'seal:encrypt to recipients and/or a passphrase'
        'open:decrypt with an identity or passphrase'
        'verify:confirm sealed files decrypt cleanly'
        'inspect:show sealed-file metadata'
        'rewrap:rotate recipients, passphrases, or the file key'
        'completion:print a shell completion script'
        'version:print version and build provenance'
        'help:show help for a command'
    )
    if (( CURRENT == 2 )); then
        _describe 'command' cmds
        return
    fi
    case "$words[2]" in
        completion) _values 'shell' bash zsh fish ;;
        help)       _values 'command' keygen pubkey seal open verify inspect rewrap completion version ;;
        *)          _files ;;
    esac
}
_sindook "$@"
`

const fishCompletion = `complete -c sindook -f -n '__fish_use_subcommand' -a keygen -d 'create an identity'
complete -c sindook -f -n '__fish_use_subcommand' -a pubkey -d 'print the public key of an identity'
complete -c sindook -f -n '__fish_use_subcommand' -a seal -d 'encrypt to recipients and/or a passphrase'
complete -c sindook -f -n '__fish_use_subcommand' -a open -d 'decrypt with an identity or passphrase'
complete -c sindook -f -n '__fish_use_subcommand' -a verify -d 'confirm sealed files decrypt cleanly'
complete -c sindook -f -n '__fish_use_subcommand' -a inspect -d 'show sealed-file metadata'
complete -c sindook -f -n '__fish_use_subcommand' -a rewrap -d 'rotate recipients, passphrases, or the file key'
complete -c sindook -f -n '__fish_use_subcommand' -a completion -d 'print a shell completion script'
complete -c sindook -f -n '__fish_use_subcommand' -a version -d 'print version and build provenance'
complete -c sindook -f -n '__fish_use_subcommand' -a help -d 'show help for a command'
complete -c sindook -f -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c sindook -f -n '__fish_seen_subcommand_from help' -a 'keygen pubkey seal open verify inspect rewrap completion version'
complete -c sindook -n '__fish_seen_subcommand_from seal open verify inspect rewrap pubkey' -F
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
	default:
		return fmt.Errorf("sindook: unknown shell %q, expected bash, zsh, or fish", args[0])
	}
	return nil
}
