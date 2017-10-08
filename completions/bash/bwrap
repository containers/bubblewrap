#!/bin/bash
#
# bash completion file for bubblewrap commands
#

_bwrap() {
    local cur prev words cword
    _init_completion || return

	local boolean_options="
		--as-pid-1
		--help
		--new-session
		--unshare-cgroup
		--unshare-cgroup-try
		--unshare-user
		--unshare-user-try
		--unshare-all
		--unshare-ipc
		--unshare-net
		--unshare-pid
		--unshare-uts
		--version
	"

	local options_with_args="
		$boolean_optons
		--args
		--bind
		--bind-data
		--block-fd
		--cap-add
		--cap-drop
		--chdir
		--dev
		--dev-bind
		--die-with-parent
		--dir
		--exec-label
		--file
		--file-label
		--gid
		--hostname
		--info-fd
		--lock-file
		--proc
		--remount-ro
		--ro-bind
		--seccomp
		--setenv
		--symlink
		--sync-fd
		--uid
		--unsetenv
		--userns-block-fd
	"

	if [[ "$cur" == -* ]]; then
	    COMPREPLY=( $( compgen -W "$boolean_options $options_with_args" -- "$cur" ) )
	fi

	return 0
}
complete -F _bwrap bwrap
