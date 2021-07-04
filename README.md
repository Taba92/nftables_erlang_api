# nftables_erlang_api

Erlang API to nftables

API : [nftables_api](https://github.com/Taba92/nftables_erlang_api/tree/main/doc/nftables.html)
See edoc folder for more documentation.

COMPILATION: rebar3 compile.

USAGE: sudo rebar3 shell.

For now only the basic management of nftables is supported, for example add rules, create tables, delete chains ecc.

NB: For the APIs that use options before the command, ***every*** option passed must be in the form without the first dash in front.
example: option *-a* must be atom *a*
		option *--handle* must be atom *-handle*

FUTURE WORKS:
	1) Streamline and improve existing API and its usage.
	2) Improve documentation with types specification.
	3) Cover nftables entirely.
