# nftables_erlang_api

For now it support only tables,chains,and rules
No sets and maps.

It have two types of API:
	DIRECT API TO NFTABLES: This type of API use cmdline to create and apply nftables rule directly (example delete_table , add_rule ecc..).
	API ON LIST_.. OUTPUT: This type of API (there are still a few!) work on a map formatted with format_list() (example list_rule(), exist_rule)
