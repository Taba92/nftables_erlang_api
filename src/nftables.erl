% @doc TYPE SPECIFICATION:
% Add here the types specification

-module(nftables).
-export([format_list/1,is_error/1,format_error/1]).
-export([list_ruleset/0,list_ruleset/1,flush_ruleset/0]).
-export([add_table/1,add_table/2,delete_table/1,delete_table/2,list_tables/0,list_tables/1,
		list_table/1,list_table/2,list_table/3,flush_table/1,flush_table/2]).
-export([add_chain/2,add_chain/3,add_chain/4,create_chain/2,create_chain/3,create_chain/4,
		delete_chain/2,delete_chain/3,list_chain/2,list_chain/3,list_chain/4,list_chains/0,list_chains/1,
		flush_chain/2,flush_chain/3,rename_chain/3,rename_chain/4,set_policy/3,set_policy/4]).
-export([add_rule/3,add_rule/4,add_rule/5,insert_rule/3,insert_rule/4,insert_rule/5,
		delete_rule/3,delete_rule/4,list_rule/4,list_rule/5,replace_rule/4,replace_rule/5]).
-include("../include/nftables.hrl").

%%UTILITY API
% @spec format_list(NftListCommandOutput :: string()) -> map()
% @doc Format the output of the commands list _.... 
format_list(NftListOutput)->
	{ok,Tokens,_}=nft_lexer:string(NftListOutput),
	{ok,Data}=nft_parser:parse(Tokens),
	Data.

% @spec is_error(NftListCommandOutput :: string()) -> boolean()
% @doc Check if the output of a command is an error or valid output 
is_error([$<|_])->true;
is_error(_)->false.

% @spec format_error(NftErrOutput :: string()) -> {Error :: string(),Reason :: string()}
% @doc Given an error output, it extracts the type of error and the reason 
format_error(Err)->
	Pattern="<cmdline>:[0-9]+:[0-9]+-[0-9]+:.Error:.(.+)[:,].(.+)\n.+",
	{match,[Error,Reason]}=re:run(Err,Pattern,[{capture,all_but_first,list}]),
	{Error,Reason}.
%%FINE UTILITY API


%%RULESET API
% @spec list_ruleset() -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Get the entire ruleset of nftables configuration
list_ruleset()->
	Cmd=?CMD++"list ruleset",
	{?EXEC(Cmd),Cmd}.
% @spec list_ruleset({opts,Opts :: [atom()]}) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Get the entire ruleset of nftables configuration with given options
list_ruleset({opts,Opts})when is_list(Opts)->
	Cmd=?CMD++?STRINGOPTS(Opts)?WS"list ruleset",
	{?EXEC(Cmd),Cmd}.
% @spec flush_ruleset() -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Clear the entire ruleset of nftables configuration
flush_ruleset()->
	Cmd=?CMD++"flush ruleset",
	{?EXEC(Cmd),Cmd}.
%%%FINE RULESET API

%%TABLE API
% @equiv add_table(ip,TableName)
add_table(Table)->
	add_table(ip,Table).

% @spec add_table(Family :: atom(), TableName :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Add a table a new table in the nftables configuration with the given TableName name and of family Family
add_table(Family,Table)->
	Cmd=?CMD++"add table "++?STRING(Family)?WS?STRING(Table),
	{?EXEC(Cmd),Cmd}.

% @equiv delete_table(ip,TableName)
delete_table(Table)->
	delete_table(ip,Table).
% @spec delete_table(Family :: atom(), TableName :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Delete the table with the given TableName name and of family Family from the nftables configuration 
delete_table(Family,Table)->
	Cmd=?CMD++"delete table "++?STRING(Family)?WS?STRING(Table),
	{?EXEC(Cmd),Cmd}.

% @equiv list_table(ip,TableName)
list_table(Table)->
	list_table(ip,Table).
% @equiv list_table(ip,TableName,{opts,Opts})
% @doc If it is called as list_table(Family :: atom(), TableName :: atom())
% Show the configuration of table TableName of family Family
% and return {OutPutCommand :: string(), CommandExecuted :: string()}
list_table(Table,{opts,Opts})->
	list_table(ip,Table,{opts,Opts});
list_table(Family,Table)->
	Cmd=?CMD++"list table "++?STRING(Family)?WS?STRING(Table),
	{?EXEC(Cmd),Cmd}.
% @spec list_table(Family :: atom(), TableName :: atom(),{opts,Opts :: [atom()]}) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Show the configuration of table TableName of family Family with given options
list_table(Family,Table,{opts,Opts})->
	Cmd=?CMD++?STRINGOPTS(Opts)?WS"list table "++?STRING(Family)?WS?STRING(Table),
	{?EXEC(Cmd),Cmd}.

% @equiv list_tables(ip)
list_tables()->
	list_tables(ip).

% @spec list_tables(Family :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc List all tables of the given Family family 
list_tables(Family)->
	Cmd=?CMD++"list tables "++?STRING(Family),
	{?EXEC(Cmd),Cmd}.

% @equiv flush_table(ip,Table)
flush_table(Table)->
	flush_table(ip,Table).
% @spec flush_table(Family :: atom(), TableName :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Flush the table with TableName name of the given Family family
flush_table(Family,Table)->
	Cmd=?CMD++"flush table "++?STRING(Family)?WS?STRING(Table),
	{?EXEC(Cmd),Cmd}.
%%FINE TABLE API

%%CHAIN API
% @equiv add_chain(ip,Table,NameChain)
add_chain(Table,NameChain)->
	add_chain(ip,Table,NameChain).
% @equiv add_chain(ip,Table,NameChain,ChainSettings)
% @doc If is called as 	add_chain(Family :: atom(), TableName :: atom(), ChainName :: atom())
% it add a chain with ChainName name to the given table TableName of the family 
% and return {OutPutCommand :: string(), CommandExecuted :: string()}
add_chain(Table,NameChain,ChainSettings)when is_list(ChainSettings)->
	add_chain(ip,Table,NameChain,ChainSettings);
add_chain(Family,Table,NameChain)->
	Cmd=?CMD++"add chain "++?STRING(Family)?WS?STRING(Table)?WS ?STRING(NameChain),
	{?EXEC(Cmd),Cmd}.
% @spec add_chain(Family :: atom(), TableName :: atom(), ChainName :: atom(), ChainSettings :: ChainSettings) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% where 
% ChainSettings = [{type,Type :: atom()} | {hook,Hook :: atom() } | {priority,Prio :: atom()} | {policy, Policy :: atom()}] 	
% @doc Add a chain with ChainName name to the given table TableName of the family with given ChainSettings. {device,Device} and {policy,Policy} are optional instead others options are mandatory.		   
add_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{priority,Prio}])->
	add_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{priority,Prio},{policy,accept}]);
add_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{priority,Prio},{policy,Policy}])->
	Settings="'{type "++?STRING(Type)?WS"hook "++?STRING(Hook)?WS"priority "++integer_to_list(Prio)?WS";policy "++?STRING(Policy)++";}'",
	Cmd=?CMD++"add chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(NameChain)?WS Settings,
	{?EXEC(Cmd),Cmd};
add_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{device,Dev},{priority,Prio}])->
	add_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{device,Dev},{priority,Prio},{policy,accept}]);
add_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{device,Dev},{priority,Prio},{policy,Policy}])->
	Settings="'{type "++?STRING(Type)?WS"hook "++?STRING(Hook)?WS"device "++?STRING(Dev)?WS"priority "++integer_to_list(Prio)?WS";policy "++?STRING(Policy)++";}'",
	Cmd=?CMD++"add chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(NameChain)?WS Settings,
	{?EXEC(Cmd),Cmd}.

% @equiv create_chain(ip,Table,ChainName)
create_chain(Table,NameChain)->
	create_chain(ip,Table,NameChain).
% @equiv create_chain(ip,Table,ChainName,ChainSettings)
% @doc If is called as 	create_chain(Family :: atom(), TableName :: atom(), ChainName :: atom())
% it create a chain with ChainName name to the given table TableName of the family 
% and return {OutPutCommand :: string(), CommandExecuted :: string()}
create_chain(Table,NameChain,ChainSettings)when is_list(ChainSettings)->
	create_chain(ip,Table,NameChain,ChainSettings);
create_chain(Family,Table,NameChain)->
	Cmd=?CMD++"create chain "++?STRING(Family)?WS?STRING(Table)?WS ?STRING(NameChain),
	{?EXEC(Cmd),Cmd}.

% @spec create_chain(Family :: atom(), TableName :: atom(), ChainName :: atom(), ChainSettings :: ChainSettings) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% where 
% ChainSettings = [{type,Type :: atom()}|{hook,Hook :: atom() }|{priority,Prio :: atom()}|{policy, Policy :: atom()}] 	
% @doc  Create a chain in the table Table of family Family, with name NameChain and give ChainSettings. {device,Device} and {policy,Policy} are optional instead others options are mandatory.	
create_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{priority,Prio}])->
	create_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{priority,Prio},{policy,accept}]);
create_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{priority,Prio},{policy,Policy}])->
	Settings="'{type "++?STRING(Type)?WS"hook "++?STRING(Hook)?WS"priority "++integer_to_list(Prio)?WS";policy "++?STRING(Policy)++";}'",
	Cmd=?CMD++"create chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(NameChain)?WS Settings,
	{?EXEC(Cmd),Cmd};
create_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{device,Dev},{priority,Prio}])->
	create_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{device,Dev},{priority,Prio},{policy,accept}]);
create_chain(Family,Table,NameChain,[{type,Type},{hook,Hook},{device,Dev},{priority,Prio},{policy,Policy}])->
	Settings="'{type "++?STRING(Type)?WS"hook "++?STRING(Hook)?WS"device "++?STRING(Dev)?WS"priority "++integer_to_list(Prio)?WS";policy "++?STRING(Policy)++";}'",
	Cmd=?CMD++"create chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(NameChain)?WS Settings,
	{?EXEC(Cmd),Cmd}.

% @equiv delete_chain(ip,Table,ChainName)
delete_chain(Table,NameChain)->
	delete_chain(ip,Table,NameChain).
% @spec delete_chain(Family :: atom(), TableName :: atom(), ChainName :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Delete the chain with ChainName from the table Table of family Family
delete_chain(Family,Table,NameChain)->
	Cmd=?CMD++"delete chain "++?STRING(Family)?WS?STRING(Table)?WS ?STRING(NameChain),
	{?EXEC(Cmd),Cmd}.

% @equiv list_chain(ip,Table,NameChain)
list_chain(Table,NameChain)->
	list_chain(ip,Table,NameChain).
% @equiv list_chain(ip,Table,NameChain,{opts,Opts})
% @doc If it is called as list_chain(Family :: atom(), TableName :: atom(), ChainName :: atom())
% show the chain NameChain configuration in the table TableName of family Family
% and return {OutPutCommand :: string(), CommandExecuted :: string()}
list_chain(Table,NameChain,{opts,Opts})->
	list_chain(ip,Table,NameChain,{opts,Opts});
list_chain(Family,Table,NameChain)->
	Cmd=?CMD++"list chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(NameChain),
	{?EXEC(Cmd),Cmd}.
% @spec list_chain(Family :: atom(), TableName :: atom(), ChainName :: atom(), {opts,Opts :: [atom()]}) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Show the chain NameChain configuration in the table TableName of family Family, with given options
list_chain(Family,Table,NameChain,{opts,Opts})->
	Cmd=?CMD++?STRINGOPTS(Opts)?WS"list chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(NameChain),
	{?EXEC(Cmd),Cmd}.

% @equiv list_chains(ip)
list_chains()->
	list_chains(ip).
% @spec list_chains(Familiy :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Show the configuration of all chains of the given family
list_chains(Family)->
	Cmd=?CMD++"list chains "++?STRING(Family),
	{?EXEC(Cmd),Cmd}.

% @equiv flush_chain(ip,Table,NameChain)
flush_chain(Table,NameChain)->
	flush_chain(ip,Table,NameChain).
% @spec flush_chain(Family :: atom(), TableName ::atom(), ChainName :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Delete configurations of the chain ChainName in the table TableName of family Family
flush_chain(Family,Table,NameChain)->
	Cmd=?CMD++"flush chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(NameChain),
	{?EXEC(Cmd),Cmd}.
% @equiv rename_chain(ip,Table,OldName,NewName)
rename_chain(Table,OldName,NewName)->
	rename_chain(ip,Table,OldName,NewName).
% @spec rename_chain(Family :: atom(), TableName :: atom(), OldName :: atom(), NewName :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Change the name of the chain OldName to NewName in the table TableName of the family Family
rename_chain(Family,Table,OldName,NewName)->
	Cmd=?CMD++"rename chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(OldName)?WS?STRING(NewName),
	{?EXEC(Cmd),Cmd}.
% @equiv set_policy(ip,Table,Chain,Policy)
set_policy(Table,Chain,Policy)->
	set_policy(ip,Table,Chain,Policy).
% @spec set_policy(Family :: atom(), TableName :: atom(), ChainName :: atom(), Policy :: atom()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Set the policy Policy of the ChainName in the table TableName of the family Family
set_policy(Family,Table,Chain,Policy)->
	Cmd=?CMD++"chain "++?STRING(Family)?WS?STRING(Table)?WS?STRING(Chain)?WS"'{policy "++?STRING(Policy)++"}'",
	{?EXEC(Cmd),Cmd}.
%%FINE CHAIN API

%%RULE API
% @equiv add_rule(ip,Table,Chain,Statement)
add_rule(Table,Chain,Statement)->
	add_rule(ip,Table,Chain,Statement).
% @equiv add_rule(ip,Table,Chain,{pos,Pos},Statement)
% @doc If it is called as add_rule(Family :: atom(),TableName :: atom(),ChainName :: atom() ,Statement :: string())
% add the rule with statement Statement in the chain ChainName of the table TableName of the family Family
% and return {OutPutCommand :: string(), CommandExecuted :: string()}
% Note that Statement is the string statement of the rule from bash command nftables
add_rule(Table,Chain,{pos,Pos},Statement)->
	add_rule(ip,Table,Chain,{pos,Pos},Statement);
add_rule(Family,Table,Chain,Statement)->
	Cmd=?CMD++"add rule "++?STRING(Family)?WS?STRING(Table)?WS?STRING(Chain)?WS Statement,
	{?EXEC(Cmd),Cmd}.
% @spec add_rule(Family :: atom(),TableName :: atom(),ChainName :: atom() ,{pos,Pos :: integer()},Statement :: string()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Add the rule with statement Statement in the chain ChainName of the table TableName of the family Family at position Pos
% Note that Statement is the string statement of the rule from bash command nftables
add_rule(Family,Table,Chain,{pos,Pos},Statement)->
	Cmd=?CMD++"add rule "++?STRING(Family)?WS?STRING(Table)?WS?STRING(Chain)?WS"position "++integer_to_list(Pos)++" "++Statement,
	{?EXEC(Cmd),Cmd}.

% @equiv insert_rule(ip,Table,Chain,Statement)
insert_rule(Table,Chain,Statement)->
	insert_rule(ip,Table,Chain,Statement).
% @equiv insert_rule(ip,Table,Chain,{pos,Pos},Statement)
% @doc If it is called as insert_rule(Family :: atom(),TableName :: atom(),ChainName :: atom(),Statement :: string())
% prepend the rule with statement Statement in the chain ChainName of the table TableName of the family Family
% and return {OutPutCommand :: string(), CommandExecuted :: string()}
% Note that Statement is the string statement of the rule from bash command nftables
insert_rule(Table,Chain,{pos,Pos},Statement)->
	insert_rule(ip,Table,Chain,{pos,Pos},Statement);
insert_rule(Family,Table,Chain,Statement)->
	Cmd=?CMD++"insert rule "++?STRING(Family)?WS?STRING(Table)?WS?STRING(Chain)?WS Statement,
	{?EXEC(Cmd),Cmd}.
% @spec insert_rule(Family :: atom(),TableName :: atom(),ChainName :: atom(),{pos,Pos :: integer()},Statement :: string()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Prepend the rule with statement Statement in the chain ChainName of the table TableName of the family Family in the position Pos
% Note that Statement is the string statement of the rule from bash command nftables
insert_rule(Family,Table,Chain,{pos,Pos},Statement)->
	Cmd=?CMD++"insert rule "++?STRING(Family)?WS?STRING(Table)?WS?STRING(Chain)?WS"position "++integer_to_list(Pos)++" "++Statement,
	{?EXEC(Cmd),Cmd}.

% @equiv delete_rule(ip,Table,Chain,Handle)
delete_rule(Table,Chain,Handle)->
	delete_rule(ip,Table,Chain,Handle).
% @spec delete_rule(Family :: atom(),TableName :: atom(),ChainName :: atom(),Handle :: integer()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Delete the rule with handle Handle from the chain ChainName of the table TableName of the family Family
delete_rule(Family,Table,Chain,Handle)->
	Cmd=?CMD++"delete rule "++?STRING(Family)?WS?STRING(Table)?WS?STRING(Chain)?WS"handle "++integer_to_list(Handle),
	{?EXEC(Cmd),Cmd}.

% @equiv replace_rule(ip,Table,Chain,Handle,Statement)
replace_rule(Table,Chain,Handle,Statement)->
	replace_rule(ip,Table,Chain,Handle,Statement).
% @spec replace_rule(Family :: atom() ,TableName :: atom(),ChainName :: atom() ,Handle :: integer(),Statement :: string()) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% @doc Replace the current statement of the rule with handle Handle of the chain ChainName of the table TableName of the family Family
% with the statement Statement.
% Note that Statement is the string statement of the rule from bash command nftables
replace_rule(Family,Table,Chain,Handle,Statement)->
	Cmd=?CMD++"replace rule "++?STRING(Family)?WS?STRING(Table)?WS?STRING(Chain)?WS"handle "++integer_to_list(Handle)?WS Statement,
	{?EXEC(Cmd),Cmd}.

% @equiv list_rule(ip,Table,Chain,StatementOrHandle ,MapListOutput)
% @doc StatementOrHandle is an integer or a string
list_rule(Table,Chain,StatementOrHandle ,MapListOutput)->
	list_rule(ip,Table,Chain,StatementOrHandle,MapListOutput).
% @spec list_rule(Family :: atom(),TableName :: atom(),ChainName :: atom() ,Statement :: string(),MapListOutput :: MapFormat) -> {OutPutCommand :: string(), CommandExecuted :: string()}
% where MapFormat = format_list(NftOutput)
% @doc Given a statement or handle and format_list map, it return respectively the handle or the statement
list_rule(Family,Table,Chain,Statement,MapListOutput)when is_list(Statement)->
	#{chains:=Chains}=maps:get({?STRING(Table),?STRING(Family)},MapListOutput),
	case maps:get(?STRING(Chain),Chains,no_chain) of
		no_chain->no_chain;
		ChainData->
			Rules=maps:get(rules,ChainData),
			{_,Handle}=lists:keyfind(Statement,1,Rules),
			Handle
	end;
list_rule(Family,Table,Chain,Handle,MapListOutput)when is_integer(Handle)->
	#{chains:=Chains}=maps:get({?STRING(Table),?STRING(Family)},MapListOutput),
	case maps:get(?STRING(Chain),Chains,no_chain) of
		no_chain->no_chain;
		ChainData->
			Rules=maps:get(rules,ChainData),
			{Statement,_}=lists:keyfind(integer_to_list(Handle),2,Rules),
			Statement
	end.
%%FINE RULE API