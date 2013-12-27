%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc Utility Module
-module(rtmp_handshake_util).

-include("../include/rtmp_handshake_internal.hrl").

%%--------------------------------------------------------------------------------
%% Exported API
%%--------------------------------------------------------------------------------
-export([
         log/4
        ]).

%%--------------------------------------------------------------------------------
%% Exported Functions
%%--------------------------------------------------------------------------------
-spec log(module(), pos_integer(), [{atom(), term()}], #handshake_option{}) -> ok.
log(_Module,_Line,_Params,#handshake_option{enable_log = false}) -> ok;
log(Module, Line, Params, #handshake_option{enable_log = true}) ->
    error_logger:info_report([{module, Module}, {line, Line} | Params]);
log(Module, Line, Params, #handshake_option{enable_log = {true, Type}}) ->
    error_logger:info_report(Type, [{module, Module}, {line, Line} | Params]).
