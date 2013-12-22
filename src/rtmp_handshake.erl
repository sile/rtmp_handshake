%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc RTMP Handshake
-module(rtmp_handshake).

-include("../include/rtmp_handshake_internal.hrl").

%%--------------------------------------------------------------------------------
%% Exported API
%%--------------------------------------------------------------------------------
-export([
%         server_handshake/2,
         client_handshake/2
        ]).

-export_type([
              handshake_method/0,
              option/0
             ]).

%%--------------------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------------------
-type option() :: {rtmp_version,  non_neg_integer()}
                | {peer_version,  binary()}
                | {timestamp,     non_neg_integer()}
                | {method,        handshake_method()}
                | {recv_timeout,  timeout()}
                | {enable_log,    false | true | {true, Type::any()}}.

-type handshake_method() :: plain.

%%--------------------------------------------------------------------------------
%% Exported Functions
%%--------------------------------------------------------------------------------
-spec client_handshake(gen_tcp:socket(), [option()]) -> ok | {error, Reason::term()}.
client_handshake(Socket, Options) ->
    case inet:getopts(Socket, [active]) of
        {error, Reason}        -> {error, Reason};
        {ok, [{active, true}]} -> {error, {unsupported, active_socket}};
        _                      ->
            case parse_handshake_option(Options) of
                {error, Reason} -> {error, Reason};
                {ok, Options2}  ->
                    Module = get_handshake_module(Options2),
                    client_handshake_impl(Socket, Module, Options2)
            end
    end.
                
%%--------------------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------------------
-spec get_handshake_module(#handshake_option{}) -> module().
get_handshake_module(#handshake_option{method = plain}) -> rtmp_handshake_plain.

-spec client_handshake_impl(gen_tcp:socket(), module(), #handshake_option{}) -> ok | {error, Reason::term()}.
client_handshake_impl(Socket, Module, Options) ->
    todo.

