%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc RTMP Handshake
-module(rtmp_handshake).

-include("../include/rtmp_handshake_internal.hrl").

%%--------------------------------------------------------------------------------
%% Exported API
%%--------------------------------------------------------------------------------
-export([
         server_handshake/2,
         client_handshake/2
        ]).

-export_type([
              handshake_method/0,
              option/0,
              rtmp_version/0,
              peer_version/0
             ]).

%%--------------------------------------------------------------------------------
%% Macros & Types
%%--------------------------------------------------------------------------------
-type option() :: {rtmp_version,  non_neg_integer()}
                | {peer_version,  binary()}
                | {timestamp,     non_neg_integer()}
                | {method,        handshake_method()}
                | {recv_timeout,  timeout()}
                | {enable_log,    false | true | {true, Type::any()}}.

-type handshake_method() :: plain.

-type rtmp_version() :: 0..255.
-type peer_version() :: binary().

%%--------------------------------------------------------------------------------
%% Exported Functions
%%--------------------------------------------------------------------------------
-spec client_handshake(gen_tcp:socket(), [option()]) -> ok | {error, Reason::term()}.
client_handshake(Socket, Options) ->
    case inet:getopts(Socket, [active]) of % TODO: binaryかどうかのチェックもいれる
        {error, Reason}        -> {error, Reason};
        {ok, [{active, true}]} -> {error, {unsupported, active_socket}};
        _                      ->
            {ok, Options2} = parse_handshake_option(Options),
            Module = get_handshake_module(Options2),
            try
                {ok, State} = Module:client_init(Options2),
                {ok, _} = do_client_handshake(Socket, Module, State, Options2),
                ok
            catch
                throw:{?MODULE, Response} -> Response
            end
    end.

-spec server_handshake(gen_tcp:socket(), [option()]) -> ok | {error, Reason::term()}.
server_handshake(Socket, Options) ->
    case inet:getopts(Socket, [active]) of
        {error, Reason}        -> {error, Reason};
        {ok, [{active, true}]} -> {error, {unsupported, active_socket}};
        _                      ->
            {ok, Options2} = parse_handshake_option(Options),
            Module = get_handshake_module(Options2),
            try
                {ok, State} = Module:server_init(Options2),
                {ok, _} = do_server_handshake(Socket, Module, State, Options2),
                ok
            catch
                throw:{?MODULE, Response} -> Response
            end
    end.
                
%%--------------------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------------------
-spec get_handshake_module(#handshake_option{}) -> module().
get_handshake_module(#handshake_option{method = plain}) -> rtmp_handshake_plain.

-spec parse_handshake_option([option()]) -> {ok, #handshake_option{}}.
parse_handshake_option(Options) ->
    Opt = #handshake_option{
             rtmp_version = proplists:get_value(rtmp_version, Options, 3),
             peer_version = proplists:get_value(peer_version, Options, <<0, 0, 0, 0>>),
             timestamp    = proplists:get_value(timestamp, Options, 0),
             method       = proplists:get_value(method, Options, plain),
             recv_timeout = proplists:get_value(recv_timeout, Options, 5000),
             enable_log   = proplists:get_value(enable_log, Options, false)
            },
    {ok, Opt}.

-spec do_client_handshake(gen_tcp:socket(), module(), term(), #handshake_option{}) -> ok | {error, Reason::term()}.
do_client_handshake(Socket, Module, State0, Options) ->
    #handshake_option{method = Method} = Options,

    %% c0
    {ok, RequestRtmpVersion, State1} = check(Module:c0(State0, Options)),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, c0}, {rtmp_version, RequestRtmpVersion}], Options),
    ok = send_0(Socket, RequestRtmpVersion, Options),
        
    %% c1
    {ok, C1Packet, State2} = check(Module:c1(State1, Options)),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, c1}, {packet, C1Packet}], Options),
    ok = send_1(Socket, C1Packet, Options),
    
    %% s0,s1
    ServerRtmpVersion = recv_0(Socket, Options),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, s0}, {rtmp_version, ServerRtmpVersion}], Options),
    S1Packet = recv_1(Socket, Options),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, s1}, {packet, S1Packet}], Options),
        
    %% c2,s2
    {ok, C2Packet, State3} = check(Module:c2(ServerRtmpVersion, S1Packet, State2, Options)),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, c2}, {packet, C2Packet}], Options),
    ok = send_2(Socket, C2Packet, Options),
    S2Packet = recv_2(Socket, Options),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, s2}, {packet, S2Packet}], Options),
    
    check(Module:client_finish(S2Packet, State3, Options)).

-spec do_server_handshake(gen_tcp:socket(), module(), term(), #handshake_option{}) -> ok | {error, Reason::term()}.
do_server_handshake(Socket, Module, State0, Options) ->
    #handshake_option{method = Method} = Options,

    %% c0,s0
    RequiredRtmpVersion = recv_0(Socket, Options),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, c0}, {rtmp_version, RequiredRtmpVersion}], Options),
    {ok, ServerRtmpVersion, State1} = check(Module:s0(RequiredRtmpVersion, State0, Options)),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, s0}, {rtmp_version, ServerRtmpVersion}], Options),
    ok = send_0(Socket, ServerRtmpVersion, Options),

    %% c1,s1
    C1Packet = recv_1(Socket, Options),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, c1}, {packet, C1Packet}], Options),
    {ok, S1Packet, State2} = check(Module:s1(C1Packet, State1, Options)),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, s1}, {packet, S1Packet}], Options),
    ok = send_1(Socket, S1Packet, Options),

    %% s2,c2
    {ok, S2Packet, State3} = check(Module:s2(State2, Options)),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, s2}, {packet, S2Packet}], Options),
    ok = send_2(Socket, S2Packet, Options),
    C2Packet = recv_1(Socket, Options),
    ok = log(?MODULE, ?LINE, [{method, Method}, {phase, c2}, {packet, C2Packet}], Options),

    check(Module:server_finish(C2Packet, State3, Options)).
    
-spec check(Result) -> OkValue when
      Result  :: {error, Reason::term()} | OkValue,
      OkValue :: term().
check({error, Reason}) -> throw({?MODULE, {error, Reason}});
check(Value)           -> Value.

-spec recv_0(gen_tcp:socket(), #handshake_option{}) -> RtmpVersion::rtmp_version().
recv_0(Socket, Options) -> 
    {ok, <<RtmpVersion:8>>} = check(gen_tcp:recv(Socket, 1, Options#handshake_option.recv_timeout)),
    RtmpVersion.

-spec recv_1(gen_tcp:socket(), #handshake_option{}) -> binary().
recv_1(Socket, Options) ->
    {ok, Packet} = check(gen_tcp:recv(Socket, ?HANDSHAKE_PACKET_SIZE, Options#handshake_option.recv_timeout)),
    Packet.

-spec recv_2(gen_tcp:socket(), #handshake_option{}) -> binary().
recv_2(Socket, Options) ->
    {ok, Packet} = check(gen_tcp:recv(Socket, ?HANDSHAKE_PACKET_SIZE, Options#handshake_option.recv_timeout)),
    Packet.

-spec send_0(gen_tcp:socket(), rtmp_version(), #handshake_option{}) -> ok.
send_0(Socket, RtmpVersion, _Options) ->
    check(gen_tcp:send(Socket, <<RtmpVersion>>)).

-spec send_1(gen_tcp:socket(), binary(), #handshake_option{}) -> ok.
send_1(Socket, Packet, _Options) ->
    check(gen_tcp:send(Socket, Packet)).

-spec send_2(gen_tcp:socket(), binary(), #handshake_option{}) -> ok.
send_2(Socket, Packet, _Options) ->
    check(gen_tcp:send(Socket, Packet)).

-spec log(module(), pos_integer(), [{atom(), term()}], #handshake_option{}) -> ok.
log(_Module,_Line,_Params,#handshake_option{enable_log = false}) -> ok;
log(Module, Line, Params, #handshake_option{enable_log = true}) ->
    error_logger:info_report([{module, Module}, {line, Line} | Params]);
log(Module, Line, Params, #handshake_option{enable_log = {true, Type}}) ->
    error_logger:info_report(Type, [{module, Module}, {line, Line} | Params]).
