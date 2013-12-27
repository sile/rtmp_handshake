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
              peer_version/0,
              handshake_result/0
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

-type handshake_method() :: plain | digest.

-type rtmp_version() :: 0..255.
-type peer_version() :: binary().

-type handshake_result() :: [{rtmp_version, rtmp_version()} |
                             {timestamp, non_neg_integer()} |
                             {version, peer_version()}].

%%--------------------------------------------------------------------------------
%% Exported Functions
%%--------------------------------------------------------------------------------
-spec client_handshake(gen_tcp:socket(), [option()]) -> {ok, handshake_result()} | {error, Reason::term()}.
client_handshake(Socket, Options) ->
    case check_socket(Socket) of
        {error, Reason} -> {error, Reason};
        ok              ->
            {ok, Options2} = parse_handshake_option(Options),
            try
                do_client_handshake(Socket, Options2)
            catch
                throw:{?MODULE, Response} -> Response
            end
    end.

-spec server_handshake(gen_tcp:socket(), [option()]) -> ok | {error, Reason::term()}.
server_handshake(Socket, Options) ->
    case check_socket(Socket) of
        {error, Reason} -> {error, Reason};
        _               ->
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
get_handshake_module(#handshake_option{method = plain})  -> rtmp_handshake_plain;
get_handshake_module(#handshake_option{method = digest}) -> rtmp_handshake_digest.

-spec parse_handshake_option([option()]) -> {ok, #handshake_option{}}.
parse_handshake_option(Options) ->
    Opt = #handshake_option{
             rtmp_version = proplists:get_value(rtmp_version, Options, 3),
             peer_version = proplists:get_value(peer_version, Options, <<0, 0, 0, 0>>), % 5.0.3.1 for server, 9.0.124.2 for client
             timestamp    = proplists:get_value(timestamp, Options, 0),
             method       = proplists:get_value(method, Options, plain),
             recv_timeout = proplists:get_value(recv_timeout, Options, 5000),
             enable_log   = proplists:get_value(enable_log, Options, false)
            },
    {ok, Opt}.

-spec do_client_handshake(gen_tcp:socket(), #handshake_option{}) -> {ok, handshake_result()} | {error, Reason::term()}.
do_client_handshake(Socket, Options) ->
    #handshake_option{rtmp_version = ClientRtmpVersion, peer_version = ClientVersion, timestamp = ClientTimestamp} = Options,

    %% c0,c1
    ClientRtmpVersion = Options#handshake_option.rtmp_version,
    ok = ?LOG([{phase, c0}, {client_rtmp_version, ClientRtmpVersion}], Options),
    ok = send_0(Socket, ClientRtmpVersion, Options),

    {Module, ModuleVersion, AuthentificationMethod} = % TODO: delete: ModuleVersion
        if
            ClientVersion < <<9,0,124,0>>  -> {rtmp_handshake_plain,  none,     none};
            ClientVersion < <<10,0,32,18>> -> {rtmp_handshake_digest, version1, digest_version1};
            true                           -> {rtmp_handshake_digest, version2, digest_version2}
        end,
    {ok, C1Packet, State0} = check(Module:c1(ModuleVersion, Options)),
    ok = ?LOG([{phase, c1}, {authentification, AuthentificationMethod}, {client_version, ClientVersion}, {client_timestamp, ClientTimestamp}, {packet, C1Packet}], Options),
    ok = send_1(Socket, C1Packet, Options),

    %% s0,s1
    ServerRtmpVersion = recv_0(Socket, Options),        
    ok = ?LOG([{phase, s0}, {server_rtmp_version, ServerRtmpVersion}], Options),
    ok = check(case ServerRtmpVersion =:= ClientRtmpVersion of
                   false -> {error, {unsupported_rtmp_version, ServerRtmpVersion}};
                   true  -> ok
               end),
    <<ServerTimestamp:32, ServerVersion:4/binary, _/binary>> = S1Packet = recv_1(Socket, Options),
    ok = ?LOG([{phase, s1}, {server_version, ServerVersion}, {server_timestamp, ServerTimestamp}, {packet, S1Packet}], Options),
        
    %% c2,s2
    {ok, C2Packet, State1} = check(Module:c2(S1Packet, State0, Options)),
    ok = ?LOG([{phase, c2}, {packet, C2Packet}], Options),
    ok = send_2(Socket, C2Packet, Options),
    S2Packet = recv_2(Socket, Options),
    ok = ?LOG([{phase, s2}, {packet, S2Packet}], Options),
    
    ok = check(Module:client_finish(S2Packet, State1, Options)),
    {ok, [{rtmp_version, ServerRtmpVersion},
          {timestmap,    ServerTimestamp},
          {version,      ServerVersion}]}.

-spec do_server_handshake(gen_tcp:socket(), module(), term(), #handshake_option{}) -> ok | {error, Reason::term()}.
do_server_handshake(Socket, Module, State0, Options) ->
    #handshake_option{method = Method} = Options,

    %% c0,s0
    RequiredRtmpVersion = recv_0(Socket, Options),
    ok = rtmp_handshake_util:log(?MODULE, ?LINE, [{method, Method}, {phase, c0}, {rtmp_version, RequiredRtmpVersion}], Options),
    {ok, ServerRtmpVersion, State1} = check(Module:s0(RequiredRtmpVersion, State0, Options)),
    ok = rtmp_handshake_util:log(?MODULE, ?LINE, [{method, Method}, {phase, s0}, {rtmp_version, ServerRtmpVersion}], Options),
    ok = send_0(Socket, ServerRtmpVersion, Options),

    %% c1,s1
    C1Packet = recv_1(Socket, Options),
    ok = rtmp_handshake_util:log(?MODULE, ?LINE, [{method, Method}, {phase, c1}, {packet, C1Packet}], Options),
    {ok, S1Packet, State2} = check(Module:s1(C1Packet, State1, Options)),
    ok = rtmp_handshake_util:log(?MODULE, ?LINE, [{method, Method}, {phase, s1}, {packet, S1Packet}], Options),
    ok = send_1(Socket, S1Packet, Options),

    %% s2,c2
    {ok, S2Packet, State3} = check(Module:s2(State2, Options)),
    ok = rtmp_handshake_util:log(?MODULE, ?LINE, [{method, Method}, {phase, s2}, {packet, S2Packet}], Options),
    ok = send_2(Socket, S2Packet, Options),
    C2Packet = recv_1(Socket, Options),
    ok = rtmp_handshake_util:log(?MODULE, ?LINE, [{method, Method}, {phase, c2}, {packet, C2Packet}], Options),

    check(Module:server_finish(C2Packet, State3, Options)).
    
-spec check(Result) -> OkValue when
      Result  :: {error, Reason::term()} | OkValue,
      OkValue :: term().
check({error, Reason}) -> throw({?MODULE, {error, Reason}});
check(Value)           -> Value.

-spec recv_0(gen_tcp:socket(), #handshake_option{}) -> RtmpVersion::rtmp_version().
recv_0(Socket, Options) -> 
    {ok, Packet} = check(gen_tcp:recv(Socket, 1, Options#handshake_option.recv_timeout)),
    <<RtmpVersion:8>> = iolist_to_binary(Packet),
    RtmpVersion.

-spec recv_1(gen_tcp:socket(), #handshake_option{}) -> binary().
recv_1(Socket, Options) ->
    {ok, Packet} = check(gen_tcp:recv(Socket, ?HANDSHAKE_PACKET_SIZE, Options#handshake_option.recv_timeout)),
    iolist_to_binary(Packet).

-spec recv_2(gen_tcp:socket(), #handshake_option{}) -> binary().
recv_2(Socket, Options) ->
    {ok, Packet} = check(gen_tcp:recv(Socket, ?HANDSHAKE_PACKET_SIZE, Options#handshake_option.recv_timeout)),
    iolist_to_binary(Packet).

-spec send_0(gen_tcp:socket(), rtmp_version(), #handshake_option{}) -> ok.
send_0(Socket, RtmpVersion, _Options) ->
    check(gen_tcp:send(Socket, <<RtmpVersion>>)).

-spec send_1(gen_tcp:socket(), binary(), #handshake_option{}) -> ok.
send_1(Socket, Packet, _Options) ->
    check(gen_tcp:send(Socket, Packet)).

-spec send_2(gen_tcp:socket(), binary(), #handshake_option{}) -> ok.
send_2(Socket, Packet, _Options) ->
    check(gen_tcp:send(Socket, Packet)).

-spec check_socket(gen_tcp:socket()) -> ok | {error, Reason::term()}.
check_socket(Socket) ->
    case inet:getopts(Socket, [active]) of
        {error, Reason}        -> {error, Reason};
        {ok, [{active, true}]} -> {error, {unsupported, active_socket}};
        _                      -> ok
    end.
