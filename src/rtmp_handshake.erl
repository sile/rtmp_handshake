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
              rtmp_version/0,
              application_version/0,
              milliseconds/0,
              option/0,
              handshake_result/0,

              validation_method/0
             ]).

%%--------------------------------------------------------------------------------
%% Macros & Types
%%--------------------------------------------------------------------------------
-type option() :: {rtmp_version, rtmp_version()}
                | {app_version,  application_version()}
                | {timestamp,    milliseconds()}
                | {recv_timeout, timeout()}
                | {enable_log,   false | true | {true, Type::any()}}.

-type rtmp_version()        :: 0..255.
-type application_version() :: {0..255, 0..255, 0..255, 0..255}.
-type milliseconds()        :: non_neg_integer().

-type handshake_result() :: [{rtmp_version,       rtmp_version()} |
                             {server_app_version, application_version()} |
                             {client_app_version, application_version()} |
                             {server_timestamp,   milliseconds()} |
                             {client_timestamp,   milliseconds()} |
                             {validation_method,  validation_method()} |
                             {valid,              boolean()}].

-type validation_method() :: none | digest_version1 | digest_version2.

%%--------------------------------------------------------------------------------
%% Exported Functions
%%--------------------------------------------------------------------------------
-spec client_handshake(inet:socket(), [option()]) -> {ok, handshake_result()} | {error, Reason::term()}.
client_handshake(Socket, Options) ->
    case check_socket(Socket) of
        {error, Reason} -> {error, Reason};
        ok              ->
            {ok, Options2} = parse_handshake_option(Options ++ [{app_version, ?CLIENT_DEFAULT_APP_VERSION}]),
            try
                do_client_handshake(Socket, Options2)
            catch
                throw:{?MODULE, Response} -> Response
            end
    end.

-spec server_handshake(inet:socket(), [option()]) -> ok | {error, Reason::term()}.
server_handshake(Socket, Options) ->
    case check_socket(Socket) of
        {error, Reason} -> {error, Reason};
        ok              ->
            {ok, Options2} = parse_handshake_option(Options ++ [{app_version, ?SERVER_DEFAULT_APP_VERSION}]),
            try
                do_server_handshake(Socket, Options2)
            catch
                throw:{?MODULE, Response} -> Response
            end
    end.

%%--------------------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------------------
-spec parse_handshake_option([option()]) -> {ok, #handshake_option{}}.
parse_handshake_option(Options) ->
    Opt = #handshake_option{
             rtmp_version = proplists:get_value(rtmp_version, Options, 3),
             app_version  = proplists:get_value(app_version,  Options, {0, 0, 0, 0}),
             timestamp    = proplists:get_value(timestamp,    Options, 0),
             recv_timeout = proplists:get_value(recv_timeout, Options, 5000),
             enable_log   = proplists:get_value(enable_log,   Options, false)
            },
    {ok, Opt}.

-spec do_client_handshake(inet:socket(), #handshake_option{}) -> {ok, handshake_result()}.
do_client_handshake(Socket, Options) ->
    #handshake_option{rtmp_version = ClientRtmpVersion, app_version = ClientVersion, timestamp = ClientTimestamp} = Options,

    %% c0,c1
    ClientRtmpVersion = Options#handshake_option.rtmp_version,
    ok = ?LOG([{phase, c0}, {client_rtmp_version, ClientRtmpVersion}], Options),
    ok = send_0(Socket, ClientRtmpVersion, Options),

    {Module, ValidationMethod} =
        if
            ClientVersion < {9,0,124,0}  -> {rtmp_handshake_plain, none};
            ClientVersion < {10,0,32,18} -> {rtmp_handshake_digest, digest_version1};
            true                         -> {rtmp_handshake_digest, digest_version2}
        end,
    {C1Packet, State0} = Module:c1(ValidationMethod, Options),
    ok = ?LOG([{phase, c1}, {validation, ValidationMethod}, {client_version, ClientVersion}, {client_timestamp, ClientTimestamp}, {packet, C1Packet}], Options),
    ok = send_1(Socket, C1Packet, Options),

    %% s0,s1
    ServerRtmpVersion = recv_0(Socket, Options),
    ok = ?LOG([{phase, s0}, {server_rtmp_version, ServerRtmpVersion}], Options),
    ok = check(case ServerRtmpVersion =:= ClientRtmpVersion of
                   false -> {error, {unsupported_rtmp_version, ServerRtmpVersion}};
                   true  -> ok
               end),
    <<ServerTimestamp:32, V1, V2, V3, V4, _/binary>> = S1Packet = recv_1(Socket, Options),
    ServerVersion = {V1, V2, V3, V4},
    ok = ?LOG([{phase, s1}, {server_version, ServerVersion}, {server_timestamp, ServerTimestamp}, {packet, S1Packet}], Options),

    %% c2,s2
    {Valid1, C2Packet, State1} = Module:c2(S1Packet, State0, Options),
    ok = ?LOG([{phase, c2}, {packet, C2Packet}], Options),
    ok = send_2(Socket, C2Packet, Options),
    S2Packet = recv_2(Socket, Options),
    ok = ?LOG([{phase, s2}, {packet, S2Packet}], Options),

    Valid2 = Module:client_finish(S2Packet, State1, Options),
    {ok, [{rtmp_version,       ServerRtmpVersion},
          {server_app_version, ServerVersion},
          {client_app_version, ClientVersion},
          {server_timestmap,   ServerTimestamp},
          {client_timestamp,   ClientTimestamp},
          {validation_method,  ValidationMethod},
          {valid,              Valid1 andalso Valid2}]}.

-spec do_server_handshake(inet:socket(), #handshake_option{}) -> {ok, handshake_result()}.
do_server_handshake(Socket, Options) ->
    #handshake_option{rtmp_version = ServerRtmpVersion, app_version = ServerVersion, timestamp = ServerTimestamp} = Options,

    %% c0,s0
    ClientRtmpVersion = recv_0(Socket, Options),
    ok = ?LOG([{phase, c0}, {client_rtmp_version, ClientRtmpVersion}], Options),
    ok = check(case ClientRtmpVersion >= ServerRtmpVersion of
                   false -> {error, {unsupported_rtmp_version, ClientRtmpVersion}};
                   true  -> ok
               end),
    ok = ?LOG([{phase, s0}, {server_rtmp_version, ServerRtmpVersion}], Options),
    ok = send_0(Socket, ServerRtmpVersion, Options),

    %% c1,s1
    <<ClientTimestamp:32, V1, V2, V3, V4, _/binary>> = C1Packet = recv_1(Socket, Options),
    ClientVersion = {V1, V2, V3, V4},
    ok = ?LOG([{phase, c1}, {client_timestamp, ClientTimestamp}, {client_version, ClientVersion}, {packet, C1Packet}], Options),

    {Module, ValidationMethod} =
        if
            ClientVersion < {9,0,124,0}  -> {rtmp_handshake_plain, none};
            ClientVersion < {10,0,32,18} -> {rtmp_handshake_digest, digest_version1};
            true                         -> {rtmp_handshake_digest, digest_version2}
        end,
    {Valid1, S1Packet, State0} = Module:s1(ValidationMethod, C1Packet, Options),
    ok = ?LOG([{phase, s1}, {packet, S1Packet}], Options),
    ok = send_1(Socket, S1Packet, Options),

    %% s2,c2
    {S2Packet, State1} = Module:s2(State0, Options),
    ok = ?LOG([{phase, s2}, {packet, S2Packet}], Options),
    ok = send_2(Socket, S2Packet, Options),
    C2Packet = recv_1(Socket, Options),
    ok = ?LOG([{phase, c2}, {packet, C2Packet}], Options),

    Valid2 = Module:server_finish(C2Packet, State1, Options),
    {ok, [{rtmp_version,       ServerRtmpVersion},
          {server_app_version, ServerVersion},
          {client_app_version, ClientVersion},
          {server_timestmap,   ServerTimestamp},
          {client_timestamp,   ClientTimestamp},
          {validation_method,  ValidationMethod},
          {valid,              Valid1 andalso Valid2}]}.

-spec check(Result) -> OkValue when
      Result  :: {error, Reason::term()} | OkValue,
      OkValue :: term().
check({error, Reason}) -> throw({?MODULE, {error, Reason}});
check(Value)           -> Value.

-spec recv_0(inet:socket(), #handshake_option{}) -> RtmpVersion::rtmp_version().
recv_0(Socket, Options) ->
    {ok, Packet} = check(gen_tcp:recv(Socket, 1, Options#handshake_option.recv_timeout)),
    <<RtmpVersion:8>> = iolist_to_binary(Packet),
    RtmpVersion.

-spec recv_1(inet:socket(), #handshake_option{}) -> binary().
recv_1(Socket, Options) ->
    {ok, Packet} = check(gen_tcp:recv(Socket, ?HANDSHAKE_PACKET_SIZE, Options#handshake_option.recv_timeout)),
    iolist_to_binary(Packet).

-spec recv_2(inet:socket(), #handshake_option{}) -> binary().
recv_2(Socket, Options) ->
    {ok, Packet} = check(gen_tcp:recv(Socket, ?HANDSHAKE_PACKET_SIZE, Options#handshake_option.recv_timeout)),
    iolist_to_binary(Packet).

-spec send_0(inet:socket(), rtmp_version(), #handshake_option{}) -> ok.
send_0(Socket, RtmpVersion, _Options) ->
    check(gen_tcp:send(Socket, <<RtmpVersion>>)).

-spec send_1(inet:socket(), binary(), #handshake_option{}) -> ok.
send_1(Socket, Packet, _Options) ->
    check(gen_tcp:send(Socket, Packet)).

-spec send_2(inet:socket(), binary(), #handshake_option{}) -> ok.
send_2(Socket, Packet, _Options) ->
    check(gen_tcp:send(Socket, Packet)).

-spec check_socket(inet:socket()) -> ok | {error, Reason::term()}.
check_socket(Socket) ->
    case inet:getopts(Socket, [active]) of
        {error, Reason}        -> {error, Reason};
        {ok, [{active, true}]} -> {error, {unsupported, active_socket}};
        _                      -> ok
    end.
