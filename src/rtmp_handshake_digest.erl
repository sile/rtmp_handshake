%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc Plain RTMP Handshake Implementation
-module(rtmp_handshake_digest).

-include("../include/rtmp_handshake_internal.hrl").

-behaviour(rtmp_handshake_interface).

%%--------------------------------------------------------------------------------
%% 'rtmp_handshake_interface' Callback API
%%--------------------------------------------------------------------------------
-export([c1/2, c2/3, client_finish/3]).
-export([server_init/1, s0/3, s1/3, s2/2, server_finish/3]).

%%--------------------------------------------------------------------------------
%% Macros & Records & Types
%%--------------------------------------------------------------------------------
-define(GENUINE_FMS_KEY,
        <<"Genuine Adobe Flash Media Server 001",
          16#f0,16#ee,16#c2,16#4a,16#80,16#68,16#be,16#e8,16#2e,16#00,16#d0,16#d1,16#02,16#9e,16#7e,16#57,
          16#6e,16#ec,16#5d,16#2d,16#29,16#80,16#6f,16#ab,16#93,16#b8,16#e6,16#36,16#cf,16#eb,16#31,16#ae>>).
          
-define(GENUINE_FP_KEY,
        <<"Genuine Adobe Flash Player 001",
          16#F0,16#EE,16#C2,16#4A,16#80,16#68,16#BE,16#E8,16#2E,16#00,16#D0,16#D1,16#02,16#9E,16#7E,16#57,
          16#6E,16#EC,16#5D,16#2D,16#29,16#80,16#6F,16#AB,16#93,16#B8,16#E6,16#36,16#CF,16#EB,16#31,16#AE>>).

-define(DIGEST_SIZE, 32).

-record(client_state,
        {
          scheme_version :: scheme_version(),
          digest         :: binary()
        }).

-record(server_state,
        {
          c1_packet      :: undefined | binary(),
          scheme_version :: undefined | scheme_version()
        }).

-type scheme_version() :: version1  % Flash before 10.0.32.18
                        | version2. % Flash after  10.0.32.18

%%--------------------------------------------------------------------------------
%% 'rtmp_handshake_interface' Callback Functions
%%--------------------------------------------------------------------------------
%% @hidden
c1(SchemeVersion, Options) ->
    #handshake_option{timestamp = Timestamp, peer_version = ClientVersion} = Options,
    Bytes = <<Timestamp:32, ClientVersion:4/binary, (crypto:rand_bytes(?HANDSHAKE_PACKET_SIZE - 8))/binary>>,
    {C1Packet, Digest} = make_client_digest(SchemeVersion, Bytes),

    State = #client_state{scheme_version = SchemeVersion, digest = Digest},
    {ok, C1Packet, State}.

%% @hidden
c2(S1Packet, State, _Options) ->
    #client_state{scheme_version = SchemeVersion} = State,

    io:format("#~p, ~p\n", [SchemeVersion, guess_server_scheme_version(S1Packet)]),

    {_, ServerDigest, _} = decode_digest(SchemeVersion, S1Packet),
    RandomBytes = crypto:rand_bytes(?HANDSHAKE_PACKET_SIZE - ?DIGEST_SIZE),
    C2Digest = crypto:hmac(sha256, crypto:hmac(sha256, ?GENUINE_FP_KEY, ServerDigest), RandomBytes),
    C2Packet = <<RandomBytes/binary, C2Digest/binary>>,
    {ok, C2Packet, State}.

%% @hidden
client_finish(S2Packet, State, _Options) ->
    #client_state{digest = ClientDigest} = State,
    <<RandomBytes:(?HANDSHAKE_PACKET_SIZE - ?DIGEST_SIZE)/binary, S2Digest/binary>> = S2Packet,
    case crypto:hmac(sha256, crypto:hmac(sha256, ?GENUINE_FMS_KEY, ClientDigest), RandomBytes) of
        S2Digest -> ok;
        _Other   -> {error, authentification_failed}
    end.

%% @hidden
server_init(_Options) ->
    State = #server_state{},
    {ok, State}.

%% @hidden
s0(RequestedRtmpVersion, State, Options) ->
    case RequestedRtmpVersion >= Options#handshake_option.rtmp_version of
        false -> {error, {unsupported_rtmp_version, RequestedRtmpVersion}};
        true  -> {ok, Options#handshake_option.rtmp_version, State}
    end.

%% @hidden
s1(C1Packet, State, Options) ->
    <<Timestamp:32, ClientVersion:4/binary, _/binary>> = C1Packet,
    SchemeVersion = guess_client_scheme_version(C1Packet),
    ok = rtmp_handshake_util:log(?MODULE, ?LINE, [{client_scheme_version, SchemeVersion}, {timestamp, Timestamp}, {client_version, ClientVersion}], Options),

    RandomBytes = crypto:rand_bytes(?HANDSHAKE_PACKET_SIZE - 8),
    {Digest1, _, Digest2} = decode_digest(SchemeVersion, <<(Options#handshake_option.timestamp):32, (Options#handshake_option.peer_version):4/binary, RandomBytes/binary>>),
    <<ServerFMSKey:36/binary, _/binary>> = ?GENUINE_FMS_KEY,
    ServerDigest = crypto:hmac(sha256, ServerFMSKey, <<Digest1/binary, Digest2/binary>>),
    S1Packet = <<Digest1/binary, ServerDigest/binary, Digest2/binary>>,

    State2 = State#server_state{
               c1_packet      = C1Packet,
               scheme_version = SchemeVersion
              },
    {ok, S1Packet, State2}.

%% @hidden
s2(State, _Options) ->
    #server_state{c1_packet = C1Packet, scheme_version = SchemeVersion} = State,
    RandomBytes = crypto:rand_bytes(?HANDSHAKE_PACKET_SIZE - ?DIGEST_SIZE),
    {_, ClientDigest, _} = decode_digest(SchemeVersion, C1Packet),
    ClientHash = crypto:hmac(sha256, crypto:hmac(sha256, ?GENUINE_FMS_KEY, ClientDigest), RandomBytes),
    S2Packet = <<RandomBytes/binary, ClientHash/binary>>,
    {ok, S2Packet, State}.

%% @hidden
server_finish(_C2Packet, State, _Options) ->
    {ok, State}.

%%--------------------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------------------
-spec guess_client_scheme_version(binary()) -> scheme_version().
guess_client_scheme_version(C1Packet) ->
    case validate_scheme_version(C1Packet, version1) of
        true  -> version1;
        false -> case validate_scheme_version(C1Packet, version2) of
                     true  -> version2;
                     false -> {unknown, version1}
                 end
    end.

guess_server_scheme_version(C1Packet) ->
    case validate_server_scheme_version(C1Packet, version1) of
        true  -> version1;
        false -> case validate_scheme_version(C1Packet, version2) of
                     true  -> version2;
                     false -> {unknown, version1}
                 end
    end.

-spec validate_scheme_version(binary(), scheme_version()) -> boolean().
validate_scheme_version(C1Packet, Version) ->
    {First, ClientDigest, Last} = decode_digest(Version, C1Packet),
    <<Key:30/binary, _/binary>> = ?GENUINE_FP_KEY,
    ClientDigest =:= crypto:hmac(sha256, Key, <<First/binary, Last/binary>>).

validate_server_scheme_version(C1Packet, Version) ->
    {First, ClientDigest, Last} = decode_digest(Version, C1Packet),
    <<Key:36/binary, _/binary>> = ?GENUINE_FMS_KEY,
    ClientDigest =:= crypto:hmac(sha256, Key, <<First/binary, Last/binary>>).

%% XXX: name
-spec make_client_digest(scheme_version(), binary()) -> {binary(), binary()}.
make_client_digest(Version, Bytes) ->
    {Left, Right} = encode_digest(Version, Bytes),
    <<Key:30/binary, _/binary>> = ?GENUINE_FP_KEY,
    Digest = crypto:hmac(sha256, Key, <<Left/binary, Right/binary>>),
    {<<Left/binary, Digest/binary, Right/binary>>, Digest}.

-spec decode_digest(scheme_version(), binary()) -> {binary(), binary(), binary()}.
decode_digest(version1, <<_:8/binary, P1, P2, P3, P4, _/binary>> = C1Packet) ->
    Offset = (P1 + P2 + P3 + P4) rem 728 + 12,
    <<First:Offset/binary, Seed:?DIGEST_SIZE/binary, Last/binary>> = C1Packet,
    {First, Seed, Last};
decode_digest(version2, <<_:772/binary, P1, P2, P3, P4, _/binary>> = C1Packet) ->
    Offset = (P1 + P2 + P3 + P4) rem 728 + 776,
    <<First:Offset/binary, Seed:?DIGEST_SIZE/binary, Last/binary>> = C1Packet,
    {First, Seed, Last}.

%% TODO:
%% -spec encode_digest(scheme_version(), binary(), binary()) -> binary().
encode_digest(version1, RandomBytes) ->
    <<_:8/binary, P1, P2, P3, P4, _/binary>> = RandomBytes,
    Offset = (P1 + P2 + P3 + P4) rem 728 + 12,
    <<Left:Offset/binary, _:?DIGEST_SIZE/binary, Right/binary>> = RandomBytes,
    {Left, Right};
encode_digest(version2, RandomBytes) ->
    <<Head:772/binary, _:4/binary, Tail/binary>> = RandomBytes,
    <<P1, P2, P3, P4>> = crypto:rand_bytes(4),
    Offset = (P1 + P2 + P3 + P4) rem 728 + 776,
    <<Left:Offset/binary, _:?DIGEST_SIZE/binary, Right/binary>> = <<Head:772/binary, P1, P2, P3, P4, Tail/binary>>,
    {Left, Right}.

%% 79> {ok, C} = gen_tcp:connect("localhost", 1935, [binary, {active,false}]).
%% 80> rtmp_handshake:client_handshake(C, [{enable_log,true}, {method, digest}, {peer_version, <<9,0,124,2>>}]).

