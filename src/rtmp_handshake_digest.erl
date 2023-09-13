%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc Digest RTMP Handshake Implementation
-module(rtmp_handshake_digest).

-include("../include/rtmp_handshake_internal.hrl").

-behaviour(rtmp_handshake_interface).

%%--------------------------------------------------------------------------------
%% 'rtmp_handshake_interface' Callback API
%%--------------------------------------------------------------------------------
-export([c1/2, c2/3, client_finish/3]).
-export([s1/3, s2/2, server_finish/3]).

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

-record(state,
        {
          client_digest  :: binary(),
          server_digest  :: binary(),
          scheme_version :: scheme_version()
        }).

-type scheme_version() :: version1 | version2.

%%--------------------------------------------------------------------------------
%% 'rtmp_handshake_interface' Callback Functions
%%--------------------------------------------------------------------------------
%% @hidden
c1(AuthMethod, Options) ->
    SchemeVersion = case AuthMethod of
                        digest_version1 -> version1;
                        digest_version2 -> version2
                    end,
    {C1Packet, ClientDigest} = generate_phase1_packet_and_digest(SchemeVersion, client, Options),
    State = #state{
               scheme_version = SchemeVersion,
               server_digest  = <<"">>,
               client_digest  = ClientDigest
              },
    {C1Packet, State}.

%% @hidden
c2(S1Packet, State, _Options) ->
    #state{scheme_version = SchemeVersion} = State,
    {Left, ServerDigest, Right} = extract_digest(SchemeVersion, S1Packet),
    IsValid = ServerDigest =:= hmac(sha256, get_digest_key(server), <<Left/binary, Right/binary>>),
    C2Packet = generate_phase2_packet(?GENUINE_FP_KEY, ServerDigest),
    {IsValid, C2Packet, State#state{server_digest = ServerDigest}}.

%% @hidden
client_finish(S2Packet, State, _Options) ->
    #state{client_digest = ClientDigest} = State,
    <<Bytes:(?HANDSHAKE_PACKET_SIZE - ?DIGEST_SIZE)/binary, S2Digest/binary>> = S2Packet,
    IsValid = S2Digest =:= hmac(sha256, hmac(sha256, ?GENUINE_FMS_KEY, ClientDigest), Bytes),
    IsValid.

%% @hidden
s1(AuthMethod, C1Packet, Options) ->
    SchemeVersion = case AuthMethod of
                        digest_version1 -> version1;
                        digest_version2 -> version2
                    end,
    {Left, ClientDigest, Right} = extract_digest(SchemeVersion, C1Packet),
    IsValid = ClientDigest =:= hmac(sha256, get_digest_key(client), <<Left/binary, Right/binary>>),
    {S1Packet, ServerDigest} = generate_phase1_packet_and_digest(SchemeVersion, server, Options),
    State = #state{
               scheme_version = SchemeVersion,
               server_digest  = ServerDigest,
               client_digest  = ClientDigest
              },
    {IsValid, S1Packet, State}.

%% @hidden
s2(State, _Options) ->
    #state{client_digest = ClientDigest} = State,
    S2Packet = generate_phase2_packet(?GENUINE_FMS_KEY, ClientDigest),
    {S2Packet, State}.

%% @hidden
server_finish(C2Packet, State, _Options) ->
    #state{server_digest = ServerDigest} = State,
    <<Bytes:(?HANDSHAKE_PACKET_SIZE - ?DIGEST_SIZE)/binary, C2Digest/binary>> = C2Packet,
    IsValid = C2Digest =:= hmac(sha256, hmac(sha256, ?GENUINE_FP_KEY, ServerDigest), Bytes),
    IsValid.

%%--------------------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------------------
-spec generate_phase1_packet_and_digest(scheme_version(), server|client, #handshake_option{}) -> {Packet::binary(), Digest::binary()}.
generate_phase1_packet_and_digest(SchemeVersion, Role, Options) ->
    #handshake_option{timestamp = Timetamp, app_version = {V1, V2, V3, V4}} = Options,
    Bytes = <<Timetamp:32, V1, V2, V3, V4, (crypto:strong_rand_bytes(?HANDSHAKE_PACKET_SIZE - 8))/binary>>,
    {Left, _, Right} = extract_digest(SchemeVersion, Bytes),
    Digest = hmac(sha256, get_digest_key(Role), <<Left/binary, Right/binary>>),
    Phase1Packet = <<Left/binary, Digest/binary, Right/binary>>,
    {Phase1Packet, Digest}.

-spec generate_phase2_packet(binary(), binary()) -> binary().
generate_phase2_packet(Key, PeerDigest) ->
    Bytes = crypto:strong_rand_bytes(?HANDSHAKE_PACKET_SIZE - ?DIGEST_SIZE),
    Digest = hmac(sha256, hmac(sha256, Key, PeerDigest), Bytes),
    <<Bytes/binary, Digest/binary>>.

-spec extract_digest(scheme_version(), binary()) -> {LeftBytes::binary(), Digest::binary(), RightBytes::binary()}.
extract_digest(version1, <<_:8/binary, P1, P2, P3, P4, _/binary>> = Bytes) ->
    Offset = (P1 + P2 + P3 + P4) rem 728 + 12,
    <<Left:Offset/binary, Digest:?DIGEST_SIZE/binary, Right/binary>> = Bytes,
    {Left, Digest, Right};
extract_digest(version2, <<_:772/binary, P1, P2, P3, P4, _/binary>> = Bytes) ->
    Offset = (P1 + P2 + P3 + P4) rem 728 + 776,
    <<Left:Offset/binary, Digest:?DIGEST_SIZE/binary, Right/binary>> = Bytes,
    {Left, Digest, Right}.

-spec get_digest_key(server|client) -> binary().
get_digest_key(server) -> binary:part(?GENUINE_FMS_KEY, 0, 36);
get_digest_key(client) -> binary:part(?GENUINE_FP_KEY, 0, 30).

-spec hmac(sha256, iodata(), iodata()) -> binary().
-ifdef(OTP_RELEASE).
-if(?OTP_RELEASE >= 23). % crypto:mac/4 was introduced at OTP 22.1
hmac(SubType, Key, Data) -> crypto:mac(hmac, SubType, Key, Data).
-else.
hmac(SubType, Key, Data) -> crypto:hmac(SubType, Key, Data).
-endif.
-else.
hmac(SubType, Key, Data) -> crypto:hmac(SubType, Key, Data).
-endif.
