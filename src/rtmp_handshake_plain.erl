%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc Plain RTMP Handshake Implementation
-module(rtmp_handshake_plain).

-include("../include/rtmp_handshake_internal.hrl").

-behaviour(rtmp_handshake_interface).

%%--------------------------------------------------------------------------------
%% 'rtmp_handshake_interface' Callback API
%%--------------------------------------------------------------------------------
-export([client_init/1, c0/2, c1/2, c2/4, client_finish/3]).

%%--------------------------------------------------------------------------------
%% 'rtmp_handshake_interface' Callback Functions
%%--------------------------------------------------------------------------------
%% @hidden
client_init(_Options) ->
    {ok, []}.

%% @hidden
c0(State, Options) ->
    {ok, Options#handshake_option.rtmp_version, State}.

%% @hidden
c1(State, Options) ->
    #handshake_option{peer_version = Version, timestamp = Timetamp} = Options,
    Head = <<Timetamp:32, Version:4/binary>>,
    Tail = crypto:rand_bytes(?HANDSHAKE_PACKET_SIZE - byte_size(Head)),
    {ok, <<Head/binary, Tail/binary>>, State}.

%% @hidden
c2(ServerRtmpVersion, S1Packet, State, Options) ->
    case ServerRtmpVersion =:= Options#handshake_option.rtmp_version of
        false -> {error, {unsupported_rtmp_version, ServerRtmpVersion}};
        true  -> {ok, S1Packet, State}
    end.

%% @hidden
client_finish(_S2Packet, State, _Options) ->
    {ok, State}.


