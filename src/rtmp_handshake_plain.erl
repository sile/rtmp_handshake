%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc Plain RTMP Handshake Implementation
-module(rtmp_handshake_plain).

-include("../include/rtmp_handshake_internal.hrl").

-behaviour(rtmp_handshake_interface).

%%--------------------------------------------------------------------------------
%% 'rtmp_handshake_interface' Callback API
%%--------------------------------------------------------------------------------
-export([c1/2, c2/3, client_finish/3]).
-export([s1/3, s2/2, server_finish/3]).

%%--------------------------------------------------------------------------------
%% Records
%%--------------------------------------------------------------------------------
-record(server_state,
        {
          c1_packet :: binary()
        }).

%%--------------------------------------------------------------------------------
%% 'rtmp_handshake_interface' Callback Functions
%%--------------------------------------------------------------------------------
%% @hidden
c1(none, Options) ->
    {generate_phase1_packet(Options), []}.

%% @hidden
c2(S1Packet, State, _Options) ->
    {true, S1Packet, State}.

%% @hidden
client_finish(_S2Packet, _State, _Options) ->
    true.

%% @hidden
s1(none, C1Packet, Options) ->
    {true, generate_phase1_packet(Options), #server_state{c1_packet = C1Packet}}.

%% @hidden
s2(State, _Options) ->
    {State#server_state.c1_packet, State}.

%% @hidden
server_finish(_C2Packet, _State, _Options) ->
    true.

%%--------------------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------------------
-spec generate_phase1_packet(#handshake_option{}) -> binary().
generate_phase1_packet(Options) ->
    #handshake_option{timestamp = Timetamp, app_version = {V1, V2, V3, V4}} = Options,
    <<Timetamp:32, V1, V2, V3, V4, (crypto:rand_bytes(?HANDSHAKE_PACKET_SIZE - 8))/binary>>.
