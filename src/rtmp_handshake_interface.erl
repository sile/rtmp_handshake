%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc RTMP Handshake Interface module
-module(rtmp_handshake_interface).

-include("../include/rtmp_handshake_internal.hrl").

%%--------------------------------------------------------------------------------
%% Exported API
%%--------------------------------------------------------------------------------
-export_type([
              client_state/0,
              server_state/0
             ]).

%%--------------------------------------------------------------------------------
%% Callback API
%%--------------------------------------------------------------------------------
-callback c1(rtmp_handshake:validation_method(), #handshake_option{}) -> {C1Packet::binary(), client_state()}.
-callback c2(S1Pakcet::binary(), client_state(), #handshake_option{}) -> {IsValid::boolean(), C2Packet::binary(), client_state()}.
-callback client_finish(S2Packet::binary(), client_state(), #handshake_option{}) -> IsValid::boolean().

-callback s1(rtmp_handshake:validation_method(), C1Packet::binary(), #handshake_option{}) -> {IsValid::boolean(), S1Pakcet::binary(), server_state()}.
-callback s2(server_state(), #handshake_option{}) -> {S2Packet::binary(), server_state()}.
-callback server_finish(C2Packet::binary(), server_state(), #handshake_option{}) -> IsValid::boolean().

%%--------------------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------------------
-type client_state() :: term().
-type server_state() :: term().
