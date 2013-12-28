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
-callback c1(rtmp_handshake:authentification_method(), #handshake_option{}) -> {ok, C1Packet::binary(), client_state()} | {error, Reason::term()}.
-callback c2(S1Pakcet::binary(), client_state(), #handshake_option{}) -> {ok, C2Packet::binary(), client_state()} | {error, Reason::term()}.
-callback client_finish(S2Packet::binary(), client_state(), #handshake_option{}) -> ok | {error, Reason::term()}.

-callback s1(rtmp_handshake:authentification_method(), C1Packet::binary(), #handshake_option{}) -> {ok, S1Pakcet::binary(), server_state()} | {error, Reason::term()}.
-callback s2(server_state(), #handshake_option{}) -> {ok, S2Packet::binary(), server_state()} | {error, Reason::term()}.
-callback server_finish(C2Packet::binary(), server_state(), #handshake_option{}) -> ok | {error, Reason::term()}.

%%--------------------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------------------
-type client_state() :: term().
-type server_state() :: term().
