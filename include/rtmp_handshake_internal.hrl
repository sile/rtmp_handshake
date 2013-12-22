%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc Internal Header for `rtmp_handshake' application

-record(handshake_option,
        {
          rtmp_version :: non_neg_integer(),
          peer_version :: binary(),
          timestamp    :: binary(),
          method       :: rtmp_handshake:handshake_method(),
          recv_timeout :: timeout()
        }).
