%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc Internal Header for `rtmp_handshake' application

-record(handshake_option,
        {
          rtmp_version :: non_neg_integer(),
          peer_version :: binary(),
          timestamp    :: binary(),
          method       :: rtmp_handshake:handshake_method(),
          recv_timeout :: timeout(),
          enable_log   :: false | true | {true, Type::any()}
        }).

-define(HANDSHAKE_PACKET_SIZE, 1536).

-define(LOG(Params, Options),
        case Options#handshake_option.enable_log of
            false     -> ok;
            true      -> error_logger:info_report([{module, ?MODULE}, {line, ?LINE}, {pid, self()} | Params]);
            {true, _} -> error_logger:info_report(element(2, Options#handshake_option.enable_log),
                                                  [{module, ?MODULE}, {line, ?LINE}, {pid, self()} | Params])
        end).
