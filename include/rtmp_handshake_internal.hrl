%% @copyright 2013 Takeru Ohta <phjgt308@gmail.com>
%%
%% @doc Internal Header for `rtmp_handshake' application

-record(handshake_option,
        {
          rtmp_version :: rtmp_handshake:rtmp_version(),
          app_version  :: rtmp_handshake:application_version(),
          timestamp    :: rtmp_handshake:milliseconds(),
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

-define(CLIENT_DEFAULT_APP_VERSION, {9,0,124,2}).
-define(SERVER_DEFAULT_APP_VERSION, {5,0,3,1}).
