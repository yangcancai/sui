-module(sui_nif).

%% API
-export([
    new/0,  %% new resource
    new/1,
    sign/2
]).
%% Native library support
-export([load/0]).

-on_load load/0.

-opaque sui_address() :: tuple().

-export_type([sui_address/0]).

new() ->
    new(#{}).

-spec new(_Opts :: map()) -> {ok, Ref :: sui_address()} | error.
new(_Opts) ->
    not_loaded(?LINE).

-spec sign(TxBytes :: binary(), Secret :: binary()) -> {ok, list()} | error.
sign(_TxBytes, _Secret) ->
   not_loaded(?LINE).

%% @private
load() ->
    erlang:load_nif(
        filename:join(priv(), "libsui"), none).

not_loaded(Line) ->
    erlang:nif_error({error, {not_loaded, [{module, ?MODULE}, {line, Line}]}}).

priv() ->
    case code:priv_dir(?MODULE) of
        {error, _} ->
            EbinDir =
                filename:dirname(
                    code:which(?MODULE)),
            AppPath = filename:dirname(EbinDir),
            filename:join(AppPath, "priv");
        Path ->
            Path
    end.