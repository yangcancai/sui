-module(sui_nif).

%% API
-export([
    new/0,  %% new resource
    new/1
]).
%% Native library support
-export([load/0]).

-on_load load/0.

-opaque sui() :: reference().

-export_type([sui/0]).

new() ->
    new(#{}).

-spec new(_Opts :: map()) -> {ok, Ref :: sui()} | error.
new(_Opts) ->
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