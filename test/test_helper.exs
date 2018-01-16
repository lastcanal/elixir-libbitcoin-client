query_endpoint = :application.get_env(:libbitcoin_client, :query_endpoint, "tcp://127.0.0.1:9091")
{:ok, bs} = Libbitcoin.Client.start_link(query_endpoint)
Process.register(bs, :bs)
ExUnit.start()
