defmodule Libbitcoin.Client do
  alias Libbitcoin.Client
  use Bitwise
  use Libbitcoin.Client.ErrorCode

  @default_timeout 2000
  @hz 10

  @empty_commands [
    "blockchain.fetch_last_height",
    "protocol.total_connections"
  ]

  @height_commands [
    "blockchain.fetch_block_header",
  ]

  @hash_commands [
    "blockchain.fetch_block_height",
    "blockchain.fetch_block_transaction_hashes",
    "blockchain.fetch_transaction_index",
    "blockchain.fetch_transaction",
    "blockchain.fetch_transaction2",
    "transaction_pool.fetch_transaction",
    "transaction_pool.fetch_transaction2",
  ]

  @output_point_commands [
    "blockchain.fetch_spend"
  ]

  @stealth_commands [
    "blockchain.fetch_stealth",
    "blockchain.fetch_stealth2",
    "blockchain.fetch_stealth_transaction_hashes"
  ]

  @history1_commands [
   "address.fetch_history",
  ]

  @history2_commands [
   "address.fetch_history2",
   "blockchain.fetch_history",
   "blockchain.fetch_history3"
  ]

  @history_commands @history1_commands ++ @history2_commands

  @transaction_commands [
   "transaction_pool.validate",
   "transaction_pool.validate2",
   "transaction_pool.broadcast",
   "protocol.broadcast_transaction"
  ]

  @block_commands [
    "blockchain.broadcast",
    "blockchain.validate"
  ]

  defstruct [context: nil, socket: nil, requests: %{}, timeout: 1000]

  def start_link(uri, options \\ %{}) do
    GenServer.start_link(__MODULE__, [uri, options])
  end

  def last_height(client, owner \\ self) do
    cast(client, "blockchain.fetch_last_height", "", owner)
  end

  def block_height(client, block_hash, owner \\ self) do
    cast(client, "blockchain.fetch_block_height", [block_hash], owner)
  end

  def block_header(client, height, owner \\ self) when is_integer(height) do
    cast(client, "blockchain.fetch_block_header", [height], owner)
  end

  def block_transaction_hashes(client, hash, owner \\ self) when is_binary(hash) do
    cast(client, "blockchain.fetch_block_transaction_hashes", [hash], owner)
  end

  def blockchain_transaction(client, hash, owner \\ self) do
    cast(client, "blockchain.fetch_transaction", [hash], owner)
  end

  def blockchain_transaction2(client, hash, owner \\ self) do
    cast(client, "blockchain.fetch_transaction2", [hash], owner)
  end

  def pool_transaction(client, hash, owner \\ self) do
    cast(client, "transaction_pool.fetch_transaction", [hash], owner)
  end

  def pool_transaction2(client, hash, owner \\ self) do
    cast(client, "transaction_pool.fetch_transaction2", [hash], owner)
  end

  def transaction_index(client, hash, owner \\ self) do
    cast(client, "blockchain.fetch_transaction_index", [hash], owner)
  end

  def spend(client, hash, index, owner \\ self) do
    cast(client, "blockchain.fetch_spend", [hash, index], owner)
  end

  def stealth(client, bits, prefix, owner \\ self) do
    cast(client, "blockchain.fetch_stealth", [bits, prefix], owner)
  end

  def stealth2(client, bits, prefix, owner \\ self) do
    cast(client, "blockchain.fetch_stealth2", [bits, prefix], owner)
  end

  def address_history(client, address, height \\ 0,  owner \\ self) do
    cast(client, "address.fetch_history", [address, height], owner)
  end

  def address_history2(client, address, height \\ 0,  owner \\ self) do
    cast(client, "address.fetch_history2", [address, height], owner)
  end

  def blockchain_history(client, address, height \\ 0,  owner \\ self) do
    cast(client, "blockchain.fetch_history", [address, height], owner)
  end

  def blockchain_history3(client, address, height \\ 0,  owner \\ self) do
    cast(client, "blockchain.fetch_history3", [address, height], owner)
  end

  def total_connections(client, owner \\ self) do
    cast(client, "protocol.total_connections", [], owner)
  end

  def validate(client, tx, owner \\ self) do
    cast(client, "transaction_pool.validate", [tx], owner)
  end

  def validate2(client, tx, owner \\ self) do
    cast(client, "transaction_pool.validate2", [tx], owner)
  end

  def blockchain_validate(client, block, owner \\ self) do
    cast(client, "blockchain.validate", [block], owner)
  end

  def broadcast_transaction(client, tx, owner \\ self) do
    cast(client, "protocol.broadcast_transaction", [tx], owner)
  end

  def transaction_pool_broadcast(client, tx, owner \\ self) do
    cast(client, "transaction_pool.broadcast", [tx], owner)
  end

  def call(client, command, argv, timeout \\ 1000) do
    {:ok, ref} = cast(client, command, argv)
    receive do
      {:libbitcoin_client, ^command, ^ref, reply} ->
        {:ok, reply}
      {:libbitcoin_client_error, ^command, ^ref, reply} ->
        {:error, reply}
    after
      timeout ->
        {:error, :timeout}
    end
  end

  def cast(client, command, argv) do
    cast(client, command, argv, self)
  end

  def cast(client, command, [], owner)
    when command in @empty_commands do
    cast(client, command, "", owner)
  end
  def cast(client, command, [height], owner)
    when command in @height_commands do
    cast(client, command, encode_int(height), owner)
  end
  def cast(client, command, [hash], owner)
    when command in @hash_commands
    and is_binary(hash) do
    cast(client, command, reverse_hash(hash), owner)
  end
  def cast(client, command, [hash, index], owner)
    when command in @output_point_commands do
    cast(client, command, reverse_hash(hash) <> encode_int(index), owner)
  end
  def cast(client, command, [bits, prefix], owner)
    when command in @stealth_commands
    and is_binary(bits)
    and is_integer(prefix) do
    bitfield = encode_stealth(bits)
    bitfield_size = byte_size(bitfield)
    size = byte_size(bits)
    cast(client, command, <<size :: unsigned-integer-size(8),
      bitfield :: binary-size(bitfield_size),
      prefix :: unsigned-integer-size(32)>>, owner)
  end
  def cast(client, command, [address, height], owner)
    when command in @history1_commands
    and is_binary(address)
    and is_integer(height) do
    {prefix, decoded} = decode_base58check(address)
    cast(client, command, <<prefix :: binary-size(1),
      reverse_hash(decoded) :: binary-size(20),
      encode_int(height) :: binary>>, owner)
  end
  def cast(client, command, [address, height], owner)
    when command in @history2_commands
    and is_binary(address)
    and is_integer(height) do
    {_prefix, decoded} = decode_base58check(address)
    cast(client, command, <<decoded :: binary-size(20),
      encode_int(height) :: binary>>, owner)
  end
  def cast(client, command, [transaction], owner)
    when command in @transaction_commands and is_binary(transaction) do
    cast(client, command, transaction, owner)
  end
  def cast(client, command, [block], owner)
    when command in @block_commands and is_binary(block) do
    cast(client, command, block, owner)
  end
  def cast(_client, _command, argv, _owner) when is_list(argv) do
    {:error, :badarg}
  end
  def cast(client, command, argv, owner) when is_binary(argv) do
    request_id = new_request_id
    payload = {:command, request_id, command, argv, owner}
    case GenServer.cast(client, payload) do
      :ok -> {:ok, request_id}
      reply -> reply
    end
  end

  @divisor 1 <<< 63
  def spend_checksum(hash, index) do
    encoded_index = <<index :: little-unsigned-size(32)>>
    <<_ :: binary-size(4), hash_value :: binary-size(4), _ :: binary>> = reverse_hash(hash)
    encoded_value = <<encoded_index :: binary-size(4), hash_value :: binary-size(4)>>
    value = :binary.decode_unsigned(encoded_value, :little)
    value &&& (@divisor - 1)
  end

  def init([uri, %{timeout: timeout}]) do
    {:ok, ctx} = :czmq.start_link
    socket = :czmq.zsocket_new ctx, :dealer
    :ok = :czmq.zctx_set_linger ctx, 0
    case :czmq.zsocket_connect socket, uri do
      :ok ->
        {:ok, %Client{context: ctx, socket: socket, timeout: timeout}}
      {:error, _} = error ->
        {:stop, error}
    end
  end
  def init([uri, options]) do
    options = Map.merge(options, %{timeout: @default_timeout})
    init([uri, options])
  end

  def handle_cast({:command, request_id, command, argv, owner}, state) do
    {:ok, state} = add_request(request_id, owner, state)
    case send_command(request_id, command, argv, state) do
      {:ok, state} ->
        {:noreply, state}
      {:error, error, %Client{requests: requests} = state} ->
        :ok = send_reply({:error, error}, command, request_id, owner)
        {:ok, requests} = clear_request(request_id, requests)
        {:ok, state} = retry_receive_payload(%Client{state | requests: requests})
        {:noreply, state}
    end
  end

  def handle_info(:receive_payload, state) do
    case receive_payload(state) do
      {:ok, state} -> {:noreply, state}
      {:error, :not_found} -> {:noreply, state}
    end
  end

  def handle_info({:timeout, request_id}, %Client{requests: requests} = state) do
    case Map.fetch(requests, request_id) do
      :error ->
        {:noreply, state}
      {:ok, owner} when is_pid(owner) ->
        send_reply({:error, :timeout}, nil, request_id, owner)
        {:ok, requests} = clear_request(request_id, requests)
        {:noreply, %Client{state | requests: requests}}
    end
  end

  defp send_command(request_id, command, payload, state) do
    case send_payload(request_id, command, payload, state) do
      :error -> {:error, :request_error, state}
      reply -> reply
    end
  end

  defp decode_command(_command, <<3 :: little-integer-unsigned-size(32), _rest :: binary>>) do
    {:error, :not_found}
  end
  defp decode_command(command,
    <<@success :: little-integer-unsigned-size(32), height :: little-integer-unsigned-size(32)>>)
    when command in ["blockchain.fetch_last_height", "blockchain.fetch_block_height"] do
    {:ok, height}
  end
  defp decode_command("blockchain.fetch_block_header",
    <<@success :: little-integer-unsigned-size(32), header :: binary>>) do
    {:ok, header}
  end
  defp decode_command("blockchain.fetch_block_transaction_hashes",
    <<@success :: little-integer-unsigned-size(32), hashes :: binary>>) do
    hashes = transform_block_transactions_hashes(hashes, [])
    {:ok, hashes}
  end
  defp decode_command(command,
    <<@success :: little-integer-unsigned-size(32), transaction :: binary>> )
    when command in @hash_commands do
    {:ok, transaction}
  end
  defp decode_command("blockchain.fetch_transaction_index",
    <<@success :: little-integer-unsigned-size(32),
      height :: little-integer-unsigned-size(32),
      index :: little-integer-unsigned-size(32)>>) do
    {:ok, {height, index}}
  end
  defp decode_command("blockchain.fetch_spend",
    <<@not_found :: little-integer-unsigned-size(32), _ :: binary>>) do
    {:error, error_code(5)}
  end
  defp decode_command("blockchain.fetch_spend",
    <<@success :: little-integer-unsigned-size(32), hash :: binary-size(32),
      index :: little-integer-unsigned-size(32)>>) do

    {:ok, {reverse_hash(hash), index}}
  end
  defp decode_command(command, <<@success :: little-integer-unsigned-size(32)>>)
    when command in ["blockchain.fetch_stealth", "blockchain.fetch_stealth2"] do
    {:ok, []}
  end
  defp decode_command(command, <<@success :: little-integer-size(32), rows :: binary>>)
    when command in ["blockchain.fetch_stealth", "blockchain.fetch_stealth2"] do
    decode_stealth(rows, [])
  end
  defp decode_command("address.fetch_history", <<@success :: little-integer-unsigned-size(32)>>) do
    {:ok, []}
  end
  defp decode_command("address.fetch_history",
    <<@success :: little-integer-size(32), history :: binary>>) do
    decode_history1(history, [])
  end
  defp decode_command(command, <<@success :: little-integer-size(32), history :: binary>>)
   when command in ["blockchain.fetch_history", "address.fetch_history2"] do
    decode_history2(history, [])
  end
  defp decode_command("blockchain.fetch_history3",
    <<@success :: little-integer-size(32), history :: binary>>) do
    decode_history2(history, [])
  end
  defp decode_command(command,
    <<ec :: little-integer-unsigned-size(32), _any :: binary>>)
    when command in @transaction_commands do
    {:ok, error_code(ec)}
  end
  defp decode_command("transaction_pool.validate2",
    <<ec :: little-integer-unsigned-size(32), _any :: binary>>) do
    {:ok, error_code(ec)}
  end
  defp decode_command("protocol.broadcast_transaction",
    <<ec :: little-integer-unsigned-size(32), _any :: binary>>) do
    {:ok, error_code(ec)}
  end
  defp decode_command("protocol.total_connections",
    <<@success :: little-integer-unsigned-size(32), connections :: little-integer-unsigned-size(32)>>) do
   {:ok, connections}
  end
  defp decode_command(_command, <<ec :: little-integer-unsigned-size(32),
                                 _rest :: binary>>) when ec != 0 do
    {:error, error_code(ec)}
  end
  defp decode_command(_any, _reply) do
    {:error, :unknown_reply}
  end

  @ephemkey_compressed 02 # assuming this is always compressed

  defp decode_stealth(<<>>, acc), do: {:ok, Enum.reverse(acc)}
  defp decode_stealth(<<ephemkey :: binary-size(32),
                        address :: binary-size(20),
                        tx_hash :: binary-size(32),
                        rest :: binary>>, acc) do

    row = %{ephemkey: <<@ephemkey_compressed, ephemkey :: binary>>,
            address: reverse_hash(address),
            tx_hash: reverse_hash(tx_hash)}
    decode_stealth(rest, [row|acc])
  end

  defp decode_history1(<<>>, acc), do: {:ok, Enum.reverse(acc)}
  defp decode_history1(<<output_hash :: binary-size(32),
                        output_index :: little-unsigned-integer-size(32),
                        output_height :: little-unsigned-integer-size(32),
                        value :: little-unsigned-integer-size(64),
                        spend_hash :: binary-size(32),
                        spend_index :: little-unsigned-integer-size(32),
                        spend_height :: little-unsigned-integer-size(32),
                        rest :: binary>>, acc) do
    row = %{output_hash: reverse_hash(output_hash),
            output_index: output_index,
            output_height: output_height,
            value: value,
            spend_hash: reverse_hash(spend_hash),
            spend_index: spend_index,
            spend_height: spend_height}
    decode_history1(rest, [row|acc])
  end

  defp decode_history2(<<>>, acc), do: {:ok, Enum.reverse(acc)}
  defp decode_history2(<<type :: binary-bytes-size(1),
                         hash :: binary-size(32),
                         index :: little-unsigned-integer-size(32),
                         height :: little-unsigned-integer-size(32),
                         value :: little-unsigned-integer-size(64),
                         rest :: binary>>, acc) do
    row = %{type: history_row_type(type),
            hash: reverse_hash(hash),
            index: index,
            height: height,
            value: value}
    decode_history2(rest, [row|acc])
  end


  defp history_row_type(<<0>>), do: :output
  defp history_row_type(<<1>>), do: :spend

  defp send_payload(request_id, command, payload,
    %Client{socket: socket, timeout: timeout} = state) do
    bin_request_id = <<request_id :: unsigned-little-integer-size(32)>>
    _timerref = schedule_timeout(request_id, timeout)
    case :czmq.zsocket_send_all(socket, [command, bin_request_id, payload]) do
      :ok ->
        receive_payload(state)
      other ->
        other
    end
  end

  defp receive_payload(%Client{socket: socket} = state) do
    case :czmq.zframe_recv_all(socket) do
      {:ok, reply} ->
        handle_reply(reply, state)
      :error ->
        retry_receive_payload(state)
    end
  end

  defp handle_reply([command, <<request_id :: integer-little-unsigned-size(32)>>, reply],
                    %Client{requests: requests} = state) do
    case Map.fetch(requests, request_id) do
      {:ok, owner} when is_pid(owner) ->
        decode_command(command, reply) |> send_reply(command, request_id, owner)
        {:ok, requests} = clear_request(request_id, requests)
        {:ok, %Client{state | requests: requests}}
      :error ->
        {:error, :not_found}
    end
  end

  defp add_request(request_id, owner, %Client{requests: requests} = state) do
    {:ok, %Client{state | requests: Map.put(requests, request_id, owner)}}
  end

  defp clear_request(request_id, requests) do
    {:ok,  Map.delete(requests, request_id)}
  end

  defp retry_receive_payload(%Client{requests: []} = state) do
    {:ok, state}
  end
  defp retry_receive_payload(state) do
    :erlang.send_after(@hz, self, :receive_payload)
    {:ok, state}
  end

  defp schedule_timeout(request_id, timeout) do
    :erlang.send_after(timeout, self, {:timeout, request_id})
  end

  defp send_reply({:ok, decoded}, command, request_id, owner) do
    send(owner, {:libbitcoin_client, command, request_id, decoded})
  end

  defp send_reply({:error, reason}, command, request_id, owner) do
    send(owner, {:libbitcoin_client_error, command, request_id, reason})
  end

  defp new_request_id, do: :crypto.rand_uniform(0, 0xFFFFFFFE)

  defp encode_int(int), do: <<int :: little-integer-unsigned-size(32)>>

  defp reverse_hash(hash) do
    reverse_hash(hash, <<>>)
  end

  defp reverse_hash(<<>>, acc), do: acc
  defp reverse_hash(<<h :: binary-size(1), rest :: binary>>, acc) do
    reverse_hash(rest, <<h :: binary, acc :: binary>>)
  end

  def decode_base58check(address) do
    <<version::binary-size(1), pkh::binary-size(20), checksum::binary-size(4)>> =
      :base58.base58_to_binary(to_char_list(address))
    case  :crypto.hash(:sha256, :crypto.hash(:sha256, version <> pkh)) do
      <<^checksum :: binary-size(4), _ :: binary>> -> {version, pkh}
      _ -> {:error, :invalid_checksum}
    end
  end

  def transform_block_transactions_hashes(<<"">>, hashes), do: Enum.reverse(hashes)
  def transform_block_transactions_hashes(<<hash :: binary-size(32), rest :: binary>>, hashes) do
    transform_block_transactions_hashes(rest, [reverse_hash(hash)|hashes])
  end

  @stealth_block_size 8
  def encode_stealth(prefix), do: encode_stealth(prefix, [])

  def encode_stealth(<<>>, blocks) do
    Enum.reverse(blocks) |> IO.iodata_to_binary
  end
  def encode_stealth(<<block :: binary-size(@stealth_block_size), tail :: binary>>, blocks) do
    value = String.to_integer(block, 2) |> :binary.encode_unsigned
    encode_stealth(tail, [value|blocks])
  end
  def encode_stealth(<<block :: binary>>, blocks) do
    str = String.ljust(block, @stealth_block_size, ?0)
    encode_stealth(str, blocks)
  end
end
