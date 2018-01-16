defmodule BitcoinClientTest do
  alias Libbitcoin.Client, as: C
  use ExUnit.Case

  @timeout 2000

  test "blockchain.fetch_last_height" do
    assert {:ok, ref} = C.last_height(:bs)
    assert_receive {:libbitcoin_client, "blockchain.fetch_last_height", ^ref, height} when is_integer(height), @timeout
  end

  test "blockchain.fetch_block_header" do
    {:ok, hash} = Base.decode16("0F9188F13CB7B2C71F2A335E3A4FC328BF5BEB436012AFCA590B1A11466E2206")
    assert {:ok, ref} = C.block_height(:bs, hash)
    assert_receive {:libbitcoin_client, "blockchain.fetch_block_height", ^ref, 0}, @timeout
  end

  test "blockchain.fetch_block_header not found" do
    {:ok, hash} = Base.decode16("00000000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert {:ok, ref} = C.block_height(:bs, hash)
    assert_receive {:libbitcoin_client_error, "blockchain.fetch_block_height", ^ref, :not_found}, @timeout
  end

  test "blockchain.block_header" do
    assert {:ok, ref} = C.block_header(:bs, 0)
    assert_receive {:libbitcoin_client, "blockchain.fetch_block_header", ^ref, header} when is_binary(header), @timeout
  end

  test "blockchain.block_height" do
    assert {:ok, ref} = C.block_header(:bs, 0)
    assert_receive {:libbitcoin_client, "blockchain.fetch_block_header", ^ref, header} when is_binary(header), @timeout
  end

  test "blockchain.block_transaction_hashes" do
    {:ok, hash} = Base.decode16("0F9188F13CB7B2C71F2A335E3A4FC328BF5BEB436012AFCA590B1A11466E2206")
    assert {:ok, ref} = C.block_transaction_hashes(:bs, hash)
    hashes = Enum.map ["4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB2127B7AFDEDA33B"], &Base.decode16!(&1)
    assert_receive {:libbitcoin_client, "blockchain.fetch_block_transaction_hashes", ^ref, ^hashes}, @timeout
  end

  test "blockchain.fetch_transaction" do
    {:ok, hash} = Base.decode16("4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB2127B7AFDEDA33B")
    assert {:ok, ref} = C.blockchain_transaction(:bs, hash)
    assert_receive {:libbitcoin_client, "blockchain.fetch_transaction", ^ref, tx} when is_binary(tx), @timeout
  end

  test "blockchain.fetch_transaction not found" do
    {:ok, hash} = Base.decode16("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert {:ok, ref} = C.blockchain_transaction(:bs, hash)
    assert_receive {:libbitcoin_client_error, "blockchain.fetch_transaction", ^ref, :not_found}, @timeout
  end

  test "blockchain.fetch_transaction2" do
    {:ok, hash} = Base.decode16("0F9188F13CB7B2C71F2A335E3A4FC328BF5BEB436012AFCA590B1A11466E2206")
    assert {:ok, ref} = C.blockchain_transaction2(:bs, hash)
    assert_receive {:libbitcoin_client_error, "blockchain.fetch_transaction2", ^ref, :not_found}, @timeout
  end

  test "blockchain.fetch_spend" do
    {:ok, hash} = Base.decode16("0F9188F13CB7B2C71F2A335E3A4FC328BF5BEB436012AFCA590B1A11466E2206")
    assert {:ok, ref} = C.spend(:bs, hash, 1)
    assert_receive {:libbitcoin_client_error, "blockchain.fetch_spend", ^ref, :not_found}, @timeout
  end

  test "transaction_pool.fetch_transaction" do
    {:ok, hash} = Base.decode16("0F9188F13CB7B2C71F2A335E3A4FC328BF5BEB436012AFCA590B1A11466E2206")
    assert {:ok, ref} = C.blockchain_transaction(:bs, hash)
    assert_receive {:libbitcoin_client_error, "blockchain.fetch_transaction", ^ref, :not_found}, @timeout
  end

  test "transaction_pool.validate" do
    {:ok, tx} = Base.decode16("0100000001ACA7F3B45654C230E0886A57FB988C3044EF5E8F7F39726D305C61D5E818903C00000000FD5D010048304502200187AF928E9D155C4B1AC9C1C9118153239ABA76774F775D7C1F9C3E106FF33C0221008822B0F658EDEC22274D0B6AE9DE10EBF2DA06B1BBDAABA4E50EB078F39E3D78014730440220795F0F4F5941A77AE032ECB9E33753788D7EB5CB0C78D805575D6B00A1D9BFED02203E1F4AD9332D1416AE01E27038E945BC9DB59C732728A383A6F1ED2FB99DA7A4014CC952410491BBA2510912A5BD37DA1FB5B1673010E43D2C6D812C514E91BFA9F2EB129E1C183329DB55BD868E209AAC2FBC02CB33D98FE74BF23F0C235D6126B1D8334F864104865C40293A680CB9C020E7B1E106D8C1916D3CEF99AA431A56D253E69256DAC09EF122B1A986818A7CB624532F062C1D1F8722084861C5C3291CCFFEF4EC687441048D2455D2403E08708FC1F556002F1B6CD83F992D085097F9974AB08A28838F07896FBAB08F39495E15FA6FAD6EDBFB1E754E35FA1C7844C41F322A1863D4621353AEFFFFFFFF0140420F00000000001976A914AE56B4DB13554D321C402DB3961187AED1BBED5B88AC00000000")
    assert {:ok, ref} = C.validate(:bs, tx)
    assert_receive {:libbitcoin_client_error, "transaction_pool.validate", ^ref, :not_found}, @timeout
  end

  test "transaction_pool.validate2" do
    {:ok, tx} = Base.decode16("0100000001ACA7F3B45654C230E0886A57FB988C3044EF5E8F7F39726D305C61D5E818903C00000000FD5D010048304502200187AF928E9D155C4B1AC9C1C9118153239ABA76774F775D7C1F9C3E106FF33C0221008822B0F658EDEC22274D0B6AE9DE10EBF2DA06B1BBDAABA4E50EB078F39E3D78014730440220795F0F4F5941A77AE032ECB9E33753788D7EB5CB0C78D805575D6B00A1D9BFED02203E1F4AD9332D1416AE01E27038E945BC9DB59C732728A383A6F1ED2FB99DA7A4014CC952410491BBA2510912A5BD37DA1FB5B1673010E43D2C6D812C514E91BFA9F2EB129E1C183329DB55BD868E209AAC2FBC02CB33D98FE74BF23F0C235D6126B1D8334F864104865C40293A680CB9C020E7B1E106D8C1916D3CEF99AA431A56D253E69256DAC09EF122B1A986818A7CB624532F062C1D1F8722084861C5C3291CCFFEF4EC687441048D2455D2403E08708FC1F556002F1B6CD83F992D085097F9974AB08A28838F07896FBAB08F39495E15FA6FAD6EDBFB1E754E35FA1C7844C41F322A1863D4621353AEFFFFFFFF0140420F00000000001976A914AE56B4DB13554D321C402DB3961187AED1BBED5B88AC00000000")
    assert {:ok, ref} = C.validate2(:bs, tx)
    assert_receive {:libbitcoin_client, "transaction_pool.validate2", ^ref, :input_not_found}, @timeout
  end

  test "blockchain.validate" do
    {:ok, tx} = Base.decode16("0100000000000000000000000000000000000000000000000000000000000000000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4ADAE5494DFFFF7F20020000000101000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000")
    assert {:ok, ref} = C.blockchain_validate(:bs, tx)
    assert_receive {:libbitcoin_client_error, "blockchain.validate", ^ref, nil}, @timeout
  end

  test "address.fetch_history" do
    assert {:ok, ref} = C.address_history(:bs, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S", 0)
    assert_receive {:libbitcoin_client_error, "address.fetch_history", ^ref, :not_found}, @timeout
  end

  test "address.fetch_history2" do
    assert {:ok, ref} = C.address_history2(:bs, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S", 0)
    assert_receive {:libbitcoin_client_error, "address.fetch_history2", ^ref, :not_found}, @timeout
  end

  test "blockchain.blockchain_history" do
    assert {:ok, ref} = C.blockchain_history(:bs, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S", 0)
    assert_receive {:libbitcoin_client_error, "blockchain.fetch_history", ^ref, :not_found}, @timeout
  end

  @tag v3: true
  test "blockchain.fetch_history3" do
    assert {:ok, ref} = C.blockchain_history3(:bs, "myYdD65ERzsmBxfJgjgcBBTXtyS5jM4Xex", 0)
    assert_receive {:libbitcoin_client, "blockchain.fetch_history3", ^ref, []}, @timeout
  end

  test "blockchain.fetch_stealth" do
    assert {:ok, ref} = C.stealth(:bs, "11111111111111111111111111111111", 0)
    assert_receive {:libbitcoin_client_error, "blockchain.fetch_stealth", ^ref, :not_found}, @timeout
  end

  test "blockchain.fetch_stealth2" do
    assert {:ok, ref} = C.stealth2(:bs, "11111111111111111111111111111111", 0)
    assert_receive {:libbitcoin_client, "blockchain.fetch_stealth2", ^ref, []}, @timeout 
  end

  test "protocol.total_connections" do
    assert {:ok, ref} = C.total_connections(:bs)
    assert_receive {:libbitcoin_client_error, _, ^ref, :not_found}, @timeout
  end

  test "protocol.broadcast_transaction" do
    {:ok, tx} = Base.decode16("0100000001ACA7F3B45654C230E0886A57FB988C3044EF5E8F7F39726D305C61D5E818903C00000000FD5D010048304502200187AF928E9D155C4B1AC9C1C9118153239ABA76774F775D7C1F9C3E106FF33C0221008822B0F658EDEC22274D0B6AE9DE10EBF2DA06B1BBDAABA4E50EB078F39E3D78014730440220795F0F4F5941A77AE032ECB9E33753788D7EB5CB0C78D805575D6B00A1D9BFED02203E1F4AD9332D1416AE01E27038E945BC9DB59C732728A383A6F1ED2FB99DA7A4014CC952410491BBA2510912A5BD37DA1FB5B1673010E43D2C6D812C514E91BFA9F2EB129E1C183329DB55BD868E209AAC2FBC02CB33D98FE74BF23F0C235D6126B1D8334F864104865C40293A680CB9C020E7B1E106D8C1916D3CEF99AA431A56D253E69256DAC09EF122B1A986818A7CB624532F062C1D1F8722084861C5C3291CCFFEF4EC687441048D2455D2403E08708FC1F556002F1B6CD83F992D085097F9974AB08A28838F07896FBAB08F39495E15FA6FAD6EDBFB1E754E35FA1C7844C41F322A1863D4621353AEFFFFFFFF0140420F00000000001976A914AE56B4DB13554D321C402DB3961187AED1BBED5B88AC00000000")
    assert {:ok, ref} = C.broadcast_transaction(:bs, tx)
    assert_receive {:libbitcoin_client_error, "protocol.broadcast_transaction", ^ref, :not_found} when is_binary(tx), @timeout
  end

  test "transaction_pool.broadcast" do
    {:ok, tx} = Base.decode16("0100000001ACA7F3B45654C230E0886A57FB988C3044EF5E8F7F39726D305C61D5E818903C00000000FD5D010048304502200187AF928E9D155C4B1AC9C1C9118153239ABA76774F775D7C1F9C3E106FF33C0221008822B0F658EDEC22274D0B6AE9DE10EBF2DA06B1BBDAABA4E50EB078F39E3D78014730440220795F0F4F5941A77AE032ECB9E33753788D7EB5CB0C78D805575D6B00A1D9BFED02203E1F4AD9332D1416AE01E27038E945BC9DB59C732728A383A6F1ED2FB99DA7A4014CC952410491BBA2510912A5BD37DA1FB5B1673010E43D2C6D812C514E91BFA9F2EB129E1C183329DB55BD868E209AAC2FBC02CB33D98FE74BF23F0C235D6126B1D8334F864104865C40293A680CB9C020E7B1E106D8C1916D3CEF99AA431A56D253E69256DAC09EF122B1A986818A7CB624532F062C1D1F8722084861C5C3291CCFFEF4EC687441048D2455D2403E08708FC1F556002F1B6CD83F992D085097F9974AB08A28838F07896FBAB08F39495E15FA6FAD6EDBFB1E754E35FA1C7844C41F322A1863D4621353AEFFFFFFFF0140420F00000000001976A914AE56B4DB13554D321C402DB3961187AED1BBED5B88AC00000000")
    assert {:ok, ref} = C.transaction_pool_broadcast(:bs, tx)
    assert_receive {:libbitcoin_client, "transaction_pool.broadcast", ^ref, :input_not_found} when is_binary(tx), @timeout
  end

  test "encode_stealth" do
    assert "ba80" = C.encode_stealth("101110101") |> Base.encode16(case: :lower)
    assert "a680" = C.encode_stealth("101001101") |> Base.encode16(case: :lower)
    assert "bae0" = C.encode_stealth("10111010111") |> Base.encode16(case: :lower)
    assert "fff8c0" = C.encode_stealth("111111111111100011") |> Base.encode16(case: :lower)
  end

  test "spend_checksum v1" do
    hash = Base.decode16!("ab00248cd12452c2c45be7ca91899fd8e174595b4d16e2f2e3c92dedbb1d8cea", case: :lower)
    assert C.spend_checksum_v1(hash, 0) == 7190328776004206592
  end

  test "call" do
    {:ok, hash} = Base.decode16("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert {:ok, _} = C.call(:bs, "blockchain.fetch_last_height", [])
    assert {:error, :not_found} = C.call(:bs, "blockchain.fetch_transaction", [hash])
  end

  test "cast" do
    {:ok, hash} = Base.decode16("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert {:ok, _ref} = C.cast(:bs, "blockchain.fetch_last_height", [])
    assert {:ok, _ref} = C.cast(:bs, "blockchain.fetch_transaction", [hash])
    assert_receive {:libbitcoin_client, "blockchain.fetch_last_height", _, _}, @timeout
    assert_receive {:libbitcoin_client_error, "blockchain.fetch_transaction", _, :not_found}, @timeout
  end
end
