local sample_projects = {
  "simple_client",
  "simple_server",
  "allocator_bench",
  "p2p_smoke",
  "p2p_demo",
  "file_transfer_demo",
  "handshake_integration",
}

for _, sample in ipairs(sample_projects) do
  if os.isdir(sample) then
    include(sample)
  else
    print("Skipping missing sample project: " .. sample)
  end
end
