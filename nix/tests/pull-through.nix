{ pkgs, self }:
let
  cacheKey = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../tests/cache.pk);
  # A two-path closure that only the upstream node has.
  dep = pkgs.writeText "pull-through-dep" "dependency";
  top = pkgs.runCommand "pull-through-top" { } ''
    echo ${dep} > $out
  '';
  hashPart = pkg: builtins.substring (builtins.stringLength builtins.storeDir + 1) 32 pkg.outPath;
in
pkgs.testers.nixosTest {
  name = "pull-through";

  nodes = {
    upstream =
      { ... }:
      {
        imports = [ self.nixosModules.harmonia ];
        services.harmonia-dev.cache.enable = true;
        services.harmonia-dev.cache.signKeyPaths = [ "${../../tests/cache.sk}" ];
        networking.firewall.allowedTCPPorts = [ 5000 ];
        system.extraDependencies = [ top ];
      };

    cache =
      { ... }:
      {
        imports = [ self.nixosModules.harmonia ];
        services.harmonia-dev.cache = {
          enable = true;
          pullThrough = {
            enable = true;
            upstreamCaches = [ "http://upstream:5000" ];
            cancelOnDisconnect = true;
          };
        };
        # The daemon checks the upstream signatures on import.
        nix.settings.trusted-public-keys = [ cacheKey ];
        networking.firewall.allowedTCPPorts = [ 5000 ];
      };

    client =
      { lib, ... }:
      {
        nix.settings.substituters = lib.mkForce [ "http://cache:5000" ];
        nix.settings.trusted-public-keys = [ cacheKey ];
        nix.extraOptions = ''
          experimental-features = nix-command
        '';
      };
  };

  testScript = ''
    start_all()
    upstream.wait_for_unit("harmonia-dev.socket")
    cache.wait_for_unit("harmonia-dev.socket")
    client.wait_until_succeeds("curl -sf http://cache:5000/nix-cache-info")

    for path in ["${top}", "${dep}"]:
        cache.fail(f"nix-store --check-validity {path}")
        client.fail(f"nix-store --check-validity {path}")

    cold = client.succeed("curl -sf http://cache:5000/${hashPart top}.narinfo")
    print(cold)
    assert "Compression: none" in cold, cold
    assert "?hash=${hashPart top}" in cold, cold

    client.succeed("nix copy --from http://cache:5000 ${top}")
    client.succeed("nix-store --check-validity ${top} ${dep}")
    assert client.succeed("cat ${top}").strip() == "${dep}"

    # The closure lands in the cache's store, with the upstream signature.
    cache.wait_until_succeeds("nix-store --check-validity ${top} ${dep}", timeout=60)
    sigs = cache.succeed("nix path-info --extra-experimental-features nix-command --sigs ${top}")
    assert "cache.example.com-1:" in sigs, sigs

    # Served locally now, in the same format.
    warm = client.succeed("curl -sf http://cache:5000/${hashPart top}.narinfo")
    assert cold == warm, f"{cold!r} != {warm!r}"

    print(cache.succeed("journalctl -u harmonia-dev --no-pager | grep pull-through"))
  '';
}
