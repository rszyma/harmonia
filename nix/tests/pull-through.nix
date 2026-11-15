{ pkgs, self }:
let
  cacheKey = pkgs.lib.removeSuffix "\n" (builtins.readFile ../../tests/cache.pk);
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
      };

    cache =
      { ... }:
      {
        imports = [ self.nixosModules.harmonia ];

        services.harmonia-dev.cache.enable = true;
        services.harmonia-dev.cache.pullThrough = {
          enable = true;
          upstreamCaches = [ "http://upstream:5000" ];
        };

        # The pull-through import (`nix copy --from <upstream>`) verifies
        # upstream signatures through this node's trust roots.
        nix.settings.trusted-public-keys = [
          "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
          cacheKey
        ];

        networking.firewall.allowedTCPPorts = [ 5000 ];
      };

    client =
      { lib, ... }:
      {
        nix.settings.require-sigs = false;
        nix.settings.substituters = lib.mkForce [ "http://cache:5000" ];
        nix.extraOptions = ''
          experimental-features = nix-command
        '';
      };
  };

  testScript = ''
    import time

    start_all()

    client.wait_until_succeeds("timeout 1 curl -f http://cache:5000")
    client.succeed("curl -f http://cache:5000/nix-cache-info")

    # Create a path that exists nowhere else: guest-local store, random
    # content. (`test -e` cannot prove absence — guests see the shared host
    # store read-only — so the path must be unique to this run.)
    storepath = upstream.succeed(
        "echo probe-$(date +%s%N)-$RANDOM > /tmp/probe && nix-store --add /tmp/probe"
    ).strip()
    assert storepath.startswith("/nix/store/"), f"not a store path: {storepath}"

    # Sanity: the pull-through cache must not have it yet (--offline: no
    # substitution, local validity only).
    cache.fail(f"nix path-info --offline {storepath}")

    # Fetch through the pull-through cache: streams to the client and
    # imports into the cache's store in the background.
    client.wait_until_succeeds(f"nix copy --from http://cache:5000/ {storepath}")

    # The import must have landed in the cache's store. Before the service
    # had a writable HOME, its `nix copy` died with
    # `creating directory "/.cache/nix": Read-only file system` and this
    # never appeared.
    ok = False
    for _ in range(60):
        try:
            cache.succeed(f"nix path-info --offline {storepath}")
            ok = True
            break
        except Exception:
            time.sleep(1)
    print(cache.succeed("journalctl -u harmonia-dev --no-pager | tail -40"))
    assert ok, f"import of {storepath} never landed in the cache store"
  '';
}
