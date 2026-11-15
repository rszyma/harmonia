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
        system.extraDependencies = [
          pkgs.hello
        ];
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
    start_all()

    client.wait_until_succeeds("timeout 1 curl -f http://cache:5000")
    client.succeed("curl -f http://cache:5000/nix-cache-info")

    # Warm the upstream so the pull-through cache starts out missing the path.
    upstream.succeed("test -e ${pkgs.hello}")
    cache.fail("test -e ${pkgs.hello}")

    # Fetch through the pull-through cache: streams to the client and
    # imports into the cache's store in the background.
    client.wait_until_succeeds("nix copy --from http://cache:5000/ ${pkgs.hello}")
    client.succeed("${pkgs.hello}/bin/hello")

    # The import must have landed in the cache's store. Before the service
    # had a writable HOME, its `nix copy` died with
    # `creating directory "/.cache/nix": Read-only file system` and this
    # never appeared.
    cache.wait_until_succeeds("test -e ${pkgs.hello}")
  '';
}
