{ pkgs ? import <nixpkgs> {} }:

let
  dotnetSdk = pkgs.dotnet-sdk_9;
  cacert = pkgs.cacert;
in
pkgs.mkShell {
  packages = [
    dotnetSdk
    cacert
  ];

  DOTNET_ROOT = "${dotnetSdk}/share/dotnet";
  DOTNET_CLI_TELEMETRY_OPTOUT = "1";
  DOTNET_NOLOGO = "1";
  SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";

  shellHook = ''
    repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
    export DOTNET_CLI_HOME="''${DOTNET_CLI_HOME:-$repo_root/.dotnet}"
    export PATH="$DOTNET_CLI_HOME/tools:$PATH"

    props_file="$repo_root/properties/GirCore.Fuzzing.props"

    if [ -f "$props_file" ]; then
      SHARPFUZZ_VERSION=$(sed -n 's|.*<SharpFuzzVersion>\(.*\)</SharpFuzzVersion>.*|\1|p' "$props_file" | head -n 1)
    else
      SHARPFUZZ_VERSION=""
    fi

    if [ -z "$SHARPFUZZ_VERSION" ]; then
      echo "warning: unable to determine SharpFuzzVersion from $props_file" >&2
    else
      mkdir -p "$DOTNET_CLI_HOME/tools"

      if [ ! -x "$DOTNET_CLI_HOME/tools/sharpfuzz" ]; then
        dotnet tool install SharpFuzz.CommandLine --tool-path "$DOTNET_CLI_HOME/tools" --version "$SHARPFUZZ_VERSION"
      else
        INSTALLED_VERSION=$("$DOTNET_CLI_HOME/tools/sharpfuzz" --version 2>/dev/null | awk 'NF { print $NF; exit }')

        if [ "$INSTALLED_VERSION" != "$SHARPFUZZ_VERSION" ]; then
          dotnet tool update SharpFuzz.CommandLine --tool-path "$DOTNET_CLI_HOME/tools" --version "$SHARPFUZZ_VERSION"
        fi
      fi
    fi
  '';
}
