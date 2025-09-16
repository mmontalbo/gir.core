{ pkgs ? import <nixpkgs> {} }:

let
  dotnetSdk = pkgs.dotnet-sdk_9;
  dotnetRuntime8 = pkgs.dotnet-runtime_8;
  dotnetRoot = pkgs.buildEnv {
    name = "dotnet-root";
    paths = [ dotnetSdk dotnetRuntime8 ];
    pathsToLink = [ "/share/dotnet" ];
  };
in
pkgs.mkShell {
  packages = [
    dotnetSdk
    dotnetRuntime8
  ];

  DOTNET_ROOT = "${dotnetRoot}/share/dotnet";
  SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

  shellHook = ''
    export DOTNET_CLI_HOME="$PWD/.dotnet"
    export PATH="$DOTNET_CLI_HOME/tools:$PATH"

    if [ -f "properties/GirCore.Fuzzing.props" ]; then
      SHARPFUZZ_VERSION=$(sed -n 's/.*<SharpFuzzVersion>\(.*\)<\/SharpFuzzVersion>.*/\1/p' properties/GirCore.Fuzzing.props | head -n 1)
    else
      SHARPFUZZ_VERSION=""
    fi

    if [ -z "$SHARPFUZZ_VERSION" ]; then
      echo "warning: unable to determine SharpFuzzVersion from properties/GirCore.Fuzzing.props" >&2
    else
      mkdir -p "$DOTNET_CLI_HOME/tools"

      if [ ! -x "$DOTNET_CLI_HOME/tools/sharpfuzz" ]; then
        dotnet tool install SharpFuzz.CommandLine --tool-path "$DOTNET_CLI_HOME/tools" --version "$SHARPFUZZ_VERSION"
      else
        INSTALLED_VERSION=$("$DOTNET_CLI_HOME/tools/sharpfuzz" --version 2>/dev/null | sed -n 's/[^0-9]*\([0-9][0-9.]*\).*/\1/p' | head -n 1)

        if [ "$INSTALLED_VERSION" != "$SHARPFUZZ_VERSION" ]; then
          dotnet tool update SharpFuzz.CommandLine --tool-path "$DOTNET_CLI_HOME/tools" --version "$SHARPFUZZ_VERSION"
        fi
      fi
    fi
  '';
}
