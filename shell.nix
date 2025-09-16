{ pkgs ? import <nixpkgs> {} }:

let
  dotnetSdk9 = pkgs.dotnet-sdk_9;
  dotnetSdk8 = pkgs.dotnet-sdk_8;

  dotnetRoot = pkgs.runCommand "dotnet-root" {} ''
    set -eu

    mkdir -p $out/share
    cp -r ${dotnetSdk9}/share/dotnet $out/share/

    copyVersioned() {
      src="$1"
      dest="$2"

      if [ -d "$src" ]; then
        mkdir -p "$dest"

        for component in "$src"/8.*; do
          if [ -e "$component" ]; then
            cp -r "$component" "$dest/"
          fi
        done
      fi
    }

    copyNested() {
      src="$1"
      dest="$2"

      if [ -d "$src" ]; then
        for parent in "$src"/*; do
          if [ -d "$parent" ]; then
            name="$(basename "$parent")"
            mkdir -p "$dest/$name"

            for component in "$parent"/8.*; do
              if [ -e "$component" ]; then
                cp -r "$component" "$dest/$name/"
              fi
            done
          fi
        done
      fi
    }

    copyVersioned ${dotnetSdk8}/share/dotnet/sdk $out/share/dotnet/sdk
    copyVersioned ${dotnetSdk8}/share/dotnet/host/fxr $out/share/dotnet/host/fxr
    copyVersioned ${dotnetSdk8}/share/dotnet/shared/Microsoft.NETCore.App $out/share/dotnet/shared/Microsoft.NETCore.App
    copyVersioned ${dotnetSdk8}/share/dotnet/shared/Microsoft.AspNetCore.App $out/share/dotnet/shared/Microsoft.AspNetCore.App
    copyVersioned ${dotnetSdk8}/share/dotnet/shared/Microsoft.WindowsDesktop.App $out/share/dotnet/shared/Microsoft.WindowsDesktop.App
    copyVersioned ${dotnetSdk8}/share/dotnet/templates $out/share/dotnet/templates
    copyVersioned ${dotnetSdk8}/share/dotnet/sdk-manifests $out/share/dotnet/sdk-manifests
    copyNested ${dotnetSdk8}/share/dotnet/packs $out/share/dotnet/packs
  '';

  cacert = pkgs.cacert;
in
pkgs.mkShell {
  packages = [
    dotnetSdk9
    cacert
  ];

  DOTNET_ROOT = "${dotnetRoot}/share/dotnet";
  DOTNET_CLI_TELEMETRY_OPTOUT = "1";
  DOTNET_NOLOGO = "1";
  DOTNET_ROLL_FORWARD = "Major";
  SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";

  shellHook = ''
    repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
    export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-$repo_root/.dotnet}"
    export PATH="$DOTNET_CLI_HOME/tools:$PATH"

    props_file="$repo_root/properties/GirCore.Fuzzing.props"

    if [ -f "$props_file" ]; then
      SHARPFUZZ_VERSION=$(sed -n 's/.*<SharpFuzzVersion>\(.*\)<\/SharpFuzzVersion>.*/\1/p' "$props_file" | head -n 1)
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
        INSTALLED_VERSION=$("$DOTNET_CLI_HOME/tools/sharpfuzz" --version 2>/dev/null | sed -n 's/[^0-9]*\([0-9][0-9.]*\).*/\1/p' | head -n 1)

        if [ "$INSTALLED_VERSION" != "$SHARPFUZZ_VERSION" ]; then
          dotnet tool update SharpFuzz.CommandLine --tool-path "$DOTNET_CLI_HOME/tools" --version "$SHARPFUZZ_VERSION"
        fi
      fi
    fi
  '';
}
