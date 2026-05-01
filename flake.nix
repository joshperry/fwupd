{
  description = "fwupd, with the in-development dell-monitor-rt plugin";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Inherit fwupd's full build dependency closure from nixpkgs so the
        # dev shell can configure and build this source tree the same way
        # nixpkgs builds the upstream release.
        upstreamFwupd = pkgs.fwupd;

        # Mirror the meson flags nixpkgs uses, minus a few that only matter
        # at install/package time.
        mesonConfigureScript = pkgs.writeShellScriptBin "fwupd-configure" ''
          set -euo pipefail
          rm -rf build
          meson setup build \
            -Ddocs=disabled \
            -Dman=false \
            -Dtests=false \
            -Dpassim=disabled \
            -Dplugin_modem_manager=disabled \
            -Dplugin_uefi_capsule_splash=false \
            -Dvendor_ids_dir=${pkgs.hwdata}/share/hwdata \
            -Dumockdev_tests=disabled \
            --buildtype=debug \
            "$@"
          echo
          echo "Built. To compile:"
          echo "  meson compile -C build"
          echo "To run a single plugin's tests once they exist:"
          echo "  meson test -C build dell-monitor-rt"
        '';
      in
      {
        devShells.default = pkgs.mkShell {
          name = "fwupd-dev";

          inputsFrom = [ upstreamFwupd ];

          packages = with pkgs; [
            mesonConfigureScript

            # Code intelligence
            clang-tools          # clangd, clang-format
            ccls

            # Reverse-engineering / runtime tracing
            radare2
            wireshark-cli        # tshark for re-analyzing pcaps
            ddcutil              # confirm DDC/CI access to the monitor
            usbutils             # lsusb -t / -v
            dpkg                 # extract Dell's .deb for protocol cross-check

            # Debug + memory tools
            gdb
            valgrind

            # Misc
            (python3.withPackages (p: with p; [ jinja2 pygobject3 setuptools ]))
            jq
            ripgrep
            fd
          ];

          shellHook = ''
            cat <<EOF

=== fwupd dev shell ===
  branch:  $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo n/a)
  meson:   $(meson --version 2>/dev/null)
  ninja:   $(ninja --version 2>/dev/null)
  gcc:     $(gcc --version 2>/dev/null | head -1)
  fwupd:   nixpkgs ${upstreamFwupd.version} (for dep closure only —
                   we build from this source tree)

Workflow:
  fwupd-configure          # runs meson setup with the right flags
  meson compile -C build
  meson test -C build dell-monitor-rt   # once we have tests

In-development plugin: plugins/dell-monitor-rt/

EOF
          '';
        };
      });
}
