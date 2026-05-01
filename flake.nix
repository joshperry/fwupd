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

        # Build *this* source tree using nixpkgs' fwupd derivation as the
        # base. Inheriting from pkgs.fwupd means we get the same patches
        # (e.g., NixOS-friendly install paths), the same dependency
        # closure, and the same configure flags — we just swap in our
        # source tree. This is what `nix build` produces.
        fwupd-dev = pkgs.fwupd.overrideAttrs (old: {
          version = "dev-${self.shortRev or "dirty"}";
          src = self;
          # Skip the upstream release-tarball checksum since we're using
          # the local tree. doCheck stays on so the test suite still runs.
          doCheck = old.doCheck or false;
        });

        # Convenience handle for things that just want the bin dir.
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
            --localstatedir="$PWD/build/_local" \
            --sysconfdir="$PWD/build/_etc" \
            --buildtype=debug \
            "$@"
          mkdir -p "$PWD/build/_local" "$PWD/build/_etc"
          echo
          echo "Built. To compile:"
          echo "  meson compile -C build"
          echo "To run a single plugin's tests once they exist:"
          echo "  meson test -C build dell-monitor-rt"
        '';

        # Stage the built quirks where the dev-mode fwupdtool will look
        # at runtime: <localstatedir>/lib/fwupd/quirks.d/builtin.quirk.gz.
        # Without this, our plugin's quirk file isn't visible to fwupdtool
        # and the device never gets matched.
        stageQuirksScript = pkgs.writeShellScriptBin "fwupd-stage-quirks" ''
          set -euo pipefail
          : "''${MESON_BUILD_DIR:=build}"
          ninja -C "$MESON_BUILD_DIR" builtin.quirk.gz >/dev/null
          # builtin.quirk.gz lives at the top of the build tree
          install -Dm644 \
            "$MESON_BUILD_DIR/builtin.quirk.gz" \
            "$MESON_BUILD_DIR/_local/lib/fwupd/quirks.d/builtin.quirk.gz"
          echo "staged $MESON_BUILD_DIR/_local/lib/fwupd/quirks.d/builtin.quirk.gz"
        '';
      in
      {
        # Run/install: the full fwupd, built from this source tree, with
        # our in-progress plugin compiled in alongside the in-tree ones.
        # Use this when you want a clean reproducible build:
        #   nix build       → ./result/bin/fwupdtool …
        #   nix run . -- get-devices
        packages.default = fwupd-dev;
        packages.fwupd = fwupd-dev;

        # Fast inner-loop development. Use this for protocol work where
        # every keystroke iteration matters — meson builds are seconds,
        # nix builds are minutes.
        devShells.default = pkgs.mkShell {
          name = "fwupd-dev";

          inputsFrom = [ upstreamFwupd ];

          packages = with pkgs; [
            mesonConfigureScript
            stageQuirksScript

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

Two build modes:

  Clean build (slow, reproducible):
    nix build              # fwupd at ./result, with our plugin baked in
    sudo ./result/bin/fwupdtool get-devices

  Inner-loop dev (fast, incremental):
    fwupd-configure                      # one-time meson setup
    meson compile -C build               # iterative build (seconds)
    fwupd-stage-quirks                   # after editing a .quirk file
    sudo build/src/fwupdtool get-devices
    meson test -C build dell-monitor-rt  # once we have tests

In-development plugin: plugins/dell-monitor-rt/

EOF
          '';
        };
      });
}
