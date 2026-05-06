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

        # End-to-end emulation runner for the dell-monitor-rt plugin.
        # Assembles the test cab from the in-tree metainfo + the .upg
        # firmware blob in the dell-u4025qw-fw companion repo, then
        # drives `fwupdtool emulation-load` against the local fixture
        # zip. Idempotent: skips the steps whose outputs already exist.
        #
        # Designed for inner-loop work on plugins/dell-monitor-rt/. The
        # plugin keeps a write_firmware safety guard that refuses to run
        # without FWUPD_DEVICE_FLAG_EMULATED on its device, so even if
        # the fixture mismatches at the BackendId level the install
        # aborts before any IO can leak to real hardware.
        runEmuScript = pkgs.writeShellScriptBin "dell-monitor-rt-emu" ''
          set -euo pipefail

          : "''${MESON_BUILD_DIR:=build}"
          plugin_dir="plugins/dell-monitor-rt"
          tests_dir="$plugin_dir/tests"

          # Prefer locations relative to the fwupd checkout; fall back to
          # a sibling clone of dell-u4025qw-fw next to fwupd's parent.
          companion_default="''${DELL_U4025QW_FW_DIR:-../dell-u4025qw-fw}"
          upg_default="$companion_default/extracted/usr/share/Dell/firmware/U4025QW/M3T105/DELL_U4025QW_LGD_4FCF2_M3T105_20251009.upg"
          pcap_default="$companion_default/captures/u4025qw-update-recap-20260502-185321.pcapng"

          metainfo="$tests_dir/u4025qw-test.metainfo.xml"
          upg="''${DELL_U4025QW_UPG:-$upg_default}"
          pcap="''${DELL_U4025QW_PCAP:-$pcap_default}"
          specializer="$plugin_dir/contrib/pcap-to-fixture.py"

          # Cab + fixture + firmware-blob staging area live under the
          # meson build tree so they get cleaned by `rm -rf build`. The
          # fixture lives here too — never use the committed
          # tests/u4025qw-emulation.zip for runs (it's a snapshot kept for
          # reference; pcap-to-fixture.py output is the source of truth
          # because the specializer evolves alongside the plugin and the
          # fixture must match the plugin's current event expectations).
          stage="$MESON_BUILD_DIR/_dell-monitor-rt-emu"
          firmware_blob="$stage/firmware.bin"
          cab="$stage/u4025qw-test.cab"
          fixture="$stage/u4025qw-emulation.zip"

          # Sanity checks before doing anything expensive
          if [[ ! -f "$metainfo" ]]; then
            echo "missing test asset: $metainfo" >&2
            exit 1
          fi
          if [[ ! -f "$upg" ]]; then
            echo "missing .upg firmware blob: $upg" >&2
            echo "  set DELL_U4025QW_UPG to override, or clone" >&2
            echo "  https://github.com/joshperry/dell-u4025qw-fw next to this checkout" >&2
            exit 1
          fi
          if [[ ! -f "$pcap" ]]; then
            echo "missing capture pcap: $pcap" >&2
            echo "  set DELL_U4025QW_PCAP to override, or clone" >&2
            echo "  https://github.com/joshperry/dell-u4025qw-fw next to this checkout" >&2
            exit 1
          fi

          mkdir -p "$stage"

          # Regenerate the fixture if missing or stale relative to the
          # specializer or pcap. The specializer owns the wire format
          # (Report-ID prefix, phase split at 0xE9, structural-event
          # propagation, stable Created timestamps), so any change to
          # either input must invalidate the cached fixture.
          if [[ ! -f "$fixture" || \
                "$pcap" -nt "$fixture" || \
                "$specializer" -nt "$fixture" ]]; then
            echo "regenerating $fixture from $pcap"
            python3 "$specializer" "$pcap" "$fixture"
          else
            echo "fixture up-to-date: $fixture"
          fi

          # Stage the .upg as firmware.bin so build-cabinet picks it up
          # under the name our metainfo.xml references.
          if [[ ! -f "$firmware_blob" || "$upg" -nt "$firmware_blob" ]]; then
            echo "staging $upg -> $firmware_blob"
            install -m644 "$upg" "$firmware_blob"
          fi

          # Build the cab if missing, or if either input is newer.
          if [[ ! -f "$cab" || "$firmware_blob" -nt "$cab" || "$metainfo" -nt "$cab" ]]; then
            echo "building $cab"
            rm -f "$cab"
            "$MESON_BUILD_DIR/src/fwupdtool" build-cabinet \
              "$cab" "$firmware_blob" "$metainfo"
          else
            echo "cab up-to-date: $cab"
          fi

          # Run the emulator. --allow-older lets us replay against a cab
          # that targets the pre-update version; --allow-reinstall lets
          # us replay even when the fixture's emulated device starts at
          # the same version the cab carries.
          echo "running emulation-load against $fixture"
          exec "$MESON_BUILD_DIR/src/fwupdtool" emulation-load \
            "$fixture" "$cab" \
            --plugins dell_monitor_rt \
            --allow-older \
            --allow-reinstall \
            "$@"
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
            runEmuScript

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

  Plugin emulation (no real hardware touched):
    dell-monitor-rt-emu                  # build cab + run emulation-load
    dell-monitor-rt-emu --verbose        # extra args pass through

In-development plugin: plugins/dell-monitor-rt/

EOF
          '';
        };
      });
}
