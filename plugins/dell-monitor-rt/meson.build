host_machine.system() == 'linux' or subdir_done()

cargs = ['-DG_LOG_DOMAIN="FuPluginDellMonitorRt"']
plugins += {meson.current_source_dir().split('/')[-1]: true}

# Wistron's .upg binary payloads are ECIES-encrypted with a non-standard
# CryptoPP cipher suite over secp521r1. Use nettle (already a transitive
# dependency via GnuTLS) for the EC scalar multiplication and SHA3-512.
nettle_dep = dependency('nettle', version: '>= 3.4')
hogweed_dep = dependency('hogweed', version: '>= 3.4')
gmp_dep = dependency('gmp')

plugin_quirks += files('dell-monitor-rt.quirk')
plugin_builtins += static_library('fu_plugin_dell_monitor_rt',
  sources: [
    'fu-dell-monitor-rt-crypto.c',
    'fu-dell-monitor-rt-device.c',
    'fu-dell-monitor-rt-ecies.c',
    'fu-dell-monitor-rt-firmware.c',
    'fu-dell-monitor-rt-firmware-component.c',
    'fu-dell-monitor-rt-plugin.c',
  ],
  include_directories: plugin_incdirs,
  link_with: plugin_libs,
  c_args: cargs,
  dependencies: plugin_deps + [nettle_dep, hogweed_dep, gmp_dep],
)
