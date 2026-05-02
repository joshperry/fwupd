host_machine.system() == 'linux' or subdir_done()

cargs = ['-DG_LOG_DOMAIN="FuPluginDellMonitorRt"']
plugins += {meson.current_source_dir().split('/')[-1]: true}

plugin_quirks += files('dell-monitor-rt.quirk')
plugin_builtins += static_library('fu_plugin_dell_monitor_rt',
  sources: [
    'fu-dell-monitor-rt-device.c',
    'fu-dell-monitor-rt-firmware.c',
    'fu-dell-monitor-rt-firmware-component.c',
    'fu-dell-monitor-rt-plugin.c',
  ],
  include_directories: plugin_incdirs,
  link_with: plugin_libs,
  c_args: cargs,
  dependencies: plugin_deps,
)
