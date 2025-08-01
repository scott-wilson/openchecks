project(
  'copenchecks',
  'c',
  version: '0.2.0',
  default_options: ['warning_level=3'],
)

cargo_toml = meson.project_source_root() / 'Cargo.toml'
cargo = find_program('cargo')
cargo_wrapper = find_program('meson/cargo_wrapper.py', native: true)
cc = meson.get_compiler('c')
host_system = host_machine.system()
is_msvc_style = cc.get_argument_syntax() == 'msvc' or cc.get_define('_MSC_VER') != ''
release_mode = get_option('debug') ? 'debug' : 'release'
build_tests = get_option('tests')
build_fuzz = get_option('fuzz')

if host_system == 'windows'
  lib_prefix = is_msvc_style ? '' : 'lib'
  dynamic_ext = 'dll'
  static_ext = is_msvc_style ? 'lib' : 'a'
elif host_system in ['darwin', 'ios']
  lib_prefix = 'lib'
  dynamic_ext = 'dylib'
  static_ext = 'a'
else
  lib_prefix = 'lib'
  dynamic_ext = 'so'
  static_ext = 'a'
endif

if is_msvc_style
  rust_c_artifacts = custom_target(
    meson.project_name(),
    build_by_default: true,
    output: [
      '@0@copenchecks.@1@'.format(lib_prefix, dynamic_ext),
      '@0@copenchecks.@1@'.format(lib_prefix, static_ext),
      '@0@copenchecks.dll.lib'.format(lib_prefix, static_ext),
    ],
    console: true,
    install: true,
    install_dir: get_option('libdir'),
    command: [
      cargo_wrapper,
      'build',
      cargo,
      '--release-mode', release_mode,
      '--manifest-path', cargo_toml,
      '--project-build-root', meson.project_build_root(),
      '--current-build-dir', meson.current_build_dir(),
    ],
  )
else
  rust_c_artifacts = custom_target(
    meson.project_name(),
    build_by_default: true,
    output: [
      '@0@copenchecks.@1@'.format(lib_prefix, dynamic_ext),
      '@0@copenchecks.@1@'.format(lib_prefix, static_ext),
    ],
    console: true,
    install: true,
    install_dir: get_option('libdir'),
    command: [
      cargo_wrapper,
      'build',
      cargo,
      '--release-mode', release_mode,
      '--manifest-path', cargo_toml,
      '--project-build-root', meson.project_build_root(),
      '--current-build-dir', meson.current_build_dir(),
    ],
  )
endif
install_headers('include/openchecks.h')

pkg = import('pkgconfig')
pkg.generate(
  name: meson.project_name(),
  description: 'A simple checks framework',
  libraries: rust_c_artifacts.to_list(),
)

cmake = import('cmake')
cmake.write_basic_package_version_file(
  name: meson.project_name(),
  version: meson.project_version(),
)
conf = configuration_data()
conf.set_quoted(
  'PACKAGE_INCLUDE_INSTALL_DIR',
  '${PACKAGE_PREFIX_DIR}' / get_option('includedir'),
)
cmake.configure_package_config_file(
  name: meson.project_name(),
  input: 'cmake/copenchecks.cmake.in',
  configuration: conf,
)

copenchecks_dep = declare_dependency(
  include_directories: ['include'],
  link_with: rust_c_artifacts.to_list(),
  version: meson.project_version(),
)

if build_tests
  subdir('tests')
endif

if build_fuzz
  subdir('fuzz')
endif
