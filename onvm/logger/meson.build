logger_src = 'logger.go'
logger_lib = 'liblogger.a'
logger_hdr = 'logger.h'

build_root = meson.current_build_dir()

logger_build = custom_target(
  'liblogger',
  input: logger_src,
  output: [logger_lib, logger_hdr],
  command: [
    'sh', '-c',
    'echo ">>> Building liblogger.a..." && echo $BUILD_ROOT && cd ../onvm/logger && ' +
    'go build -o liblogger.a -buildmode=c-archive logger.go && ' +
    'mv liblogger.h logger.h && ' +
    'cp liblogger.a $BUILD_ROOT/liblogger.a && ' +
    'cp logger.h $BUILD_ROOT/logger.h && ' +
    'cp logger.h $BUILD_ROOT/../utlt/logger.h'
  ],
  env: {
    'BUILD_ROOT': build_root,
  },
  install: false,
  build_by_default: true
)

liblogger_dep = declare_dependency(
  link_args: [logger_build[0].full_path()],
  include_directories: include_directories('.')
)
