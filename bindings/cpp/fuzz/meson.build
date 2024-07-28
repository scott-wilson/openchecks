fuzz_targets = [
  'result_new_failed',
  'result_new_passed',
  'result_new_skipped',
  'result_new_warning',
  'result_new',
  'runner_run',
  'status_has_failed',
  'status_has_passed',
  'status_is_pending',
]

foreach fuzz_target : fuzz_targets
  if is_msvc_style
    executable(
      fuzz_target,
      '@0@.cpp'.format(fuzz_target),
      include_directories: ['.', copenchecks_include_dirs],
      dependencies: [cppopenchecks_dep, copenchecks_dep],
      c_args: '-WX -W4 -fsanitize=fuzzer',
      link_args: '-fsanitize=fuzzer',
    )
  else
    executable(
      fuzz_target,
      '@0@.cpp'.format(fuzz_target),
      include_directories: ['.', copenchecks_include_dirs],
      dependencies: [cppopenchecks_dep, copenchecks_dep],
      c_args: '-Werror -Wall -fsanitize=fuzzer',
      link_args: '-fsanitize=fuzzer',
    )
  endif
endforeach
