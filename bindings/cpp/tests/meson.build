test_targets = [
  'test_item',
  'test_items',
  'test_result',
  'test_runner',
  'test_status',
]

gtest_proj = subproject('gtest')
gtest_dep = gtest_proj.get_variable('gtest_dep')
gtest_main_dep = gtest_proj.get_variable('gtest_main_dep')

foreach test_target : test_targets
  test_exec = executable(
    test_target,
    '@0@.cpp'.format(test_target),
    dependencies: [cppopenchecks_dep, copenchecks_dep, gtest_dep, gtest_main_dep],
    include_directories: ['.', copenchecks_include_dirs],
  )
  test(test_target, test_exec)
endforeach
