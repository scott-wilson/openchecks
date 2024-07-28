test_targets = [
  'test_check',
  'test_item',
  'test_result',
  'test_runner',
  'test_status',
]

cmocka_proj = subproject('cmocka')

foreach test_target : test_targets
  test_exec = executable(
    test_target,
    '@0@.c'.format(test_target),
    dependencies: [copenchecks_dep, cmocka_proj.get_variable('cmocka_dep')],
    include_directories: ['common'],
    link_with: [rust_c_artifacts[0]],
    )
  test(test_target, test_exec)
endforeach
