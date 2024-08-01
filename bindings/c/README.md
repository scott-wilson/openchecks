# Open Checks Framework

## Overview

This framework is designed to provide a system to write checks for studio work.
This includes validating assets (rigs, geometry, surfacing, etc), shots
(animation, lighting, simulation, etc), and whatever a studio would need to
validate. It provides a simple API with a rich result type that provides all the
information to let a user know why a check failed and what they need to do to
fix it. It also supports fixing issues if the issue can be fixed by the
computer.

## Features

- A Rust, C, C++, and Python 3 API
- Automatically fixing issues
- Marking checks with whether they are skippable or not.
- Exposing the result of checks in a user interface.

## Requirements

- Rust: 1.66 or later (This is not the guaranteed minimum supported Rust
  version)

## Design

### Status

The status is a machine readable part of the result.

- `Pending`: The check has not been run yet. This is a useful status in user
  interfaces to let users know that the checks are ready to be run.
- `Skipped`: The check has been skipped due to previous checks that this one
  depends on failing.
- `Passed`: The test has passed.
- `Warning`: The test has found things that might be an issue. However, this can
  still be treated the same as `Passed`.
- `Failed`: The test has found an issue with the object. This can be treated as
  `Passed` if the result allows skipping this test.
- `SystemError`: An issue with the test has happened. Either functionality it
  depends on has an error, or there is an issue with the test or test runner.
  Assume that the result of the test is invalid, and never allow the test to
  pass.

### Item

The item is a wrapper around the cause of a result. For example, if an asset
must be named a certain way, and an object under the asset is named wrong, then
the result can return the offending object as an item. The item wrapper is only
important for user interfaces, because it forces all types to be sortable and
displayable. For example, a file object may not have any knowledge of the file
path that created the file object, but the item wrapper could be extended to
include the file path with the file object. The item also includes a hint that
can tell a user interface what the type represents. For example, if the type of
data in an item is a string, but the string represents a scene path, then the
user interface could select the scene objects when the items are selected in the
check UI.

### Result

The result type contains information about what is the status of the check, a
human readable description of the result, the items that caused the result,
whether the result is fixable or skippable, error information for `SystemError`s
and timing information for the check and auto-fix.

### Check

A check is a unit of validation. For example, a check could be validating that
the asset is named correctly, textures exist, all parameters are set to their
defaults, etc. It is recommended that a check will only check one thing at a
time. For example, if an asset needs to be named correctly, the textures need to
exist, and the parameters are all defaults, then these should be three separate
checks. However, there might be checks that will all have to do the same work in
order to do their work. For example, if there are checks to make sure that
textures are the correct resolution, and other checks to make sure the textures
are the right types (8 bit intergers, 32 bit floats, etc), then both set of
checks would need to open the files, and therefore validate that the files
exist. The solution to this issue is left up to the team implementing the
checks.

### Runner

#### Check Runner

The runner takes a check and produces the result. It is also responsible for
making sure the check is in a valid state (returning a system error if it is
not), and producing timing information about the check for diagnostics.

#### Auto-Fix Runner

The auto-fix runner is similar to the check runner, but it will run the auto-fix
method for the check. The auto-fix runner should be run after the check runner,
and only if the check runner's result says that the result supports fixing.
After it has attempted fixing the issue, it will run the check again and return
a result to validate that the fix actually fixed the issue or not.

## Install

### Rust

```bash
cd /to/your/project
cargo add --git https://github.com/scott-wilson/openchecks.git
```

### Python

#### For development

```bash
cd /path/to/checks/bindings/python

make build
```

### C

```bash
cd /path/to/checks/bindings/c

make build
```

### C++

#### For development

```bash
cd /path/to/checks/bindings/cpp

make build
```

## Wishlist

- [ ] A unique name for the package
      [Issue](https://github.com/scott-wilson/openchecks/issues/5)
- [ ] To have the Python package named the same as the Rust package. (Currently,
      the Python package is called `pycheck`.)
      [Issue](https://github.com/scott-wilson/openchecks/issues/6)
- [ ] A C++ API (using the C API as a base)
      [Issue](https://github.com/scott-wilson/openchecks/issues/9)
- [ ] A scheduler to manage running the checks and returning results. This could
      also include having checks depend on other checks.
      [Issue](https://github.com/scott-wilson/openchecks/issues/7)
- [ ] Test discovery for situations where a context is given (a character rig
      for project XYZ or animating the shot ABC_010), and a list of checks are
      produced, ready to be ran.
      [Issue](https://github.com/scott-wilson/openchecks/issues/8)
- [ ] A Qt GUI [Issue](https://github.com/scott-wilson/openchecks/issues/10)
- [ ] Blender integration
      [Issue](https://github.com/scott-wilson/openchecks/issues/11)
- [ ] Gaffer integration
      [Issue](https://github.com/scott-wilson/openchecks/issues/11)
- [ ] Natron integration
      [Issue](https://github.com/scott-wilson/openchecks/issues/11)
- [ ] Houdini integration
      [Issue](https://github.com/scott-wilson/openchecks/issues/11)
- [ ] Katana integration
      [Issue](https://github.com/scott-wilson/openchecks/issues/11)
- [ ] Maya integration
      [Issue](https://github.com/scott-wilson/openchecks/issues/11)
- [ ] Nuke integration
      [Issue](https://github.com/scott-wilson/openchecks/issues/11)
