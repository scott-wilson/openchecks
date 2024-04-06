#![no_main]

use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Arbitrary)]
struct Item {
    value: u32,
}

impl std::fmt::Display for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl checks::Item for Item {
    type Value = u32;

    fn value(&self) -> Self::Value {
        self.value
    }
}

#[derive(Debug, Arbitrary)]
struct Input {
    message: String,
    items: Option<Vec<Item>>,
    can_fix: bool,
    can_skip: bool,
}

fuzz_target!(|input: Input| {
    let items = input.items.clone();
    let result =
        checks::CheckResult::new_skipped(&input.message, items, input.can_fix, input.can_skip);

    assert_eq!(result.status(), &checks::Status::Skipped);
    assert_eq!(result.message(), &input.message);
    assert_eq!(result.items(), &input.items);
    assert_eq!(result.error(), &None);
});
