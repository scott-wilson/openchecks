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
    status: checks::Status,
    message: String,
    items: Option<Vec<Item>>,
    can_fix: bool,
    can_skip: bool,
    error: Option<checks::Error>,
}

fuzz_target!(|input: Input| {
    let items = input.items.clone();
    let error = input.error.clone();
    let result = checks::CheckResult::new(
        input.status,
        &input.message,
        items,
        input.can_fix,
        input.can_skip,
        error,
    );

    assert_eq!(result.status(), &input.status);
    assert_eq!(result.message(), &input.message);
    assert_eq!(result.items(), &input.items);
    assert_eq!(result.error(), &input.error);

    if input.status == checks::Status::SystemError {
        assert!(!result.can_fix());
        assert!(!result.can_skip());
    } else {
        assert_eq!(result.can_fix(), input.can_fix);
        assert_eq!(result.can_skip(), input.can_skip);
    }
});
