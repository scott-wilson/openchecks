#[derive(Debug, PartialEq, PartialOrd)]
struct NumberItem {
    number: i32,
}

impl std::fmt::Display for NumberItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.number.fmt(f)
    }
}

// The item container lets a type that is normally not debuggable, displayable,
// or sortable to be. This is only really useful for graphical user interfaces.
impl openchecks::Item for NumberItem {
    type Value<'a>
        = i32
    where
        Self: 'a;

    fn value(&self) -> Self::Value<'_> {
        self.number
    }
}

impl NumberItem {
    pub fn new(number: i32) -> Self {
        Self { number }
    }
}

struct IsEvenCheck {
    number: i32,
}

impl openchecks::CheckMetadata for IsEvenCheck {
    fn title(&self) -> std::borrow::Cow<str> {
        "Is Even Check".into()
    }

    fn description(&self) -> std::borrow::Cow<str> {
        "Check if the number is even".into()
    }
}

impl openchecks::Check for IsEvenCheck {
    type Item = NumberItem;

    type Items = Vec<Self::Item>;

    fn check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        let can_fix = false;
        let can_skip = false;

        // The items argument doesn't need to have any items, unless that
        // provides useful context. Generally this is reserved for failures.
        if self.number % 2 == 0 {
            openchecks::CheckResult::new_passed("The number is even.", None, can_fix, can_skip)
        } else {
            openchecks::CheckResult::new_failed(
                "The number is not even.",
                Some(vec![NumberItem::new(self.number)]),
                can_fix,
                can_skip,
            )
        }
    }
}

impl IsEvenCheck {
    pub fn new(number: i32) -> Self {
        Self { number }
    }
}

fn main() {
    let check_pass = IsEvenCheck::new(2);
    let result_pass = openchecks::run(&check_pass);

    assert!(!result_pass.status().has_failed());

    let check_fail = IsEvenCheck::new(1);
    let result_fail = openchecks::run(&check_fail);

    assert!(result_fail.status().has_failed());
}
