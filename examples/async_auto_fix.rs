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

struct IsZeroCheck {
    number: i32,
}

impl openchecks::CheckMetadata for IsZeroCheck {
    fn title(&self) -> std::borrow::Cow<str> {
        "Is Zero Check".into()
    }

    fn description(&self) -> std::borrow::Cow<str> {
        "Check if the number is zero".into()
    }
}

#[async_trait::async_trait]
impl openchecks::AsyncCheck for IsZeroCheck {
    type Item = NumberItem;

    type Items = Vec<Self::Item>;

    async fn async_check(&self) -> openchecks::CheckResult<Self::Item, Self::Items> {
        // In this case, we can automatically fix the error. If the number is
        // not zero, set it to zero!
        let can_fix = true;
        let can_skip = false;

        // The items argument doesn't need to have any items, unless that
        // provides useful context. Generally this is reserved for failures.
        if self.number == 0 {
            openchecks::CheckResult::new_passed("The number is zero.", None, can_fix, can_skip)
        } else {
            openchecks::CheckResult::new_failed(
                "The number is not zero.",
                Some(vec![NumberItem::new(self.number)]),
                can_fix,
                can_skip,
            )
        }
    }

    async fn async_auto_fix(&mut self) -> Result<(), openchecks::Error> {
        self.number = 0;

        Ok(())
    }
}

impl IsZeroCheck {
    pub fn new(number: i32) -> Self {
        Self { number }
    }
}

#[tokio::main]
async fn main() {
    let mut check = IsZeroCheck::new(1);
    let result_fail = openchecks::async_run(&check).await;

    assert!(result_fail.status().has_failed());
    assert!(result_fail.can_fix());

    // When an auto-fix is ran, then the run function is automatically called
    // after to validate that the auto-fix fixed the issue or not.
    let result_pass = openchecks::async_auto_fix(&mut check).await;

    assert!(!result_pass.status().has_failed());
}
