use openchecks::Item;

#[derive(Debug, PartialEq, PartialOrd)]
struct TestItem {
    value: (),
}

impl std::fmt::Display for TestItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "test")
    }
}

impl Item for TestItem {
    type Value<'a>
        = ()
    where
        Self: 'a;

    fn value(&self) -> Self::Value<'_> {
        self.value
    }
}

#[test]
fn test_item_hint() {
    let item = TestItem { value: () };
    assert!(item.type_hint().is_none());
}

#[test]
fn test_item_display() {
    let item = TestItem { value: () };
    assert_eq!(&format!("{}", item), "test");
}
