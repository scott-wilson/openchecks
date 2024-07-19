use openchecks::Status;

macro_rules! test_is_pending {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (status, expected) = $value;
                assert_eq!(status.is_pending(), expected);
            }
        )*
        }
    }

test_is_pending! {
    test_is_pending_pending_success: (Status::Pending, true),
    test_is_pending_skipped_success: (Status::Skipped, false),
    test_is_pending_passed_success: (Status::Passed, false),
    test_is_pending_warning_success: (Status::Warning, false),
    test_is_pending_failed_success: (Status::Failed, false),
    test_is_pending_system_error_success: (Status::SystemError, false),
}

macro_rules! test_has_passed {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (status, expected) = $value;
                assert_eq!(status.has_passed(), expected);
            }
        )*
        }
    }

test_has_passed! {
    test_has_passed_pending_success: (Status::Pending, false),
    test_has_passed_skipped_success: (Status::Skipped, false),
    test_has_passed_passed_success: (Status::Passed, true),
    test_has_passed_warning_success: (Status::Warning, true),
    test_has_passed_failed_success: (Status::Failed, false),
    test_has_passed_system_error_success: (Status::SystemError, false),
}

macro_rules! test_has_failed {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (status, expected) = $value;
                assert_eq!(status.has_failed(), expected);
            }
        )*
        }
    }

test_has_failed! {
    test_has_failed_pending_success: (Status::Pending, false),
    test_has_failed_skipped_success: (Status::Skipped, false),
    test_has_failed_passed_success: (Status::Passed, false),
    test_has_failed_warning_success: (Status::Warning, false),
    test_has_failed_failed_success: (Status::Failed, true),
    test_has_failed_system_error_success: (Status::SystemError, true),
}

macro_rules! test_debug {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (status, expected) = $value;
                assert_eq!(&format!("{:?}", status), expected);
            }
        )*
        }
    }

test_debug! {
    test_debug_pending_success: (Status::Pending, "Pending"),
    test_debug_skipped_success: (Status::Skipped, "Skipped"),
    test_debug_passed_success: (Status::Passed, "Passed"),
    test_debug_warning_success: (Status::Warning, "Warning"),
    test_debug_failed_success: (Status::Failed, "Failed"),
    test_debug_system_error_success: (Status::SystemError, "SystemError"),
}

macro_rules! test_clone {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (status, expected) = $value;
                assert_eq!(status.clone(), expected);
            }
        )*
        }
    }

test_clone! {
    test_clone_pending_success: (Status::Pending, Status::Pending),
    test_clone_skipped_success: (Status::Skipped, Status::Skipped),
    test_clone_passed_success: (Status::Passed, Status::Passed),
    test_clone_warning_success: (Status::Warning, Status::Warning),
    test_clone_failed_success: (Status::Failed, Status::Failed),
    test_clone_system_error_success: (Status::SystemError, Status::SystemError),
}
