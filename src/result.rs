/// A check result contains all of the information needed to know the status of
/// a check.
///
/// It contains useful information such as...
///
/// - [Status](crate::Status): A machine readable value that can be used to
///   quickly tell whether the test passed, failed, or is pending.
/// - Message: A human readable description of the status. If the status failed,
///   this should contain information on what happened, and how to fix the
///   issue.
/// - [Items](crate::Item): An iterable of items that caused the result. For
///   example, if a check that validates if objects are named correctly failed,
///   then the items would include the offending objects.
/// - Can fix: Whether the check can be fixed or not. For example, if a check
///   requires textures to be no larger than a certain size, includes a method
///   to resize the textures, and failed, the result could be marked as fixable
///   so the user could press an "auto-fix" button in a user interface to resize
///   the textures.
/// - Can skip: Usually, a validation system should not let any checks that
///   failed to go forward with, for example, publishing an asset. Sometimes a
///   company might decide that the error isn't critical enough to always fail
///   if a supervisor approves the fail to pass through.
/// - [Error](crate::Error): If the status is
///   [Status::SystemError](crate::Status::SystemError), then it may also
///   contain the error that caused the result. Other statuses shouldn't contain
///   an error.
/// - Check duration: A diagnostic tool that could be exposed in a user
///   interface to let the user know how long it took to run the check.
/// - Fix duration: A diagnostic tool that could be exposed in a user
///   interface to let the user know how long it took to run the auto-fix.
#[derive(Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CheckResult<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>> {
    status: crate::Status,
    message: String,
    items: Option<Items>,
    can_fix: bool,
    can_skip: bool,
    error: Option<crate::Error>,
    check_duration: std::time::Duration,
    fix_duration: std::time::Duration,
}

impl<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>> CheckResult<Item, Items> {
    /// Create a new result.
    ///
    /// It is suggested to use one of the other `new_*` methods such as
    /// [new_passed](crate::CheckResult::new_passed) for convenience.
    pub fn new<M: AsRef<str>>(
        status: crate::Status,
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
        error: Option<crate::Error>,
    ) -> Self {
        Self {
            status,
            message: message.as_ref().to_string(),
            items,
            can_fix,
            can_skip,
            error,
            check_duration: std::time::Duration::ZERO,
            fix_duration: std::time::Duration::ZERO,
        }
    }

    /// Create a new result that passed a check.
    pub fn new_passed<M: AsRef<str>>(
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        Self::new(
            crate::Status::Passed,
            message.as_ref(),
            items,
            can_fix,
            can_skip,
            None,
        )
    }

    /// Create a new result that skipped a check.
    pub fn new_skipped<M: AsRef<str>>(
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        Self::new(
            crate::Status::Skipped,
            message.as_ref(),
            items,
            can_fix,
            can_skip,
            None,
        )
    }

    /// Create a new result that passed a check, but with a warning.
    ///
    /// Warnings should be considered as passes, but with notes saying that
    /// there *may* be an issue. For example, textures could be any resolution,
    /// but anything over 4096x4096 could be marked as a potential performance
    /// issue.
    pub fn new_warning<M: AsRef<str>>(
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        Self::new(
            crate::Status::Warning,
            message.as_ref(),
            items,
            can_fix,
            can_skip,
            None,
        )
    }

    /// Create a new result that failed a check.
    ///
    /// Failed checks in a validation system should not let the following
    /// process continue forward unless the check can be skipped/overridden by a
    /// supervisor, or is fixed and later passes, or passes with a warning.
    pub fn new_failed<M: AsRef<str>>(
        message: M,
        items: Option<Items>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        Self::new(
            crate::Status::Failed,
            message.as_ref(),
            items,
            can_fix,
            can_skip,
            None,
        )
    }

    /// The status of the result.
    pub fn status(&self) -> &crate::Status {
        &self.status
    }

    /// A human readable message for the result.
    ///
    /// If a check has issues, then this should include information about what
    /// happened and how to fix the issue.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The items that caused the result.
    pub fn items(&self) -> &Option<Items> {
        &self.items
    }

    /// Whether the result can be fixed or not.
    ///
    /// If the status is [Status::SystemError](crate::Status::SystemError), then
    /// the check can **never** be fixed without fixing the issue with the
    /// validation system.
    pub fn can_fix(&self) -> bool {
        if self.status == crate::Status::SystemError {
            false
        } else {
            self.can_fix
        }
    }

    /// Whether the result can be skipped or not.
    ///
    /// A result should only be skipped if the company decides that letting the
    /// failed check pass will not cause serious issues to the next department.
    /// Also, it is recommended that check results are not skipped unless a
    /// supervisor overrides the skip.
    ///
    /// If the status is [Status::SystemError](crate::Status::SystemError), then
    /// the check can **never** be skipped without fixing the issue with the
    /// validation system.
    pub fn can_skip(&self) -> bool {
        if self.status == crate::Status::SystemError {
            false
        } else {
            self.can_skip
        }
    }

    /// The error that caused the result.
    ///
    /// This only really applies to the
    /// [Status::SystemError](crate::Status::SystemError) status. Other results
    /// should not include the error object.
    pub fn error(&self) -> &Option<crate::Error> {
        &self.error
    }

    /// The duration of a check.
    ///
    /// This is not settable outside of the [check runner](crate::run). It can
    /// be exposed to a user to let them know how long a check took to run, or
    /// be used as a diagnostics tool to improve check performance.
    pub fn check_duration(&self) -> std::time::Duration {
        self.check_duration
    }

    pub(crate) fn set_check_duration(&mut self, duration: std::time::Duration) {
        self.check_duration = duration
    }

    /// The duration of an auto-fix.
    ///
    /// This is not settable outside of the [auto-fix runner](crate::auto_fix).
    /// It can be exposed to a user to let them know how long an auto-fix took
    /// to run, or be used as a diagnostics tool to improve check performance.
    pub fn fix_duration(&self) -> std::time::Duration {
        self.fix_duration
    }

    pub(crate) fn set_fix_duration(&mut self, duration: std::time::Duration) {
        self.fix_duration = duration
    }
}
