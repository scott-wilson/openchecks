/// The status enum represents a result status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Status {
    /// The check is waiting to run. A check should not return this status, but
    /// instead this can be used by a user interface to let a user know that the
    /// check is ready to run.
    Pending,
    /// The check has been skipped. A check might return this to let the user
    /// know that an element it depends on is invalid (such as a file doesn't)
    /// exist, or a check scheduler may make child checks return this status if
    /// a check fails.
    Skipped,
    /// The check has successfully passed without issue.
    Passed,
    /// There were issues found, but they are not deemed failures. This can be
    /// treated the same as a pass.
    Warning,
    /// The check found an issue that caused it to fail. A validation system
    /// should block the process following the validations to have the issue
    /// fixed, unless the result allows skipping the check.
    Failed,
    /// There was an issue with a check or runner itself. For example, code that
    /// the check depends on has an error, or the check is otherwise invalid.
    /// If a validation process finds a result with this status, then the
    /// process should not let the next process after run at all until the check
    /// has been fixed by a developer.
    SystemError,
}

impl Status {
    /// Return if a check is waiting to be run.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use checks::Status;
    /// let status = Status::Pending;
    /// assert_eq!(status.is_pending(), true);
    ///
    /// let status = Status::Passed;
    /// assert_eq!(status.is_pending(), false);
    /// ```
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Return if a check has passed.
    ///
    /// Currently, the only statuses that are considered passed are
    /// [Passed](Status::Passed), [Skipped](Status::Skipped), and
    /// [Warning](Status::Warning).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use checks::Status;
    /// let status = Status::Passed;
    /// assert_eq!(status.has_passed(), true);
    ///
    /// let status = Status::Skipped;
    /// assert_eq!(status.has_passed(), false);
    ///
    /// let status = Status::Warning;
    /// assert_eq!(status.has_passed(), true);
    ///
    /// let status = Status::Failed;
    /// assert_eq!(status.has_passed(), false);
    /// ```
    pub fn has_passed(&self) -> bool {
        matches!(self, Self::Passed | Self::Warning)
    }

    /// Return if a check has failed.
    ///
    /// Currently, the only statuses that are considered failures are
    /// [Failed](Status::Failed) and [SystemError](Status::SystemError).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use checks::Status;
    /// let status = Status::Passed;
    /// assert_eq!(status.has_failed(), false);
    ///
    /// let status = Status::Failed;
    /// assert_eq!(status.has_failed(), true);
    ///
    /// let status = Status::SystemError;
    /// assert_eq!(status.has_failed(), true);
    /// ```
    pub fn has_failed(&self) -> bool {
        matches!(self, Self::Failed | Self::SystemError)
    }
}
