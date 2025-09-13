#ifndef copenchecks_h
#define copenchecks_h

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef enum OpenChecksAutoFixStatus {
  OpenChecksAutoFixStatusOk,
  OpenChecksAutoFixStatusError,
} OpenChecksAutoFixStatus;

/**
 * The status enum represents a result status.
 */
typedef enum OpenChecksStatus {
  /**
   * The check is waiting to run. A check should not return this status, but
   * instead this can be used by a user interface to let a user know that the
   * check is ready to run.
   */
  OpenChecksStatusPending,
  /**
   * The check has been skipped. A check might return this to let the user
   * know that an element it depends on is invalid (such as a file doesn't)
   * exist, or a check scheduler may make child checks return this status if
   * a check fails.
   */
  OpenChecksStatusSkipped,
  /**
   * The check has successfully passed without issue.
   */
  OpenChecksStatusPassed,
  /**
   * There were issues found, but they are not deemed failures. This can be
   * treated the same as a pass.
   */
  OpenChecksStatusWarning,
  /**
   * The check found an issue that caused it to fail. A validation system
   * should block the process following the validations to have the issue
   * fixed, unless the result allows skipping the check.
   */
  OpenChecksStatusFailed,
  /**
   * There was an issue with a check or runner itself. For example, code that
   * the check depends on has an error, or the check is otherwise invalid.
   * If a validation process finds a result with this status, then the
   * process should not let the next process after run at all until the check
   * has been fixed by a developer.
   */
  OpenChecksStatusSystemError,
} OpenChecksStatus;

/**
 * The OpenChecksString contains an owned pointer to a C style string.
 *
 * # Safety
 *
 * The pointer to the string must be destroyed with `openchecks_string_destroy`
 * once it is no longer needed. Also, the pointer must not be modified at all
 * by any functions not exposed by the validation library.
 *
 * Internally, if a OpenChecksString is created, the system will create a copy
 * of the string being pointed to.
 */
typedef struct OpenChecksString {
  /**
   * The owned pointer to a string.
   *
   * # Safety
   *
   * This should not be modified at all outside of the validation library.
   * Also, it should only be destroyed with `openchecks_string_destroy`.
   */
  char *string;
  /**
   * Destroy the owned data.
   *
   * # Safety
   *
   * The destroy function should be called once at most.
   *
   * The destroy function should handle if the string pointer is null.
   */
  void (*destroy_fn)(struct OpenChecksString*);
} OpenChecksString;

/**
 * The item is a wrapper to make a result item more user interface friendly.
 *
 * Result items represent the objects that caused a result. For example, if a
 * check failed because the bones in a character rig are not properly named,
 * then the items would contain the bones that are named incorrectly.
 *
 * The item wrapper makes the use of items user interface friendly because it
 * implements item sorting and a string representation of the item.
 *
 * # Safety
 *
 * It is assumed that the value the item contains is owned by the item wrapper.
 */
typedef struct OpenChecksItem {
  /**
   * A type hint can be used to add a hint to a system that the given type
   * represents something else. For example, the value could be a string, but
   * this is a scene path.
   *
   * A user interface could use this hint to select the item in the
   * application.
   *
   * # Safety
   *
   * The string passed from the type hint function is owned by the item, or
   * is static. A null pointer represents no type hint. The function must
   * also contain type information needed by the `value_fn` for casting the
   * void pointer to the correct type.
   */
  const char *(*type_hint_fn)(const struct OpenChecksItem*);
  /**
   * The value that is wrapped.
   *
   * # Safety
   *
   * The value is assumed to be owned by the item wrapper. Also, the
   * type_hint_fn must contain type information needed to cast the void
   * pointer to the correct type.
   */
  const void *(*value_fn)(const struct OpenChecksItem*);
  /**
   * The clone function will create a full copy of the item and its value.
   *
   * # Safety
   *
   * The items should only be read-only during their lifetime (excluding when
   * they are deleted). So, if a value is going to be shared among items,
   * then it should do so behind reference counters. Or, have the destroy
   * function not actually modify/destroy the data, and leave that up to a
   * process outside of the validation library.
   */
  struct OpenChecksItem *(*clone_fn)(const struct OpenChecksItem*);
  /**
   * Destroy the owned data.
   *
   * # Safety
   *
   * The destroy function should be called once at most.
   */
  void (*destroy_fn)(struct OpenChecksItem*);
  /**
   * The debug function is used to create a string for debugging issues.
   *
   * # Safety
   *
   * The string's ownership is handed over to the caller, so it will not
   * release the memory when finished. Also, do not modify or destroy the
   * memory outside of the context in which the memory was created. For
   * example, if the string was created with `malloc`, it should be deleted
   * with `free`.
   */
  struct OpenChecksString (*debug_fn)(const struct OpenChecksItem*);
  /**
   * The display function is used to create a string for displaying to a
   * user.
   *
   * # Safety
   *
   * The string's ownership is handed over to the caller, so it will not
   * release the memory when finished. Also, do not modify or destroy the
   * memory outside of the context in which the memory was created. For
   * example, if the string was created with `malloc`, it should be deleted
   * with `free`
   */
  struct OpenChecksString (*display_fn)(const struct OpenChecksItem*);
  /**
   * The order function is used to order items in user interfaces.
   */
  bool (*lt_fn)(const struct OpenChecksItem*, const struct OpenChecksItem*);
  /**
   * The compare function is used to order items in user interfaces.
   */
  bool (*eq_fn)(const struct OpenChecksItem*, const struct OpenChecksItem*);
} OpenChecksItem;

/**
 * The OpenChecksItems iterable container is used to iterate over any number of
 * and any sized objects.
 */
typedef struct OpenChecksItems {
  /**
   * Get an item from the container.
   *
   * # Safety
   *
   * The container pointer must not be null. Passing an invalid index will
   * return a null pointer.
   */
  const struct OpenChecksItem *(*get_fn)(const struct OpenChecksItems*, size_t);
  /**
   * Clone the container.
   *
   * # Safety
   *
   * The container pointer must not be null.
   */
  struct OpenChecksItems *(*clone_fn)(const struct OpenChecksItems*);
  /**
   * Get the length of the container.
   *
   * # Safety
   *
   * The container pointer must not be null.
   */
  size_t (*length_fn)(const struct OpenChecksItems*);
  /**
   * Get the size of each item in the container. This must be the same for
   * all items in the container.
   *
   * # Safety
   *
   * The container pointer must not be null.
   */
  size_t (*item_size_fn)(const struct OpenChecksItems*);
  /**
   * The compare function is used to compare containers.
   *
   * # Safety
   *
   * This must support comparing a null with another null or non-null value.
   * Null == null is true, but null != non-null is false.
   */
  bool (*eq_fn)(const struct OpenChecksItems*, const struct OpenChecksItems*);
  /**
   * Destroy the container.
   *
   * # Safety
   *
   * The container pointer must not be null.
   */
  void (*destroy_fn)(struct OpenChecksItems*);
} OpenChecksItems;

/**
 * A check result contains all of the information needed to know the status of
 * a check.
 *
 * It contains useful information such as...
 *
 * - Status: A machine readable value that can be used to quickly tell whether
 *   the test passed, failed, or is pending.
 * - Message: A human readable description of the status. If the status failed,
 *   this should contain information on what happened, and how to fix the
 *   issue.
 * - Items: An iterable of items that caused the result. For example, if a
 *   check that validates if objects are named correctly failed, then the items
 *   would include the offending objects.
 * - Can fix: Whether the check can be fixed or not. For example, if a check
 *   requires textures to be no larger than a certain size, includes a method
 *   to resize the textures, and failed, the result could be marked as fixable
 *   so the user could press an "auto-fix" button in a user interface to resize
 *   the textures.
 * - Can skip: Usually, a validation system should not let any checks that
 *   failed to go forward with, for example, publishing an asset. Sometimes a
 *   company might decide that the error isn't critical enough to always fail
 *   if a supervisor approves the fail to pass through.
 * - Error: If the status is OpenChecksStatusSystemError, then it may also
 *   contain the error that caused the result. Other statuses shouldn't contain
 *   an error.
 * - Check duration: A diagnostic tool that could be exposed in a user
 *   interface to let the user know how long it took to run the check.
 * - Fix duration: A diagnostic tool that could be exposed in a user
 *   interface to let the user know how long it took to run the auto-fix.
 */
typedef struct OpenChecksCheckResult {
  enum OpenChecksStatus status;
  char *message;
  struct OpenChecksItems *items;
  bool can_fix;
  bool can_skip;
  char *error;
  double check_duration;
  double fix_duration;
} OpenChecksCheckResult;

/**
 * The check hint flags contains useful information such as whether the check
 * should support auto-fixing issues.
 */
typedef uint8_t OpenChecksCheckHint;

/**
 * The result of the auto fix. The message should only contain a value if the
 * auto-fix returned an error.
 *
 * # Safety
 *
 * The message pointer must not be modified or destroyed. The auto-fix runner
 * is responsible for destroying the message once done.
 */
typedef struct OpenChecksAutoFixResult {
  /**
   * The status of the auto-fix.
   */
  enum OpenChecksAutoFixStatus status;
  /**
   * The error message. Null means no message.
   */
  char *message;
} OpenChecksAutoFixResult;

typedef struct OpenChecksBaseCheck {
  /**
   * The human readable title for the check.
   *
   * User interfaces should use the title for displaying the check.
   */
  const char *(*title_fn)(const struct OpenChecksBaseCheck*);
  /**
   * The human readable description for the check.
   *
   * This should include information about what the check is looking for,
   * what are the conditions for the different statuses it supports, and if
   * there's an auto-fix, what the auto-fix will do.
   */
  const char *(*description_fn)(const struct OpenChecksBaseCheck*);
  /**
   * The hint gives information about what features the check supports.
   */
  OpenChecksCheckHint (*hint_fn)(const struct OpenChecksBaseCheck*);
  /**
   * Run a validation on the input data and output the result of the
   * validation.
   */
  struct OpenChecksCheckResult (*check_fn)(const struct OpenChecksBaseCheck*);
  /**
   * Automatically fix the issue detected by the check method.
   */
  struct OpenChecksAutoFixResult (*auto_fix_fn)(struct OpenChecksBaseCheck*);
} OpenChecksBaseCheck;

/**
 * The OpenChecksStringView creates a borrowed pointer to a C style string.
 *
 * # Safety
 *
 * The pointer must not outlive the container that owns the string. Also, the
 * pointer should not be null, but that is not a strict requirement.
 */
typedef struct OpenChecksStringView {
  /**
   * The borrowed pointer to a string.
   *
   * # Safety
   *
   * The string must not outlive the container that owns it.
   */
  const char *string;
} OpenChecksStringView;

typedef struct OpenChecksItemsIterator {
  const struct OpenChecksItems *items;
  size_t index;
} OpenChecksItemsIterator;

/**
 * The check supports auto-fixing.
 *
 * This does not guarantee that the auto-fix is implemented, but instead that
 * the auto-fix should be implemented.
 */
#define OPENCHECKS_CHECK_HINT_AUTO_FIX 1

/**
 * The check supports no extra features.
 *
 * This should be considered the most conservative check *feature*. For
 * example, no auto-fix, check cannot be skipped before running, etc.
 */
#define OPENCHECKS_CHECK_HINT_NONE 0

/**
 * Automatically fix an issue found by a check.
 *
 * This function should only be run after the check runner returns a result,
 * and that result can be fixed. Otherwise, the fix might try to fix an already
 * "good" object, causing issues with the object.
 *
 * The auto-fix will re-run the check runner to validate that it has actually
 * fixed the issue.
 *
 * This will return a result with the `OpenChecksStatusSystemError` status if
 * the check does not have the CheckHint::AUTO_FIX flag set, or an auto-fix
 * returned an error. In the case of the latter, it will include the error with
 * the check result.
 *
 * # Safety
 *
 * The check pointer must not be null.
 */
struct OpenChecksCheckResult openchecks_auto_fix(struct OpenChecksBaseCheck *check);

/**
 * The auto-fix returned an error.
 *
 * # Safety
 *
 * The message string will be copied, so the caller may destroy the string
 * after calling this method. Also, a null pointer will be converted to an
 * empty string.
 */
struct OpenChecksAutoFixResult openchecks_check_auto_fix_error(const char *message);

/**
 * The auto-fix was successful, and did not return any errors.
 *
 * # Safety
 *
 * The pointer should not be null, and point to valid memory.
 */
struct OpenChecksAutoFixResult openchecks_check_auto_fix_ok(void);

/**
 * The human readable description for the check.
 *
 * This should include information about what the check is looking for, what
 * are the conditions for the different statuses it supports, and if there's an
 * auto-fix, what the auto-fix will do.
 *
 * # Safety
 *
 * The pointer should not be null, and point to valid memory.
 */
struct OpenChecksStringView openchecks_check_description(const struct OpenChecksBaseCheck *check);

/**
 * Run a validation on the input data and output the result of the validation.
 *
 * # Safety
 *
 * The pointer should not be null, and point to valid memory.
 */
OpenChecksCheckHint openchecks_check_hint(const struct OpenChecksBaseCheck *check);

/**
 * Whether the result can be fixed or not.
 *
 * If the status is `OpenChecksStatusSystemError`, then the check can **never**
 * be fixed without fixing the issue with the validation system.
 *
 * # Safety
 *
 * The result pointer must not be null.
 */
bool openchecks_check_result_can_fix(const struct OpenChecksCheckResult *result);

/**
 * Whether the result can be skipped or not.
 *
 * A result should only be skipped if the company decides that letting the
 * failed check pass will not cause serious issues to the next department.
 * Also, it is recommended that check results are not skipped unless a
 * supervisor overrides the skip.
 *
 * If the status is `OpenChecksStatusSystemError`, then the check can **never**
 * be skipped without fixing the issue with the validation system.
 *
 * # Safety
 *
 * The result pointer must not be null.
 */
bool openchecks_check_result_can_skip(const struct OpenChecksCheckResult *result);

/**
 * The duration of a check.
 *
 * This is not settable outside of the check runner. It can be exposed to a
 * user to let them know how long a check took to run, or be used as a
 * diagnostics tool to improve check performance.
 *
 * # Safety
 *
 * The result pointer must not be null.
 */
double openchecks_check_result_check_duration(const struct OpenChecksCheckResult *result);

/**
 * Destroy the result.
 *
 * # Safety
 *
 * The result pointer must be not null, and must not be already destroyed.
 */
void openchecks_check_result_destroy(struct OpenChecksCheckResult *result);

/**
 * The error that caused the result.
 *
 * This only really applies to the `OpenChecksStatusSystemError` status. Other
 * results should not include the error object.
 *
 * # Safety
 *
 * The result pointer is null if there are no errors. Otherwise it will point
 * to a valid message.
 */
const char *openchecks_check_result_error(const struct OpenChecksCheckResult *result);

/**
 * Create a new result that failed a check.
 *
 * Failed checks in a validation system should not let the following process
 * continue forward unless the check can be skipped/overridden by a supervisor,
 * or is fixed and later passes, or passes with a warning.
 *
 * # Safety
 *
 * The message pointer must not be null. It is also copied, so the caller may
 * be able to free the memory once the method is called.
 *
 * The items can be null if there are no items. Also, the result will take
 * ownership of the pointer and be responsible for cleaning it once the result
 * is destroyed.
 */
struct OpenChecksCheckResult openchecks_check_result_failed(const char *message,
                                                            struct OpenChecksItems *items,
                                                            bool can_fix,
                                                            bool can_skip);

/**
 * The duration of an auto-fix.
 *
 * This is not settable outside of the auto-fix runner. It can be exposed to a
 * user to let them know how long an auto-fix took to run, or be used as a
 * diagnostics tool to improve check performance.
 *
 * # Safety
 *
 * The result pointer must not be null.
 */
double openchecks_check_result_fix_duration(const struct OpenChecksCheckResult *result);

/**
 * The items that caused the result.
 *
 * # Safety
 *
 * A null result pointer represents that there are no items.
 */
const struct OpenChecksItems *openchecks_check_result_items(const struct OpenChecksCheckResult *result);

/**
 * A human readable message for the result.
 *
 * If a check has issues, then this should include information about what
 * happened and how to fix the issue.
 *
 * # Safety
 *
 * The result pointer must not be null.
 */
struct OpenChecksStringView openchecks_check_result_message(const struct OpenChecksCheckResult *result);

/**
 * Create a new result.
 *
 * It is suggested to use one of the other `openchecks_check_result_*` methods
 * such as `openchecks_check_result_passed` for convenience.
 *
 * # Safety
 *
 * The message pointer must not be null. It is also copied, so the caller may
 * be able to free the memory once the method is called.
 *
 * The items can be null if there are no items. Also, the result will take
 * ownership of the pointer and be responsible for cleaning it once the result
 * is destroyed.
 *
 * Error can be a null pointer. It is also copied, so the caller may be able to
 * free the memory once the method is called.
 */
struct OpenChecksCheckResult openchecks_check_result_new(enum OpenChecksStatus status,
                                                         const char *message,
                                                         struct OpenChecksItems *items,
                                                         bool can_fix,
                                                         bool can_skip,
                                                         const char *error);

/**
 * Create a new result that passed a check.
 *
 * # Safety
 *
 * The message pointer must not be null. It is also copied, so the caller may
 * be able to free the memory once the method is called.
 *
 * The items can be null if there are no items. Also, the result will take
 * ownership of the pointer and be responsible for cleaning it once the result
 * is destroyed.
 */
struct OpenChecksCheckResult openchecks_check_result_passed(const char *message,
                                                            struct OpenChecksItems *items,
                                                            bool can_fix,
                                                            bool can_skip);

/**
 * Create a new result that skipped a check.
 *
 * # Safety
 *
 * The message pointer must not be null. It is also copied, so the caller may
 * be able to free the memory once the method is called.
 *
 * The items can be null if there are no items. Also, the result will take
 * ownership of the pointer and be responsible for cleaning it once the result
 * is destroyed.
 */
struct OpenChecksCheckResult openchecks_check_result_skipped(const char *message,
                                                             struct OpenChecksItems *items,
                                                             bool can_fix,
                                                             bool can_skip);

/**
 * The status of the result.
 *
 * # Safety
 *
 * The result pointer must not be null.
 */
enum OpenChecksStatus openchecks_check_result_status(const struct OpenChecksCheckResult *result);

/**
 * Create a new result that passed a check, but with a warning.
 *
 * Warnings should be considered as passes, but with notes saying that there
 * *may* be an issue. For example, textures could be any resolution, but
 * anything over 4096x4096 could be marked as a potential performance issue.
 *
 * # Safety
 *
 * The message pointer must not be null. It is also copied, so the caller may
 * be able to free the memory once the method is called.
 *
 * The items can be null if there are no items. Also, the result will take
 * ownership of the pointer and be responsible for cleaning it once the result
 * is destroyed.
 */
struct OpenChecksCheckResult openchecks_check_result_warning(const char *message,
                                                             struct OpenChecksItems *items,
                                                             bool can_fix,
                                                             bool can_skip);

/**
 * The human readable title for the check.
 *
 * User interfaces should use the title for displaying the check.
 *
 * # Safety
 *
 * The pointer should not be null, and point to valid memory.
 */
struct OpenChecksStringView openchecks_check_title(const struct OpenChecksBaseCheck *check);

/**
 * Create a copy of the value contained by the item.
 *
 * # Safety
 *
 * The item pointer must not be null.
 */
struct OpenChecksItem *openchecks_item_clone(const struct OpenChecksItem *item);

/**
 * Create a debug string for the item.
 *
 * # Safety
 *
 * The item pointer must not be null.
 */
struct OpenChecksString openchecks_item_debug(const struct OpenChecksItem *item);

/**
 * Destroy an item and its contents.
 *
 * # Safety
 *
 * The item pointer must not be null, and the item must not be deleted multiple
 * times (AKA: double free).
 */
void openchecks_item_destroy(struct OpenChecksItem *item);

/**
 * Create a display string for the item for users.
 *
 * # Safety
 *
 * The item pointer must not be null.
 */
struct OpenChecksString openchecks_item_display(const struct OpenChecksItem *item);

/**
 * Return if the item is is equal to the other item.
 *
 * This is used for sorting items in user interfaces.
 *
 * # Safety
 *
 * The item pointer must not be null.
 */
bool openchecks_item_eq(const struct OpenChecksItem *item, const struct OpenChecksItem *other);

/**
 * Return if the iterator has finished.
 *
 * # Safety
 *
 * The iterator pointer must not be null.
 */
bool openchecks_item_iterator_is_done(const struct OpenChecksItemsIterator *iterator);

/**
 * Return the pointer to the current item. A null pointer represents no more
 * items.
 *
 * # Safety
 *
 * The iterator pointer must not be null.
 */
const struct OpenChecksItem *openchecks_item_iterator_item(struct OpenChecksItemsIterator *iterator);

/**
 * Return the pointer to the next item. A null pointer represents no more
 * items.
 *
 * # Safety
 *
 * The iterator pointer must not be null.
 */
const struct OpenChecksItem *openchecks_item_iterator_next(struct OpenChecksItemsIterator *iterator);

/**
 * Return if the item is should be before or after the other item.
 *
 * This is used for sorting items in user interfaces.
 *
 * # Safety
 *
 * The item pointer must not be null.
 */
bool openchecks_item_lt(const struct OpenChecksItem *item, const struct OpenChecksItem *other);

/**
 * A type hint can be used to add a hint to a system that the given type
 * represents something else. For example, the value could be a string, but
 * this is a scene path.
 *
 * A user interface could use this hint to select the item in the application.
 *
 * # Safety
 *
 * The item pointer must not be null.
 */
const char *openchecks_item_type_hint(const struct OpenChecksItem *item);

/**
 * The value that is wrapped.
 *
 * # Safety
 *
 * The item pointer must not be null.
 */
const void *openchecks_item_value(const struct OpenChecksItem *item);

/**
 * Clone the items.
 *
 * # Safety
 *
 * The items pointer must not be null.
 */
struct OpenChecksItems *openchecks_items_clone(const struct OpenChecksItems *items);

void openchecks_items_destroy(struct OpenChecksItems *items);

/**
 * Compare two items containers for equality.
 *
 * # Safety
 *
 * The items pointer and the other items pointer can be null. If both are null,
 * then this will return true. If one is null and the other is not, then this
 * will return false.
 */
bool openchecks_items_eq(const struct OpenChecksItems *items,
                         const struct OpenChecksItems *other_items);

/**
 * Get an item from the container.
 *
 * A null pointer is returned if the index is invalid.
 *
 * # Safety
 *
 * The items pointer must not be null.
 */
const struct OpenChecksItem *openchecks_items_get(const struct OpenChecksItems *items,
                                                  size_t index);

/**
 * Get the size of each item in the items. All items must be the same size.
 *
 * # Safety
 *
 * The items pointer must not be null.
 */
size_t openchecks_items_item_size(const struct OpenChecksItems *items);

/**
 * Create a new iterator to iterate over the items.
 *
 * # Safety
 *
 * The items pointer must not be null.
 */
struct OpenChecksItemsIterator openchecks_items_iterator_new(const struct OpenChecksItems *items);

/**
 * Get the length of the items.
 *
 * # Safety
 *
 * The items pointer must not be null.
 */
size_t openchecks_items_length(const struct OpenChecksItems *items);

/**
 * Run a check.
 *
 * # Safety
 *
 * The check pointer must not be null.
 */
struct OpenChecksCheckResult openchecks_run(const struct OpenChecksBaseCheck *check);

/**
 * Return if a check has failed.
 *
 * # Safety
 *
 * The status must not be a null pointer.
 */
bool openchecks_status_has_failed(const enum OpenChecksStatus *status);

/**
 * Return if a check has passed.
 *
 * # Safety
 *
 * The status must not be a null pointer.
 */
bool openchecks_status_has_passed(const enum OpenChecksStatus *status);

/**
 * Return if a check is waiting to be run.
 *
 * # Safety
 *
 * The status must not be a null pointer.
 */
bool openchecks_status_is_pending(const enum OpenChecksStatus *status);

/**
 * Destroy a string pointer.
 *
 * # Safety
 *
 * The pointer must not be null, and must not already have been destroyed (AKA:
 * double free). Once the destroy function is called, all pointers to the
 * string are invalid.
 */
void openchecks_string_destroy(struct OpenChecksString *string);

#endif  /* copenchecks_h */
