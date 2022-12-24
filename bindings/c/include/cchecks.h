#ifndef cchecks_h
#define cchecks_h

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef enum CChecksAutoFixStatus {
  CChecksAutoFixStatusOk,
  CChecksAutoFixStatusError,
} CChecksAutoFixStatus;

typedef enum CChecksStatus {
  CChecksStatusPending,
  CChecksStatusSkipped,
  CChecksStatusPassed,
  CChecksStatusWarning,
  CChecksStatusFailed,
  CChecksStatusSystemError,
} CChecksStatus;

typedef struct CChecksItem {
  const char *(*type_hint_fn)(const struct CChecksItem*);
  const void *(*value_fn)(const struct CChecksItem*);
  void (*clone_fn)(const struct CChecksItem*, struct CChecksItem*);
  void (*destroy_fn)(struct CChecksItem*);
  char *(*debug_fn)(const struct CChecksItem*);
  char *(*display_fn)(const struct CChecksItem*);
  bool (*lt_fn)(const struct CChecksItem*, const struct CChecksItem*);
  bool (*eq_fn)(const struct CChecksItem*, const struct CChecksItem*);
} CChecksItem;

typedef struct CChecksItems {
  struct CChecksItem *ptr;
  size_t item_size;
  size_t length;
  void (*destroy_fn)(struct CChecksItem*);
} CChecksItems;

typedef struct CChecksCheckResult {
  enum CChecksStatus status;
  char *message;
  struct CChecksItems *items;
  bool can_fix;
  bool can_skip;
  char *error;
  double check_duration;
  double fix_duration;
} CChecksCheckResult;

typedef uint8_t CChecksCheckHint;

typedef struct CChecksAutoFixResult {
  enum CChecksAutoFixStatus status;
  char *message;
} CChecksAutoFixResult;

typedef struct CChecksBaseCheck {
  const char *(*title_fn)(const struct CChecksBaseCheck*);
  const char *(*description_fn)(const struct CChecksBaseCheck*);
  CChecksCheckHint (*hint_fn)(const struct CChecksBaseCheck*);
  struct CChecksCheckResult (*check_fn)(const struct CChecksBaseCheck*);
  struct CChecksAutoFixResult (*auto_fix_fn)(const struct CChecksBaseCheck*);
} CChecksBaseCheck;

typedef struct CChecksStringView {
  const char *string;
} CChecksStringView;

typedef struct CChecksString {
  char *string;
} CChecksString;

typedef struct CChecksItemsIterator {
  const struct CChecksItems *items;
  size_t index;
} CChecksItemsIterator;

#define CCHECKS_CHECK_HINT_AUTO_FIX 1

#define CCHECKS_CHECK_HINT_NONE 0

struct CChecksCheckResult cchecks_auto_fix(struct CChecksBaseCheck *check);

struct CChecksAutoFixResult cchecks_check_auto_fix_error(const char *message);

struct CChecksAutoFixResult cchecks_check_auto_fix_ok(void);

struct CChecksStringView cchecks_check_description(const struct CChecksBaseCheck *check);

CChecksCheckHint cchecks_check_hint(const struct CChecksBaseCheck *check);

bool cchecks_check_result_can_fix(const struct CChecksCheckResult *result);

bool cchecks_check_result_can_skip(const struct CChecksCheckResult *result);

double cchecks_check_result_check_duration(const struct CChecksCheckResult *result);

void cchecks_check_result_destroy(struct CChecksCheckResult *result);

struct CChecksStringView cchecks_check_result_error(const struct CChecksCheckResult *result);

struct CChecksCheckResult cchecks_check_result_failed(const char *message,
                                                      struct CChecksItem *items,
                                                      size_t item_size,
                                                      size_t item_count,
                                                      bool can_fix,
                                                      bool can_skip,
                                                      void (*items_destroy_fn)(struct CChecksItem*));

double cchecks_check_result_fix_duration(const struct CChecksCheckResult *result);

const struct CChecksItems *cchecks_check_result_items(const struct CChecksCheckResult *result);

struct CChecksStringView cchecks_check_result_message(const struct CChecksCheckResult *result);

struct CChecksCheckResult cchecks_check_result_new(enum CChecksStatus status,
                                                   const char *message,
                                                   struct CChecksItem *items,
                                                   size_t item_size,
                                                   size_t item_count,
                                                   bool can_fix,
                                                   bool can_skip,
                                                   const char *error,
                                                   void (*items_destroy_fn)(struct CChecksItem*));

struct CChecksCheckResult cchecks_check_result_passed(const char *message,
                                                      struct CChecksItem *items,
                                                      size_t item_size,
                                                      size_t item_count,
                                                      bool can_fix,
                                                      bool can_skip,
                                                      void (*items_destroy_fn)(struct CChecksItem*));

struct CChecksCheckResult cchecks_check_result_skipped(const char *message,
                                                       struct CChecksItem *items,
                                                       size_t item_size,
                                                       size_t item_count,
                                                       bool can_fix,
                                                       bool can_skip,
                                                       void (*items_destroy_fn)(struct CChecksItem*));

enum CChecksStatus cchecks_check_result_status(const struct CChecksCheckResult *result);

struct CChecksCheckResult cchecks_check_result_warning(const char *message,
                                                       struct CChecksItem *items,
                                                       size_t item_size,
                                                       size_t item_count,
                                                       bool can_fix,
                                                       bool can_skip,
                                                       void (*items_destroy_fn)(struct CChecksItem*));

struct CChecksStringView cchecks_check_title(const struct CChecksBaseCheck *check);

void cchecks_item_clone(const struct CChecksItem *item, struct CChecksItem *new_item);

struct CChecksString cchecks_item_debug(const struct CChecksItem *item);

void cchecks_item_destroy(struct CChecksItem *item);

struct CChecksString cchecks_item_display(const struct CChecksItem *item);

bool cchecks_item_eq(const struct CChecksItem *item, const struct CChecksItem *other);

bool cchecks_item_iterator_is_done(const struct CChecksItemsIterator *iterator);

const struct CChecksItem *cchecks_item_iterator_item(struct CChecksItemsIterator *iterator);

const struct CChecksItem *cchecks_item_iterator_next(struct CChecksItemsIterator *iterator);

bool cchecks_item_lt(const struct CChecksItem *item, const struct CChecksItem *other);

const char *cchecks_item_type_hint(const struct CChecksItem *item);

const void *cchecks_item_value(const struct CChecksItem *item);

struct CChecksItemsIterator cchecks_items_iterator_new(const struct CChecksItems *items);

struct CChecksItems cchecks_items_new(struct CChecksItem *items,
                                      size_t item_size,
                                      size_t length,
                                      void (*destroy_fn)(struct CChecksItem*));

struct CChecksCheckResult cchecks_run(const struct CChecksBaseCheck *check);

bool cchecks_status_has_failed(const enum CChecksStatus *status);

bool cchecks_status_has_passed(const enum CChecksStatus *status);

bool cchecks_status_is_pending(const enum CChecksStatus *status);

void cchecks_string_destroy(struct CChecksString *string);

#endif /* cchecks_h */
