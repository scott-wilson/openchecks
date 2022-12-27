cchecks package
===============

String Wrapper
--------------

Owned String Wrapper
~~~~~~~~~~~~~~~~~~~~

.. doxygenstruct:: CChecksString
    :members:

.. doxygenfunction:: cchecks_string_destroy

Borrowed String Wrapper
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenstruct:: CChecksStringView
    :members:

Check
-----

Check Hint
~~~~~~~~~~

.. doxygentypedef:: CChecksCheckHint
.. doxygendefine:: CCHECKS_CHECK_HINT_AUTO_FIX
.. doxygendefine:: CCHECKS_CHECK_HINT_NONE

Base Check
~~~~~~~~~~

.. doxygenstruct:: CChecksBaseCheck
    :members:

.. doxygenfunction:: cchecks_check_title
.. doxygenfunction:: cchecks_check_description
.. doxygenfunction:: cchecks_check_hint

Check Auto Fix Result
~~~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: CChecksAutoFixStatus

.. doxygenstruct:: CChecksAutoFixResult
    :members:

.. doxygenfunction:: cchecks_check_auto_fix_ok
.. doxygenfunction:: cchecks_check_auto_fix_error

Item
----

.. doxygenstruct:: CChecksItem
    :members:

.. doxygenfunction:: cchecks_item_type_hint
.. doxygenfunction:: cchecks_item_value
.. doxygenfunction:: cchecks_item_clone
.. doxygenfunction:: cchecks_item_destroy
.. doxygenfunction:: cchecks_item_debug
.. doxygenfunction:: cchecks_item_display
.. doxygenfunction:: cchecks_item_lt
.. doxygenfunction:: cchecks_item_eq

Items
-----

Items Container
~~~~~~~~~~~~~~~

.. doxygenstruct:: CChecksItems
    :members:

.. doxygenfunction:: cchecks_items_new

Items Iterator
~~~~~~~~~~~~~~

.. doxygenstruct:: CChecksItemsIterator
    :members:

.. doxygenfunction:: cchecks_items_iterator_new
.. doxygenfunction:: cchecks_item_iterator_next
.. doxygenfunction:: cchecks_item_iterator_item
.. doxygenfunction:: cchecks_item_iterator_is_done

Result
------

.. doxygenstruct:: CChecksCheckResult
    :members:

.. doxygenfunction:: cchecks_check_result_new
.. doxygenfunction:: cchecks_check_result_passed
.. doxygenfunction:: cchecks_check_result_skipped
.. doxygenfunction:: cchecks_check_result_warning
.. doxygenfunction:: cchecks_check_result_failed
.. doxygenfunction:: cchecks_check_result_status
.. doxygenfunction:: cchecks_check_result_message
.. doxygenfunction:: cchecks_check_result_items
.. doxygenfunction:: cchecks_check_result_can_fix
.. doxygenfunction:: cchecks_check_result_can_skip
.. doxygenfunction:: cchecks_check_result_error
.. doxygenfunction:: cchecks_check_result_check_duration
.. doxygenfunction:: cchecks_check_result_fix_duration

Runners
-------

.. doxygenfunction:: cchecks_run
.. doxygenfunction:: cchecks_auto_fix

Status
------

.. doxygenenum:: CChecksStatus

.. doxygenfunction:: cchecks_status_is_pending
.. doxygenfunction:: cchecks_status_has_passed
.. doxygenfunction:: cchecks_status_has_failed
