openchecks package
==================

String Wrapper
--------------

Owned String Wrapper
~~~~~~~~~~~~~~~~~~~~

.. doxygenstruct:: OpenChecksString
    :members:

.. doxygenfunction:: openchecks_string_destroy

Borrowed String Wrapper
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenstruct:: OpenChecksStringView
    :members:

Check
-----

Check Hint
~~~~~~~~~~

.. doxygentypedef:: OpenChecksCheckHint
.. doxygendefine:: OPENCHECKS_CHECK_HINT_AUTO_FIX
.. doxygendefine:: OPENCHECKS_CHECK_HINT_NONE

Base Check
~~~~~~~~~~

.. doxygenstruct:: OpenChecksBaseCheck
    :members:

.. doxygenfunction:: openchecks_check_title
.. doxygenfunction:: openchecks_check_description
.. doxygenfunction:: openchecks_check_hint

Check Auto Fix Result
~~~~~~~~~~~~~~~~~~~~~

.. doxygenenum:: OpenChecksAutoFixStatus

.. doxygenstruct:: OpenChecksAutoFixResult
    :members:

.. doxygenfunction:: openchecks_check_auto_fix_ok
.. doxygenfunction:: openchecks_check_auto_fix_error

Item
----

.. doxygenstruct:: OpenChecksItem
    :members:

.. doxygenfunction:: openchecks_item_type_hint
.. doxygenfunction:: openchecks_item_value
.. doxygenfunction:: openchecks_item_clone
.. doxygenfunction:: openchecks_item_destroy
.. doxygenfunction:: openchecks_item_debug
.. doxygenfunction:: openchecks_item_display
.. doxygenfunction:: openchecks_item_lt
.. doxygenfunction:: openchecks_item_eq

Items
-----

Items Container
~~~~~~~~~~~~~~~

.. doxygenstruct:: OpenChecksItems
    :members:

.. doxygenfunction:: openchecks_items_new

Items Iterator
~~~~~~~~~~~~~~

.. doxygenstruct:: OpenChecksItemsIterator
    :members:

.. doxygenfunction:: openchecks_items_iterator_new
.. doxygenfunction:: openchecks_item_iterator_next
.. doxygenfunction:: openchecks_item_iterator_item
.. doxygenfunction:: openchecks_item_iterator_is_done

Result
------

.. doxygenstruct:: OpenChecksCheckResult
    :members:

.. doxygenfunction:: openchecks_check_result_new
.. doxygenfunction:: openchecks_check_result_passed
.. doxygenfunction:: openchecks_check_result_skipped
.. doxygenfunction:: openchecks_check_result_warning
.. doxygenfunction:: openchecks_check_result_failed
.. doxygenfunction:: openchecks_check_result_status
.. doxygenfunction:: openchecks_check_result_message
.. doxygenfunction:: openchecks_check_result_items
.. doxygenfunction:: openchecks_check_result_can_fix
.. doxygenfunction:: openchecks_check_result_can_skip
.. doxygenfunction:: openchecks_check_result_error
.. doxygenfunction:: openchecks_check_result_check_duration
.. doxygenfunction:: openchecks_check_result_fix_duration

Runners
-------

.. doxygenfunction:: openchecks_run
.. doxygenfunction:: openchecks_auto_fix

Status
------

.. doxygenenum:: OpenChecksStatus

.. doxygenfunction:: openchecks_status_is_pending
.. doxygenfunction:: openchecks_status_has_passed
.. doxygenfunction:: openchecks_status_has_failed
