use cchecks::*;
mod common;
use common::*;

/* ----------------------------------------------------------------------------
  Checks
*/
#[test]
fn test_always_pass_check() {
    unsafe {
        let check = create_always_pass_check();
        let mut result = cchecks_run(&check as *const AlwaysPassCheck as *const CChecksBaseCheck);
        assert_eq!(cchecks_status_has_passed(&result.status), true);
        cchecks_check_result_destroy(&mut result);
    }
}

#[test]
fn test_always_fail_check() {
    unsafe {
        let check = create_always_fail_check();
        let mut result = cchecks_run(&check as *const AlwaysFailCheck as *const CChecksBaseCheck);
        assert_eq!(cchecks_status_has_passed(&result.status), false);
        cchecks_check_result_destroy(&mut result);
    }
}

#[test]
fn test_pass_on_fix_check() {
    unsafe {
        let mut check = create_pass_on_fix_check();
        let mut result = cchecks_run(&check as *const PassOnFixCheck as *const CChecksBaseCheck);
        assert_eq!(cchecks_status_has_passed(&result.status), false);
        cchecks_check_result_destroy(&mut result);

        let mut result =
            cchecks_auto_fix(&mut check as *mut PassOnFixCheck as *mut CChecksBaseCheck);
        assert_eq!(cchecks_status_has_passed(&result.status), true);
        cchecks_check_result_destroy(&mut result);
    }
}

#[test]
fn test_fail_on_fix_check() {
    unsafe {
        let mut check = create_fail_on_fix_check();
        let mut result = cchecks_run(&check as *const FailOnFixCheck as *const CChecksBaseCheck);
        assert_eq!(cchecks_status_has_passed(&result.status), false);
        cchecks_check_result_destroy(&mut result);

        let mut result =
            cchecks_auto_fix(&mut check as *mut FailOnFixCheck as *mut CChecksBaseCheck);
        assert_eq!(cchecks_status_has_passed(&result.status), false);
        cchecks_check_result_destroy(&mut result);
    }
}

#[test]
fn test_no_auto_fix_flag_check() {
    unsafe {
        let mut check = create_no_auto_fix_flag_check();
        let mut result =
            cchecks_auto_fix(&mut check as *mut NoAutoFixFlagCheck as *mut CChecksBaseCheck);
        assert_eq!(
            result.status as u8,
            CChecksStatus::CChecksStatusSystemError as u8
        );
        cchecks_check_result_destroy(&mut result);
    }
}
