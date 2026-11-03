use super::*;

mod background;
mod operations;
mod relocate;
mod state;
mod sync;

#[cfg(test)]
#[path = "../../../../tests/coverage/test_folder_reenrollment.rs"]
mod folder_reenrollment_tests;

#[cfg(test)]
#[path = "../../../../tests/coverage/test_folder_relocation.rs"]
mod folder_relocation_tests;

#[cfg(test)]
#[path = "../../../../tests/coverage/test_enroll_throughput.rs"]
mod enroll_throughput_tests;

#[cfg(test)]
#[path = "../../../../tests/coverage/test_enroll_single_read.rs"]
mod enroll_single_read_tests;

#[cfg(test)]
#[path = "../../../../tests/coverage/test_remove_protection_batches.rs"]
mod remove_protection_batches_tests;

#[cfg(test)]
#[path = "../../../../tests/coverage/test_enroll_disguised_ciphertext.rs"]
mod enroll_disguised_ciphertext_tests;

#[cfg(test)]
#[path = "../../../../tests/coverage/test_coverage_watcher_stop.rs"]
mod coverage_watcher_stop_tests;

#[cfg(test)]
#[path = "../../../../tests/coverage/test_folder_record_operations.rs"]
mod folder_record_operations_tests;
