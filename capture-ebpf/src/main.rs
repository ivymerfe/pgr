#![no_std]
#![no_main]

mod global;
mod tc_classifier;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
