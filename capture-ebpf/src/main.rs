#![no_std]
#![no_main]

mod global;

#[allow(dangerous_implicit_autorefs)]
mod tc_classifier;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
