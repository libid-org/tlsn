//! Keeps the calling thread's event loop turning while protocol work runs.
//!
//! Protocol futures run on the calling thread under `wasm-bindgen-futures`,
//! which resumes a future woken from another thread (the mpz executor's
//! workers) by resolving an `Atomics.waitAsync` promise. WebKit can strand
//! that resolution in a dedicated worker: the notifying thread arms the
//! waiting VM's deferred-work timer, but the worker's run loop is woken for it
//! only if the timer is armed while the worker is already blocked, and the
//! armed timer suppresses later wake-ups. The worker then sleeps until an
//! unrelated event arrives. In protocol phases without network traffic none
//! does, and the session stalls for good. Any turn of the event loop services
//! the armed timer, so a no-op interval bounds such a stall to one period.

use std::cell::RefCell;

use wasm_bindgen::prelude::*;

/// The interval period, and so the longest a stranded wake-up waits.
const PERIOD_MS: i32 = 10;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = setInterval)]
    fn set_interval(handler: &Closure<dyn FnMut()>, timeout: i32) -> JsValue;

    #[wasm_bindgen(js_name = clearInterval)]
    fn clear_interval(handle: &JsValue);
}

struct Interval {
    handle: JsValue,
    _handler: Closure<dyn FnMut()>,
    holders: usize,
}

thread_local! {
    static INTERVAL: RefCell<Option<Interval>> = const { RefCell::new(None) };
}

/// Runs the no-op interval on this thread while any `Heartbeat` is alive.
#[must_use = "the heartbeat stops when dropped"]
pub(crate) struct Heartbeat(());

impl Heartbeat {
    pub(crate) fn start() -> Self {
        INTERVAL.with_borrow_mut(|slot| match slot {
            Some(interval) => interval.holders += 1,
            None => {
                let handler = Closure::new(|| {});
                let handle = set_interval(&handler, PERIOD_MS);
                *slot = Some(Interval {
                    handle,
                    _handler: handler,
                    holders: 1,
                });
            }
        });
        Self(())
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        INTERVAL.with_borrow_mut(|slot| {
            let interval = slot.as_mut().expect("a live heartbeat holds the interval");
            interval.holders -= 1;
            if interval.holders == 0 {
                clear_interval(&interval.handle);
                *slot = None;
            }
        });
    }
}
