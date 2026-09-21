//! Platform-aware task spawning.

use std::future::Future;

use futures::{FutureExt, channel::oneshot};
use tlsn::SessionDriver;

use crate::{
    error::{Result, SdkError},
    io::Io,
};

pub(crate) type BoxIo = Box<dyn Io>;

pub(crate) struct DriverTask(oneshot::Receiver<tlsn::Result<BoxIo>>);

impl DriverTask {
    pub(crate) fn spawn(driver: SessionDriver<BoxIo>) -> Self {
        let (sender, receiver) = oneshot::channel();
        spawn(async move {
            let result = driver.await;
            match &result {
                Ok(_) => tracing::warn!("session driver completed (mux closed)"),
                Err(error) => tracing::error!("session driver error: {error}"),
            }
            let _ = sender.send(result);
        });
        Self(receiver)
    }

    /// A dead session cannot finish an outstanding setup or HTTP operation.
    pub(crate) async fn during<T>(
        &mut self,
        operation: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let operation = operation.fuse();
        futures::pin_mut!(operation);
        futures::select_biased! {
            result = operation => result,
            result = (&mut self.0).fuse() => {
                let result = result.map_err(|_| SdkError::internal("session driver task dropped"))?;
                Err(match result {
                    Ok(_) => SdkError::protocol("session closed before operation completed"),
                    Err(error) => SdkError::protocol(format!("session driver: {error}")),
                })
            }
        }
    }

    pub(crate) async fn finish(self) -> Result<BoxIo> {
        self.0
            .await
            .map_err(|_| SdkError::internal("session driver task dropped"))?
            .map_err(Into::into)
    }
}

/// Spawns a future on the appropriate runtime.
#[cfg(feature = "wasm")]
pub(crate) fn spawn(future: impl Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(future);
}

/// Spawns a future on the appropriate runtime.
#[cfg(not(feature = "wasm"))]
pub(crate) fn spawn(future: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(future);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket() -> BoxIo {
        Box::new(futures::io::Cursor::new(Vec::<u8>::new()))
    }

    #[test]
    fn dead_driver_interrupts_pending_work() {
        futures::executor::block_on(async {
            for result in [
                Ok(socket()),
                Err(std::io::Error::other("disconnected").into()),
            ] {
                let (sender, receiver) = oneshot::channel();
                sender.send(result).ok().unwrap();
                let error = DriverTask(receiver)
                    .during(std::future::pending::<Result<()>>())
                    .await
                    .unwrap_err();
                assert!(error.to_string().contains("session"));
            }
        });
    }

    #[test]
    fn completed_work_preserves_a_clean_driver_result_for_finish() {
        futures::executor::block_on(async {
            let (sender, receiver) = oneshot::channel();
            let mut driver = DriverTask(receiver);
            // Even if completion is already queued, ready protocol work wins.
            sender.send(Ok(socket())).ok().unwrap();
            assert_eq!(driver.during(async { Ok(42) }).await.unwrap(), 42);
            driver.finish().await.unwrap();
        });
    }
}
