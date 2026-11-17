use helios_api::bindings::wasi::clocks::monotonic_clock;
use helios_api::sync::{SignalSource, TimelineError, wait_all, wait_any};
use helios_api::task;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("shared timeline refused: {0}")]
    Timeline(#[from] TimelineError),
    #[error("shared timeline violated {0}")]
    Contract(&'static str),
}

pub async fn run() -> Result<(), Error> {
    let left = SignalSource::new(0);
    let right = SignalSource::new(0);
    let left_reader = left.reader();
    let right_reader = right.reader();
    let points = [left_reader.point(1), right_reader.point(2)];
    let now = monotonic_clock::now();
    if wait_any(&points, Some(now)).await? {
        return Err(Error::Contract("an expired unsignaled wait"));
    }
    left.signal(1)?;
    left.signal(0)?;
    if left_reader.value()? != 1 {
        return Err(Error::Contract("monotonic progress"));
    }
    if !wait_any(&points, Some(now)).await? || wait_all(&points, Some(now)).await? {
        return Err(Error::Contract("wait-any versus wait-all"));
    }
    task::spawn(async move {
        task::yield_now().await;
        right.signal(2).expect("live timeline accepts its producer");
    });
    // Bound a lost-wake regression by the smoke operation's five-second budget.
    let deadline = monotonic_clock::now() + 5_000_000_000;
    if !wait_all(&points, Some(deadline)).await? || right_reader.value()? != 2 {
        return Err(Error::Contract("a future signal waking its waiter"));
    }
    drop(left);
    if !matches!(
        wait_all(&[left_reader.point(2)], Some(deadline)).await,
        Err(TimelineError::Closed)
    ) {
        return Err(Error::Contract(
            "producer closure waking an unreachable point",
        ));
    }
    if !wait_all(&[left_reader.point(1)], Some(now)).await? {
        return Err(Error::Contract(
            "completed values surviving producer closure",
        ));
    }
    let failed = SignalSource::new(0);
    let failed_reader = failed.reader();
    task::spawn(async move {
        task::yield_now().await;
        failed.fail();
    });
    if !matches!(
        wait_all(&[failed_reader.point(1)], Some(deadline)).await,
        Err(TimelineError::Failed)
    ) || !matches!(failed_reader.value(), Err(TimelineError::Failed))
    {
        return Err(Error::Contract(
            "producer failure waking an unreachable point",
        ));
    }
    println!("gpu-test:shared-timelines ok");
    Ok(())
}
