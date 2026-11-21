//! Does one stream whose reader stops reading stall the others? (Receive
//! backpressure must stay per stream.)
//!
//! Runs on paused time: tokio only jumps the clock when every task is idle,
//! so a timeout firing proves nothing can make progress, without real waits.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tunnel_protocol::mux::Session;

const WINDOW: usize = yamux::DEFAULT_CREDIT as usize;
/// More than the stream's receive window, so the flood must be held back.
const FLOOD: usize = 4 * WINDOW;

#[tokio::test(start_paused = true)]
async fn unread_stream_does_not_stall_others() {
    // Far larger than the flood's window, so only yamux can hold it back.
    let (a, b) = tokio::io::duplex(8 * FLOOD);
    let mut client = Session::new_client(a);
    let mut client_ctl = client.control();
    tokio::spawn(async move { while client.next().await.is_some() {} });

    // Server: a stream that starts with `F` floods; any other one echoes.
    let written = Arc::new(AtomicUsize::new(0));
    let (flooded_tx, flooded_rx) = oneshot::channel::<()>();
    let mut server = Session::new_server(b);
    let counter = written.clone();
    tokio::spawn(async move {
        let mut flooded_tx = Some(flooded_tx);
        let mut counter = Some(counter);
        while let Some(mut s) = server.next().await {
            let flood = (flooded_tx.take(), counter.take());
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if s.read_exact(&mut first).await.is_err() {
                    return;
                }
                if first[0] == b'F' {
                    let (Some(done), Some(counter)) = flood else { return };
                    let chunk = [b'x'; 16 * 1024];
                    while counter.load(Ordering::SeqCst) < FLOOD {
                        let Ok(n) = s.write(&chunk).await else { return };
                        let _ = s.flush().await;
                        counter.fetch_add(n, Ordering::SeqCst);
                    }
                    let _ = done.send(());
                } else {
                    let _ = s.write_all(b"pong").await;
                    let _ = s.flush().await;
                }
                std::future::pending::<()>().await;
            });
        }
    });

    // Stream 1 asks for a flood, then is never read.
    let mut flood = client_ctl.open_stream().await.unwrap();
    flood.write_all(b"F").await.unwrap();
    flood.flush().await.unwrap();
    // Fires only once every task is idle: the flood is stuck on its window.
    let finished = tokio::time::timeout(Duration::from_secs(10), flooded_rx).await;
    assert!(finished.is_err(), "the unread stream was not held back: {finished:?}");
    let sent = written.load(Ordering::SeqCst);
    assert!((WINDOW..FLOOD).contains(&sent), "flood stopped at {sent} bytes, window {WINDOW}");

    // Stream 2 must still work.
    let mut other = client_ctl.open_stream().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        other.write_all(b"P").await?;
        other.flush().await?;
        let mut buf = [0u8; 4];
        other.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    })
    .await;
    assert_eq!(written.load(Ordering::SeqCst), sent, "the flood moved while it was unread");
    drop(flood);
    assert!(matches!(result, Ok(Ok(b)) if &b == b"pong"), "second stream stalled: {result:?}");
}
