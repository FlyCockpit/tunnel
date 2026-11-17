//! User-facing subcommands. Each talks to the daemon over IPC.

use std::io;
use std::os::unix::process::CommandExt;
use std::time::Duration;

use anyhow::bail;
use tokio::net::UnixStream;

use crate::IceFormat;
use crate::ice;
use crate::ipc::{ConnState, Reach, Request, Response, Status, call, call_on, ensure_daemon};
use crate::paths::{ENV_SERVER, ENV_TARGET, ENV_TOKEN, Paths, env_nonempty, env_token};
use crate::state::Persisted;

/// Covers the daemon's per-port server round trips plus its connect wait.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) enum Answer {
    Response(Response),
    /// Already reported; exit with this code.
    Exit(i32),
    Stopped,
}

pub(crate) async fn ask(req: Request, takeover: bool, json: bool) -> anyhow::Result<Answer> {
    let paths = Paths::resolve()?;
    let (token, server, target) = match &req {
        Request::Expose { token, server, target, .. } => (token.as_deref(), server.as_deref(), target.as_deref()),
        _ => (None, None, None),
    };
    let reach = ensure_daemon(&paths, takeover, token, server, target).await?;
    let reach = match (reach, target) {
        (Reach::Running(mut stream), Some(_)) => {
            require_target_support(&mut stream).await?;
            Reach::Running(stream)
        }
        (reach, _) => reach,
    };
    match reach {
        Reach::Running(stream) => match call(stream, &req, REQUEST_TIMEOUT).await? {
            Some(Response::Error { message }) => bail!("{message}"),
            Some(resp) => Ok(Answer::Response(resp)),
            None => daemon_gone(&paths, json).map(Answer::Exit),
        },
        Reach::Terminal(p, state) => Ok(Answer::Exit(report_terminal(&p, state, json))),
        Reach::Stopped => Ok(Answer::Stopped),
    }
}

/// A daemon started by an older binary would ignore the target and expose
/// loopback; ask first, before anything is exposed, on the same connection
/// the Expose then uses (so both reach the same daemon).
async fn require_target_support(stream: &mut UnixStream) -> anyhow::Result<()> {
    let supported = match call_on(stream, &Request::Status, REQUEST_TIMEOUT).await? {
        Some(Response::Status { status }) => status.features.iter().any(|f| f == "target"),
        _ => false,
    };
    if !supported {
        bail!("the running daemon does not support --target / {ENV_TARGET}; run `tunnel stop` and try again");
    }
    Ok(())
}

fn report_terminal(p: &Persisted, state: ConnState, json: bool) -> i32 {
    let status = Status::from_persisted(p, state);
    status.print(json);
    status.exit_code()
}

/// The daemon hung up mid-request: it exited, usually on revocation.
fn daemon_gone(paths: &Paths, json: bool) -> anyhow::Result<i32> {
    match Persisted::load(&paths.state_file) {
        Some(p) if p.revoked => Ok(report_terminal(&p, ConnState::Revoked, json)),
        Some(p) if p.replaced => Ok(report_terminal(&p, ConnState::Replaced, json)),
        _ => bail!("daemon exited unexpectedly; see {}", paths.log_file.display()),
    }
}

/// `--target`, else `$TUNNEL_TARGET_HOST`; validated (IP literals only).
pub(crate) fn resolve_target(flag: Option<String>) -> anyhow::Result<Option<String>> {
    match flag {
        Some(t) => Ok(Some(crate::paths::parse_target(&t)?.to_string())),
        None => Ok(crate::paths::env_target()?.map(|ip| ip.to_string())),
    }
}

fn expect_status(resp: Response) -> anyhow::Result<Status> {
    match resp {
        Response::Status { status } => Ok(status),
        _ => bail!("unexpected daemon response"),
    }
}

pub async fn expose(ports: Vec<u16>, target: Option<String>) -> anyhow::Result<i32> {
    // The server: $TUNNEL_SERVER, else the one this machine logged in to
    // (the daemon falls back to its saved server, then the build-time default).
    let server = env_nonempty(ENV_SERVER).or_else(|| crate::login::Login::load().ok().flatten().map(|l| l.server));
    let target = resolve_target(target)?;
    let req = Request::Expose { ports, token: env_token()?, server, target };
    match ask(req, true, false).await? {
        Answer::Response(resp) => {
            let status = expect_status(resp)?;
            status.print(false);
            Ok(status.exit_code())
        }
        Answer::Exit(code) => Ok(code),
        Answer::Stopped => bail!("no tunnel token: set {ENV_TOKEN}"),
    }
}

pub async fn unexpose(port: u16) -> anyhow::Result<i32> {
    match ask(Request::Unexpose { port }, false, false).await? {
        Answer::Response(resp) => {
            let status = expect_status(resp)?;
            status.print(false);
            Ok(status.exit_code())
        }
        Answer::Exit(code) => Ok(code),
        Answer::Stopped => bail!("the tunnel daemon is not running"),
    }
}

pub async fn status(json: bool) -> anyhow::Result<i32> {
    let status = match ask(Request::Status, false, json).await? {
        Answer::Response(resp) => expect_status(resp)?,
        Answer::Exit(code) => return Ok(code),
        Answer::Stopped => Status::stopped(),
    };
    status.print(json);
    Ok(status.exit_code())
}

pub async fn ice(format: IceFormat, fresh: bool, exec: Vec<String>) -> anyhow::Result<i32> {
    let (config, ice_file, endpoint) = match ask(Request::Ice { fresh }, false, false).await? {
        Answer::Response(Response::Ice { ice, ice_file, ice_url, ice_token }) => {
            (ice, ice_file, ice_url.zip(ice_token))
        }
        Answer::Response(_) => bail!("unexpected daemon response"),
        Answer::Exit(code) => return Ok(code),
        Answer::Stopped => bail!("the tunnel daemon is not running; run `tunnel expose <PORT>` first"),
    };
    let mut vars = ice::env_vars(&config, &ice_file);
    if let Some((url, token)) = endpoint {
        vars.push(("TUNNEL_ICE_URL", url));
        vars.push(("TUNNEL_ICE_TOKEN", token));
    }
    if let Some((program, args)) = exec.split_first() {
        // Replaces this process, so the command keeps the caller's stdio and exit status.
        let err = std::process::Command::new(program).args(args).envs(vars).exec();
        bail!("exec {program}: {err}");
    }
    match format {
        IceFormat::Env => print!("{}", ice::format_env(&vars)),
        IceFormat::Json => println!("{}", serde_json::to_string_pretty(&config)?),
        IceFormat::File => println!("{ice_file}"),
    }
    Ok(0)
}

pub async fn stop() -> anyhow::Result<i32> {
    let paths = Paths::resolve()?;
    // A tunnel `share` created is deleted on the server, not just disconnected.
    let deleted = crate::share::delete_shared(&paths).await;
    stop_daemon(&paths, deleted).await
}

async fn stop_daemon(paths: &Paths, deleted: bool) -> anyhow::Result<i32> {
    if let Ok(stream) = UnixStream::connect(&paths.socket).await {
        // The daemon replies, deletes its state, and exits.
        if let Some(Response::Error { message }) = call(stream, &Request::Stop, REQUEST_TIMEOUT).await? {
            bail!("{message}");
        }
    }
    // No daemon (or it already exited): make sure nothing restarts it from state.
    match std::fs::remove_file(&paths.state_file) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => bail!("removing {}: {e}", paths.state_file.display()),
    }
    println!("stopped");
    Ok(if deleted { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;
    use tokio::net::UnixListener;
    use tunnel_protocol::{read_json_line, write_json_line};

    #[tokio::test]
    async fn stop_still_stops_daemon_and_fails_when_shared_deletion_failed() {
        let dir = std::env::temp_dir().join(format!("tunnel-stop-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let paths = Paths {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        };
        std::fs::write(&paths.state_file, b"state").unwrap();
        std::fs::write(paths.dir.join("share.json"), b"retry").unwrap();
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let request = read_json_line::<_, Request>(&mut BufReader::new(rd), &mut String::new()).await.unwrap();
            assert!(matches!(request, Some(Request::Stop)));
            write_json_line(&mut wr, &Response::Status { status: Status::stopped() }).await.unwrap();
        });
        assert_eq!(stop_daemon(&paths, false).await.unwrap(), 1);
        peer.await.unwrap();
        assert!(!paths.state_file.exists());
        assert!(paths.dir.join("share.json").exists());
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }

    /// A daemon that answers every request with a status listing `features`.
    async fn fake_daemon(features: Vec<String>) -> Paths {
        let dir = std::env::temp_dir().join(format!("tunnel-cmd-test-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let paths = Paths {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        };
        let listener = UnixListener::bind(&paths.socket).unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let features = features.clone();
                tokio::spawn(async move {
                    let (rd, mut wr) = stream.into_split();
                    let mut rd = BufReader::new(rd);
                    let mut buf = String::new();
                    while let Ok(Some(_)) = read_json_line::<_, Request>(&mut rd, &mut buf).await {
                        let status = Status { features: features.clone(), ..Status::stopped() };
                        let _ = write_json_line(&mut wr, &Response::Status { status }).await;
                    }
                });
            }
        });
        paths
    }

    #[tokio::test]
    async fn targeted_expose_refuses_a_daemon_without_target_support() {
        let paths = fake_daemon(Vec::new()).await;
        let mut stream = UnixStream::connect(&paths.socket).await.unwrap();
        let err = require_target_support(&mut stream).await.unwrap_err().to_string();
        assert!(err.contains("does not support --target"), "{err}");
        std::fs::remove_dir_all(&paths.dir).unwrap();

        let paths = fake_daemon(vec!["target".into()]).await;
        let mut stream = UnixStream::connect(&paths.socket).await.unwrap();
        require_target_support(&mut stream).await.unwrap();
        // The request then goes to the same daemon on the same connection,
        // even if the socket path is replaced in between.
        std::fs::remove_file(&paths.socket).unwrap();
        let answer = call(stream, &Request::Status, REQUEST_TIMEOUT).await.unwrap();
        assert!(matches!(answer, Some(Response::Status { .. })));
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }
}
