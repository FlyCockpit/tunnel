//! User-facing subcommands. Each talks to the daemon over IPC.

use std::io;
use std::os::unix::process::CommandExt;
use std::time::Duration;

use anyhow::bail;
use tokio::net::UnixStream;

use crate::IceFormat;
use crate::ice;
use crate::ipc::{Answer, REQUEST_TIMEOUT, Report, Request, Response, Status, ask, call};
use crate::paths::{ENV_SERVER, ENV_TOKEN, Paths, env_nonempty, env_token, resolve_target};

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
    match ask(req, true, Report::Text).await? {
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
    match ask(Request::Unexpose { port, expect: None }, false, Report::Text).await? {
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
    let report = if json { Report::Json } else { Report::Text };
    let status = match ask(Request::Status, false, report).await? {
        Answer::Response(resp) => expect_status(resp)?,
        Answer::Exit(code) => return Ok(code),
        Answer::Stopped => Status::stopped(),
    };
    let info = match &status.tunnel_id {
        Some(id) => server_tunnel(id).await,
        None => None,
    };
    status.print_access(json, info.as_ref().map(|i| &i.access), info.as_ref().and_then(|i| i.name.as_deref()));
    Ok(status.exit_code())
}

/// The tunnel's access settings and name, when this machine's login can
/// read it (best effort: nothing when logged out, offline, or not its tunnel).
async fn server_tunnel(tunnel_id: &str) -> Option<crate::login::TunnelInfo> {
    let login = crate::login::Login::load().ok().flatten()?;
    let api = crate::login::Api::new(&login).ok()?;
    tokio::time::timeout(Duration::from_secs(5), api.tunnel(tunnel_id)).await.ok()?.ok()?
}

pub async fn ice(format: IceFormat, fresh: bool, exec: Vec<String>) -> anyhow::Result<i32> {
    let (config, ice_file, endpoint) = match ask(Request::Ice { fresh }, false, Report::Text).await? {
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
    stop_daemon(&paths, deleted, false).await
}

/// Stop the daemon and remove its state; `quiet` keeps stdout clean (for `--json`).
pub(crate) async fn stop_daemon(paths: &Paths, deleted: bool, quiet: bool) -> anyhow::Result<i32> {
    if let Ok(stream) = UnixStream::connect(&paths.socket).await {
        // The daemon replies, deletes its state, and exits.
        if let Some(Response::Error { message }) =
            call(stream, &Request::Stop { expect: None }, REQUEST_TIMEOUT).await?
        {
            bail!("{message}");
        }
    }
    // No daemon (or it already exited): make sure nothing restarts it from state.
    match std::fs::remove_file(&paths.state_file) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => bail!("removing {}: {e}", paths.state_file.display()),
    }
    if quiet {
        eprintln!("stopped");
    } else {
        println!("stopped");
    }
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
            assert!(matches!(request, Some(Request::Stop { expect: None })));
            write_json_line(&mut wr, &Response::Status { status: Status::stopped() }).await.unwrap();
        });
        assert_eq!(stop_daemon(&paths, false, false).await.unwrap(), 1);
        peer.await.unwrap();
        assert!(!paths.state_file.exists());
        assert!(paths.dir.join("share.json").exists());
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }
}
