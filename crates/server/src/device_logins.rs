//! Browser-approved machine logins (RFC 8628 device flow): a machine asks,
//! the user approves its code in the web UI, the machine's poll creates it.

use rusqlite::{OptionalExtension, params};
use serde::Serialize;

use crate::db::{Db, NewClientError, authorized, client_admissible};
use crate::tokens::now;

#[derive(Debug, Clone, Serialize)]
pub struct DeviceRequest {
    pub user_code: String,
    pub client_name: String,
    pub ip: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecideError {
    /// Unknown, decided or expired code.
    NotFound,
    Client(NewClientError),
}

/// `POST /v1/device/token` outcomes (RFC 8628 §3.5).
#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Pending,
    SlowDown,
    Expired,
    Denied,
    /// The machine was created; `token` is its client token (delivered once).
    Approved {
        name: String,
    },
    /// Approved, but the machine could not be created (quota, name, owner gone).
    Failed(NewClientError),
}

impl Db {
    #[allow(clippy::too_many_arguments)]
    pub async fn create_device_login(
        &self,
        device_code_hash: String,
        user_code: String,
        client_name: String,
        ip: Option<String>,
        expires_at: i64,
        interval_s: i64,
    ) -> anyhow::Result<bool> {
        self.call(move |c| {
            let n = c.execute(
                "INSERT INTO device_logins (device_code_hash, user_code, client_name, ip, created_at, expires_at, interval_s, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending') ON CONFLICT DO NOTHING",
                params![device_code_hash, user_code, client_name, ip, now(), expires_at, interval_s],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// A pending, unexpired request by its user code.
    pub async fn device_request(&self, user_code: String) -> anyhow::Result<Option<DeviceRequest>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT user_code, client_name, ip, created_at, expires_at FROM device_logins
                 WHERE user_code = ?1 AND status = 'pending' AND expires_at > ?2",
                params![user_code, now()],
                |r| {
                    Ok(DeviceRequest {
                        user_code: r.get(0)?,
                        client_name: r.get(1)?,
                        ip: r.get(2)?,
                        created_at: r.get(3)?,
                        expires_at: r.get(4)?,
                    })
                },
            )
            .optional()?)
        })
        .await
    }

    /// Approve (for `user_id`) or deny a pending request. Approval checks the
    /// user's machine quota now, so the user sees a refusal in the browser.
    pub async fn decide_device(
        &self,
        user_code: String,
        user_id: String,
        approve: bool,
        session: String,
    ) -> anyhow::Result<Result<String, DecideError>> {
        let defaults = self.limit_defaults();
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // The approving session must still be valid (not ended by a reset or a disable).
            if !authorized(&tx, &user_id, None, &session)? {
                return Ok(Err(DecideError::Client(NewClientError::NoUser)));
            }
            let name: Option<String> = tx
                .query_row(
                    "SELECT client_name FROM device_logins WHERE user_code = ?1 AND status = 'pending' AND expires_at > ?2",
                    params![user_code, t],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(name) = name else {
                return Ok(Err(DecideError::NotFound));
            };
            if approve {
                let unique = unique_client_name(&tx, &name)?;
                if let Err(e) = client_admissible(&tx, &unique, &user_id, defaults)? {
                    return Ok(Err(DecideError::Client(e)));
                }
            }
            tx.execute(
                "UPDATE device_logins SET status = ?2, user_id = ?3 WHERE user_code = ?1",
                params![user_code, if approve { "approved" } else { "denied" }, user_id],
            )?;
            tx.commit()?;
            Ok(Ok(name))
        })
        .await
    }

    /// One poll of the device flow. On approval the client is created with
    /// `token_hash` and the request is removed, so the token is handed out
    /// exactly once.
    pub async fn poll_device(
        &self,
        device_code_hash: String,
        client_id: String,
        token_hash: String,
    ) -> anyhow::Result<Option<Poll>> {
        let defaults = self.limit_defaults();
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // status, client name, expiry, interval, last poll, approving user
            type Row = (String, String, i64, i64, Option<i64>, Option<String>);
            let row: Option<Row> = tx
                .query_row(
                    "SELECT status, client_name, expires_at, interval_s, last_poll_at, user_id FROM device_logins
                     WHERE device_code_hash = ?1",
                    params![device_code_hash],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .optional()?;
            let Some((status, name, expires_at, interval, last_poll, user_id)) = row else {
                return Ok(None);
            };
            if expires_at <= t {
                tx.execute("DELETE FROM device_logins WHERE device_code_hash = ?1", params![device_code_hash])?;
                tx.commit()?;
                return Ok(Some(Poll::Expired));
            }
            if last_poll.is_some_and(|p| t - p < interval) {
                // RFC 8628 §3.5: a client polling too fast waits 5 s longer from now on.
                tx.execute(
                    "UPDATE device_logins SET interval_s = interval_s + 5, last_poll_at = ?2 WHERE device_code_hash = ?1",
                    params![device_code_hash, t],
                )?;
                tx.commit()?;
                return Ok(Some(Poll::SlowDown));
            }
            tx.execute(
                "UPDATE device_logins SET last_poll_at = ?2 WHERE device_code_hash = ?1",
                params![device_code_hash, t],
            )?;
            let outcome = match (status.as_str(), user_id) {
                ("approved", Some(user_id)) => {
                    tx.execute("DELETE FROM device_logins WHERE device_code_hash = ?1", params![device_code_hash])?;
                    let unique = unique_client_name(&tx, &name)?;
                    match client_admissible(&tx, &unique, &user_id, defaults)? {
                        Ok(()) => {
                            tx.execute(
                                "INSERT INTO clients (id, name, token_hash, created_at, last_used_at, user_id)
                                 VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
                                params![client_id, unique, token_hash, t, user_id],
                            )?;
                            Poll::Approved { name: unique }
                        }
                        Err(e) => Poll::Failed(e),
                    }
                }
                ("denied", _) => {
                    tx.execute("DELETE FROM device_logins WHERE device_code_hash = ?1", params![device_code_hash])?;
                    Poll::Denied
                }
                _ => Poll::Pending,
            };
            tx.commit()?;
            Ok(Some(outcome))
        })
        .await
    }
}

/// `name`, or `name-2`, `name-3`, … if taken (device logins pick their own name).
fn unique_client_name(tx: &rusqlite::Transaction<'_>, name: &str) -> anyhow::Result<String> {
    let taken = |n: &str| -> anyhow::Result<bool> {
        Ok(tx.query_row("SELECT EXISTS (SELECT 1 FROM clients WHERE name = ?1)", params![n], |r| r.get(0))?)
    };
    if !taken(name)? {
        return Ok(name.to_string());
    }
    for i in 2..1000 {
        let base: String = name.chars().take(crate::clients::MAX_NAME_LEN - 4).collect();
        let candidate = format!("{base}-{i}");
        if !taken(&candidate)? {
            return Ok(candidate);
        }
    }
    anyhow::bail!("no free machine name for {name}")
}
