//! Validate and re-seal password, recovery-code and two-factor secrets before serving.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, params};

use crate::db::Db;
use crate::pepper::{PepperSet, Purpose};
use crate::seal::{Keys, totp_aad};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Counts {
    /// Legacy Argon2 password hashes to seal.
    pub converted: usize,
    /// Password and TOTP seals under `ui_secret_previous`.
    pub rewrapped: usize,
    /// Recovery-code rows (used or not).
    pub codes: usize,
    /// Legacy plain SHA-256 recovery-code rows to seal.
    pub codes_converted: usize,
    /// Recovery-code seals under `ui_secret_previous`.
    pub codes_rewrapped: usize,
}

impl Counts {
    /// Values still sealed with `ui_secret_previous`.
    pub fn previous(&self) -> usize {
        self.rewrapped + self.codes_rewrapped
    }
}

pub async fn seal(db: &Db, peppers: PepperSet, totp: (Keys, Option<Keys>)) -> anyhow::Result<Counts> {
    db.call(move |c| {
        c.pragma_update(None, "synchronous", "FULL")?;
        let result = (|| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let counts = inspect(&tx, &peppers, (&totp.0, totp.1.as_ref()), true)?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(counts)
        })();
        let restore = c.pragma_update(None, "synchronous", "NORMAL");
        let counts = result?;
        restore?;
        checkpoint(c)?;
        c.execute_batch("VACUUM")?;
        checkpoint(c)?;
        Ok(counts)
    })
    .await
}

fn checkpoint(c: &Connection) -> anyhow::Result<()> {
    let busy: i32 = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    anyhow::ensure!(busy == 0, "password sealing checkpoint is busy; stop other database users and restart");
    Ok(())
}

/// A read-only snapshot, including legacy hashes that startup can convert.
pub fn check(path: &Path, peppers: &PepperSet, totp: (&Keys, Option<&Keys>)) -> anyhow::Result<Counts> {
    crate::db::ensure_plain_path(path)?;
    let mut c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    let tx = c.transaction()?;
    inspect(&tx, peppers, totp, false)
}

fn refusal(table: &str, row: &str, found: &str, peppers: &PepperSet) -> anyhow::Error {
    let expected = match &peppers.previous {
        Some(p) => format!("{} or {}", peppers.current.id(), p.id()),
        None => peppers.current.id().to_string(),
    };
    anyhow::anyhow!(
        "{table} row {row}: key id {found}, expected {expected}; the database was sealed with a different ui_secret: \
         put back the ui_secret it was made with (from the config backup), or set the old one as ui_secret_previous \
         to re-seal; losing it means resetting those passwords"
    )
}

/// The SHA-256 hex older versions stored for a recovery code.
fn legacy_code_hash(stored: &str) -> bool {
    stored.len() == 64 && stored.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Only print a well-formed public key id, never an untrusted hash fragment.
fn found_id(stored: &str) -> &str {
    stored
        .strip_prefix("pw1:")
        .or_else(|| stored.strip_prefix("rc1:"))
        .and_then(|s| s.split_once(':'))
        .map(|(id, _)| id)
        .filter(|id| id.len() == 16 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .unwrap_or("invalid or missing")
}

fn inspect(c: &Connection, peppers: &PepperSet, totp: (&Keys, Option<&Keys>), write: bool) -> anyhow::Result<Counts> {
    let mut counts = Counts::default();
    for (table, purpose, query) in [
        ("users", Purpose::User, "SELECT id, password_hash FROM users WHERE password_hash != '!'"),
        ("tunnels", Purpose::Tunnel, "SELECT id, password_hash FROM tunnels WHERE password_hash IS NOT NULL"),
    ] {
        let mut statement = c.prepare(query)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let stored: String = row.get(1)?;
            let plain = if stored.starts_with("$argon2") {
                anyhow::ensure!(crate::password::valid_phc(&stored), "{table} row {id}: invalid Argon2id PHC");
                counts.converted += 1;
                stored.clone()
            } else {
                let plain = peppers
                    .unwrap(&stored, purpose, &id)
                    .ok_or_else(|| refusal(table, &id, found_id(&stored), peppers))?;
                anyhow::ensure!(crate::password::valid_phc(&plain), "{table} row {id}: invalid Argon2id PHC");
                if found_id(&stored) == peppers.current.id() {
                    continue;
                }
                counts.rewrapped += 1;
                plain
            };
            if write {
                let sealed = peppers.current.wrap(&plain, purpose, &id);
                c.execute(&format!("UPDATE {table} SET password_hash = ?2 WHERE id = ?1"), params![id, sealed])?;
            }
        }
    }
    {
        // Recovery codes: legacy rows hold `hex(SHA-256(code))`, which is
        // exactly what gets sealed, so they convert without the codes.
        let rows = c
            .prepare("SELECT rowid, user_id, code_hash FROM recovery_codes ORDER BY rowid")?
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        for (rowid, user, stored) in rows {
            counts.codes += 1;
            let plain = if legacy_code_hash(&stored) {
                counts.codes_converted += 1;
                stored
            } else {
                let plain = peppers.unwrap(&stored, Purpose::Recovery, &user).ok_or_else(|| {
                    refusal("recovery_codes", &format!("{rowid} (user {user})"), found_id(&stored), peppers)
                })?;
                anyhow::ensure!(
                    legacy_code_hash(&plain),
                    "recovery_codes row {rowid} (user {user}): invalid code hash"
                );
                if found_id(&stored) == peppers.current.id() {
                    continue;
                }
                counts.codes_rewrapped += 1;
                plain
            };
            if write {
                let sealed = peppers.current.wrap(&plain, Purpose::Recovery, &user);
                c.execute("UPDATE recovery_codes SET code_hash = ?2 WHERE rowid = ?1", params![rowid, sealed])?;
            }
        }
    }
    {
        let (current, previous) = totp;
        let mut statement = c.prepare(
            "SELECT id, totp_secret_sealed, totp_pending_sealed FROM users
             WHERE totp_secret_sealed IS NOT NULL OR totp_pending_sealed IS NOT NULL",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let aad = totp_aad(&id);
            for (index, column) in [(1, "totp_secret_sealed"), (2, "totp_pending_sealed")] {
                let Some(sealed) = row.get::<_, Option<String>>(index)? else { continue };
                if current.open(&sealed, &aad).is_some() {
                    continue;
                }
                let plain = previous.and_then(|keys| keys.open(&sealed, &aad)).ok_or_else(|| {
                    anyhow::anyhow!(
                        "users row {id}: {column} cannot open; the database was sealed with a different ui_secret or the value is damaged"
                    )
                })?;
                counts.rewrapped += 1;
                if write {
                    c.execute(
                        &format!("UPDATE users SET {column} = ?2 WHERE id = ?1"),
                        params![id, current.seal(&plain, &aad)],
                    )?;
                }
            }
        }
    }
    Ok(counts)
}
