use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eyre::Context;
use fs2::FileExt;

pub fn with_locked_json_file<T, R>(
    path: &Path,
    operation: impl FnOnce(&mut T) -> eyre::Result<R>,
) -> eyre::Result<R>
where
    T: Default + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .wrap_err_with(|| format!("open state file {}", path.display()))?;
    file.lock_exclusive()
        .wrap_err_with(|| format!("lock state file {}", path.display()))?;

    let result = (|| {
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .wrap_err_with(|| format!("read state file {}", path.display()))?;
        let mut value = if raw.trim().is_empty() {
            T::default()
        } else {
            serde_json::from_str(&raw)
                .wrap_err_with(|| format!("parse state file {}", path.display()))?
        };
        let result = operation(&mut value)?;
        let serialized = serde_json::to_vec(&value)
            .wrap_err_with(|| format!("serialize state file {}", path.display()))?;
        file.set_len(0)
            .wrap_err_with(|| format!("truncate state file {}", path.display()))?;
        file.seek(SeekFrom::Start(0))
            .wrap_err_with(|| format!("seek state file {}", path.display()))?;
        file.write_all(&serialized)
            .wrap_err_with(|| format!("write state file {}", path.display()))?;
        file.sync_all()
            .wrap_err_with(|| format!("sync state file {}", path.display()))?;
        Ok(result)
    })();

    let unlock_result = file.unlock();
    match (result, unlock_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(eyre::eyre!(
            "unlock state file {}: {error}",
            path.display()
        )),
        (Err(error), Err(_)) => Err(error),
    }
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

pub fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}
