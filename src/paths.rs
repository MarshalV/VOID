//! Единая директория данных VOID — vault, outbox, пароль сессии всегда в одном месте.
//! Все пути абсолютные: на macOS Finder часто стартует с cwd=`/`, куда писать нельзя.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing::{info, warn};

const DATA_DIR_NAME: &str = "VOID";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

const LEGACY_BLOBS: &[&str] = &[
    "vault.bin",
    "void.key",
    "void.pwd",
    "outbox.bin",
    "chat_journal.bin",
    "relay_mailbox.bin",
];

const LEGACY_DIRS: &[&str] = &["void_downloads"];

/// Переключает cwd на каталог данных и мигрирует файлы из старых мест (cwd, рядом с .exe).
pub(crate) fn init_storage_paths() -> Result<(), String> {
    let dir = pick_writable_data_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("не удалось создать {}: {}", dir.display(), e))?;
    migrate_legacy_files(&dir)?;
    let _ = DATA_DIR.set(dir.clone());
    // Best-effort: относительные пути (void_downloads) тоже попадут сюда.
    if let Err(e) = std::env::set_current_dir(&dir) {
        warn!("VOID: set_current_dir({}) не удался: {e}", dir.display());
    }
    info!("VOID: каталог данных — {}", dir.display());
    Ok(())
}

/// Каталог данных VOID (абсолютный путь).
pub(crate) fn data_dir() -> PathBuf {
    if let Some(d) = DATA_DIR.get() {
        return d.clone();
    }
    // Lazy init если init_storage_paths не вызвали / упал раньше set.
    match pick_writable_data_dir() {
        Ok(dir) => {
            let _ = DATA_DIR.set(dir.clone());
            dir
        }
        Err(e) => {
            warn!("VOID: fallback data_dir: {e}");
            resolve_preferred_data_dir().unwrap_or_else(|| PathBuf::from("."))
        }
    }
}

/// Абсолютный путь к файлу внутри каталога данных.
pub(crate) fn data_file(name: impl AsRef<Path>) -> PathBuf {
    data_dir().join(name)
}

/// Одна копия VOID на vault: второй процесс с тем же ключом шлёт второй TCP
/// на bootstrap, и libp2p закрывает оба (`yamux Closed` за 1 мс).
pub(crate) fn acquire_instance_lock() -> Result<std::fs::File, String> {
    let path = data_file("void.instance.lock");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(0);
    }
    let mut file = opts.open(&path).map_err(|_| {
        "VOID уже запущен. Закройте старую копию (трей и Диспетчер задач: VOID / app.exe) и откройте снова.".to_string()
    })?;
    {
        use std::io::Write;
        let _ = file.set_len(0);
        let _ = writeln!(file, "{}", std::process::id());
        let _ = file.flush();
    }
    Ok(file)
}

fn dir_is_writable(dir: &Path) -> bool {
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!("VOID: нельзя создать {}: {e}", dir.display());
        return false;
    }
    let probe = dir.join(".void_write_probe");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(e) => {
            warn!("VOID: нет записи в {}: {e}", dir.display());
            false
        }
    }
}

fn resolve_preferred_data_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VOID_DATA_DIR") {
        return Some(PathBuf::from(p));
    }
    if let Some(base) = dirs::data_dir() {
        return Some(base.join(DATA_DIR_NAME));
    }
    if let Some(home) = dirs::home_dir() {
        return Some(home.join(DATA_DIR_NAME));
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

fn pick_writable_data_dir() -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("VOID_DATA_DIR") {
        candidates.push(PathBuf::from(p));
    }
    if let Some(base) = dirs::data_dir() {
        candidates.push(base.join(DATA_DIR_NAME));
    }
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(DATA_DIR_NAME));
        candidates.push(home.join(".void"));
    }
    candidates.dedup();

    for dir in &candidates {
        if dir_is_writable(dir) {
            return Ok(dir.clone());
        }
    }
    Err(format!(
        "нет доступного каталога данных (пробовали: {})",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn migrate_legacy_files(dest_dir: &Path) -> Result<(), String> {
    let mut legacy_roots: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        if cwd != dest_dir {
            legacy_roots.push(cwd);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            // Не трогаем Contents/MacOS внутри .app — только чтение чужих путей даёт EACCES.
            let in_app_bundle = parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("MacOS"))
                && parent
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n == "Contents");
            if !in_app_bundle
                && parent != dest_dir
                && !legacy_roots.iter().any(|p| p == parent)
            {
                legacy_roots.push(parent.to_path_buf());
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        if home != dest_dir && !legacy_roots.iter().any(|p| p == &home) {
            legacy_roots.push(home);
        }
    }

    for name in LEGACY_BLOBS {
        migrate_one_file(dest_dir, &legacy_roots, name)?;
        for suffix in [".tmp", ".bak"] {
            migrate_one_file(dest_dir, &legacy_roots, &format!("{name}{suffix}"))?;
        }
    }
    for name in LEGACY_DIRS {
        migrate_one_dir(dest_dir, &legacy_roots, name)?;
    }
    Ok(())
}

fn migrate_one_dir(dest_dir: &Path, legacy_roots: &[PathBuf], name: &str) -> Result<(), String> {
    let dest = dest_dir.join(name);
    if dest.exists() {
        return Ok(());
    }
    for root in legacy_roots {
        let src = root.join(name);
        if !src.is_dir() {
            continue;
        }
        match copy_dir_recursive(&src, &dest) {
            Ok(()) => {
                info!(
                    "VOID: перенесён каталог {} → {}",
                    src.display(),
                    dest.display()
                );
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                info!("VOID: пропуск миграции {}: {e}", src.display());
            }
            Err(e) => {
                return Err(format!("миграция каталога {}: {e}", src.display()));
            }
        }
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dest.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

fn migrate_one_file(dest_dir: &Path, legacy_roots: &[PathBuf], name: &str) -> Result<(), String> {
    let dest = dest_dir.join(name);
    if dest.exists() {
        return Ok(());
    }
    for root in legacy_roots {
        let src = root.join(name);
        if !src.is_file() {
            continue;
        }
        match std::fs::copy(&src, &dest) {
            Ok(_) => {
                info!("VOID: перенесён {} → {}", src.display(), dest.display());
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                info!("VOID: пропуск миграции {}: {e}", src.display());
            }
            Err(e) => return Err(format!("миграция {}: {e}", src.display())),
        }
    }
    Ok(())
}
