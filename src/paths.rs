//! Единая директория данных VOID — vault, outbox, пароль сессии всегда в одном месте.

use std::path::{Path, PathBuf};

use tracing::info;

const DATA_DIR_NAME: &str = "VOID";

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
    let dir = resolve_data_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("не удалось создать {}: {}", dir.display(), e))?;
    migrate_legacy_files(&dir)?;
    std::env::set_current_dir(&dir).map_err(|e| format!("set_current_dir: {e}"))?;
    info!("VOID: каталог данных — {}", dir.display());
    Ok(())
}

/// Каталог данных VOID (после `init_storage_paths` совпадает с cwd).
pub(crate) fn data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("VOID_DATA_DIR") {
        return PathBuf::from(p);
    }
    std::env::current_dir().unwrap_or_else(|_| resolve_data_dir())
}

fn resolve_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("VOID_DATA_DIR") {
        return PathBuf::from(p);
    }
    if let Some(base) = dirs::data_dir() {
        return base.join(DATA_DIR_NAME);
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
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
            // .app на macOS: cwd=/ или Contents/MacOS — EACCES не должен валить старт.
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
