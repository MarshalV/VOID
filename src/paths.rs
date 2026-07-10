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
            if parent != dest_dir && !legacy_roots.iter().any(|p| p == parent) {
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
        std::fs::copy(&src, &dest)
            .map_err(|e| format!("миграция {}: {e}", src.display()))?;
        info!("VOID: перенесён {} → {}", src.display(), dest.display());
        break;
    }
    Ok(())
}
