use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Es,
}

impl Lang {
    pub fn from_env() -> Self {
        match std::env::var("LANG").unwrap_or_default() {
            s if s.starts_with("es") || s.starts_with("ES") => Lang::Es,
            _ => Lang::En,
        }
    }
}

static CACHED_LANG: OnceLock<Lang> = OnceLock::new();

pub fn cached_lang() -> Lang {
    *CACHED_LANG.get_or_init(Lang::from_env)
}

/// Translate a message key. Falls back to English if key not found in the requested language.
/// For keys not found at all, returns the key itself.
pub fn t(lang: Lang, key: &'static str) -> &'static str {
    match key {
        // ── Ctrl-C / Interruption ──
        "hard_abort" => match lang {
            Lang::En => "Hard abort.",
            Lang::Es => "Abortando.",
        },
        "scan_interrupted" => match lang {
            Lang::En => {
                "Scan interrupted. Partial results saved to cache. Use --cache on next run to resume."
            }
            Lang::Es => "Escaneo interrumpido. Resultados parciales guardados en caché.",
        },
        "interrupted_by_user" => match lang {
            Lang::En => "Interrupted by user",
            Lang::Es => "Interrumpido por el usuario",
        },

        // ── Warnings / Errors ──
        "warning" => match lang {
            Lang::En => "warning",
            Lang::Es => "aviso",
        },
        "json_report_failed" => match lang {
            Lang::En => "warning: failed to write JSON report",
            Lang::Es => "aviso: no se pudo escribir el reporte JSON",
        },
        "json_report_arrow" => match lang {
            Lang::En => "JSON report →",
            Lang::Es => "Reporte JSON →",
        },
        "path_not_utf8" => match lang {
            Lang::En => "path is not valid UTF-8",
            Lang::Es => "ruta no es UTF-8 válido",
        },
        "quarantine_open_error" => match lang {
            Lang::En => "quarantine open",
            Lang::Es => "error al abrir cuarentena",
        },
        "type_123" => match lang {
            Lang::En => "Type 1, 2, or 3",
            Lang::Es => "Escribe 1, 2 o 3",
        },

        // ── Discovery / Progress Steps ──
        "discovering_files" => match lang {
            Lang::En => "Discovering files...",
            Lang::Es => "Descubriendo archivos...",
        },
        "grouping_by_size" => match lang {
            Lang::En => "Grouping by size...",
            Lang::Es => "Agrupando por tamaño...",
        },
        "partial_hashing" => match lang {
            Lang::En => "Partial hashing (head+tail)...",
            Lang::Es => "Hashing parcial (head+tail)...",
        },
        "full_hashing" => match lang {
            Lang::En => "Full hashing (BLAKE3)...",
            Lang::Es => "Hashing completo (BLAKE3)...",
        },
        "byte_verify" => match lang {
            Lang::En => "Byte-by-byte verification...",
            Lang::Es => "Verificación byte a byte...",
        },
        "fingerprinting" => match lang {
            Lang::En => "Fingerprinting (pHash + dHash + EXIF)...",
            Lang::Es => "Calculando huellas (pHash + dHash + EXIF)...",
        },
        "fingerprinting_progress" => match lang {
            Lang::En => "Fingerprinting...",
            Lang::Es => "Calculando huellas...",
        },
        "clustering" => match lang {
            Lang::En => "Clustering near-duplicates...",
            Lang::Es => "Agrupando casi-duplicados...",
        },
        "discovering_images" => match lang {
            Lang::En => "Discovering image files...",
            Lang::Es => "Descubriendo imágenes...",
        },
        "scanning_for_junk" => match lang {
            Lang::En => "Scanning for junk files...",
            Lang::Es => "Buscando archivos basura...",
        },
        "scanning_junk_in" => match lang {
            Lang::En => "Scanning for junk in",
            Lang::Es => "Buscando basura en",
        },
        "cleaning_junk" => match lang {
            Lang::En => "Cleaning junk...",
            Lang::Es => "Limpiando basura...",
        },

        // ── Mode Descriptions ──
        "reference_mode" => match lang {
            Lang::En => "Reference mode: keeping files in {}, reporting duplicates elsewhere.",
            Lang::Es => "Modo referencia: conservando archivos en {}, reportando duplicados fuera.",
        },
        "isolate_mode" => match lang {
            Lang::En => "Isolate mode: only showing cross-directory duplicates.",
            Lang::Es => "Modo aislado: solo duplicados entre directorios distintos.",
        },

        // ── Exact Results ──
        "no_duplicates" => match lang {
            Lang::En => "No duplicate files found.",
            Lang::Es => "No se encontraron duplicados.",
        },
        "duplicate_group" => match lang {
            Lang::En => "DUPLICATE GROUP",
            Lang::Es => "GRUPO DE DUPLICADOS",
        },
        "exact_duplicates_found" => match lang {
            Lang::En => "EXACT DUPLICATES FOUND",
            Lang::Es => "DUPLICADOS EXACTOS ENCONTRADOS",
        },
        "keeper" => match lang {
            Lang::En => "KEEPER",
            Lang::Es => "CONSERVAR",
        },
        "keeper_star" => match lang {
            Lang::En => "★ KEEPER",
            Lang::Es => "★ CONSERVAR",
        },
        "files_marked_keeper" => match lang {
            Lang::En => "Files marked with ★ are ZeroDupe's keeper recommendation.",
            Lang::Es => "★ = recomendación de ZeroDupe para conservar.",
        },
        "total_reclaimable" => match lang {
            Lang::En => "Total reclaimable",
            Lang::Es => "Total recuperable",
        },
        "reclaimable_across" => match lang {
            Lang::En => "Total reclaimable: {} across {} duplicate files in {} groups",
            Lang::Es => "Total recuperable: {} en {} archivos duplicados y {} grupos",
        },
        "groups_files_duplicates" => match lang {
            Lang::En => "{} groups  •  {} files  •  {} duplicates to resolve",
            Lang::Es => "{} grupos  •  {} archivos  •  {} duplicados por resolver",
        },

        // ── Similar Results ──
        "no_similar_images" => match lang {
            Lang::En => "No similar images found.",
            Lang::Es => "No se encontraron imágenes similares.",
        },
        "similar_images_found" => match lang {
            Lang::En => "SIMILAR IMAGES FOUND",
            Lang::Es => "IMÁGENES SIMILARES ENCONTRADAS",
        },
        "similarity_score" => match lang {
            Lang::En => "confidence",
            Lang::Es => "similitud",
        },
        "similar_groups_summary" => match lang {
            Lang::En => "{} groups  •  {} similar images",
            Lang::Es => "{} grupos  •  {} imágenes similares",
        },
        "reclaimable_similar" => match lang {
            Lang::En => "Total reclaimable: {} across {} similar image files in {} groups",
            Lang::Es => "Total recuperable: {} en {} imágenes similares y {} grupos",
        },
        "similar_display_group" => match lang {
            Lang::En => "Group {} — {} confidence — {} files",
            Lang::Es => "Grupo {} — {} similitud — {} archivos",
        },

        // ── Hygiene Results ──
        "no_junk" => match lang {
            Lang::En => "No junk items found.",
            Lang::Es => "No se encontró basura.",
        },
        "no_junk_roots" => match lang {
            Lang::En => "No junk items found across all roots.",
            Lang::Es => "No se encontró basura en ninguna ruta.",
        },
        "junk_found" => match lang {
            Lang::En => "JUNK ITEMS FOUND",
            Lang::Es => "ARCHIVOS BASURA ENCONTRADOS",
        },
        "hygiene_summary" => match lang {
            Lang::En => "Hygiene Summary",
            Lang::Es => "Resumen de Higiene",
        },
        "junk_items_found_detail" => match lang {
            Lang::En => "Found {} junk items ({})",
            Lang::Es => "Encontrados {} archivos basura ({})",
        },
        "no_junk_files_found" => match lang {
            Lang::En => "No junk files found.",
            Lang::Es => "No se encontraron archivos basura.",
        },
        "items_found_at" => match lang {
            Lang::En => "{} junk items found ({} low, {} med, {} high)",
            Lang::Es => "{} archivos basura ({} bajo, {} medio, {} alto)",
        },

        // ── Quarantine ──
        "quarantined" => match lang {
            Lang::En => "Quarantined",
            Lang::Es => "En cuarentena",
        },
        "quarantined_files" => match lang {
            Lang::En => "Quarantined {} files.",
            Lang::Es => "{} archivos en cuarentena.",
        },
        "quarantined_items" => match lang {
            Lang::En => "Quarantined {} items.",
            Lang::Es => "{} elementos en cuarentena.",
        },
        "quarantine_preserved" => match lang {
            Lang::En => "Exiting. Quarantine state preserved.",
            Lang::Es => "Saliendo. Cuarentena preservada.",
        },
        "exiting_no_changes" => match lang {
            Lang::En => "Exiting. No changes made.",
            Lang::Es => "Saliendo. Sin cambios.",
        },
        "exiting_no_files_moved" => match lang {
            Lang::En => "Exiting. No files moved.",
            Lang::Es => "Saliendo. Sin archivos movidos.",
        },
        "skipped_no_files" => match lang {
            Lang::En => "Skipped — no files moved.",
            Lang::Es => "Omitido — sin cambios.",
        },
        "quarantine_empty" => match lang {
            Lang::En => "Quarantine is empty.",
            Lang::Es => "Cuarentena vacía.",
        },
        "similar_quarantined" => match lang {
            Lang::En => "{} similar images quarantined",
            Lang::Es => "{} imágenes similares en cuarentena",
        },
        "files_quarantined_keepers" => match lang {
            Lang::En => "{} files quarantined  •  {} keepers preserved",
            Lang::Es => "{} archivos en cuarentena  •  {} conservados",
        },
        "auto_quarantined_keepers" => match lang {
            Lang::En => "Auto-quarantined {} files ({} keepers preserved).",
            Lang::Es => "Auto-cuarentena: {} archivos ({} conservados).",
        },
        "auto_cleaned_items" => match lang {
            Lang::En => "Auto-cleaned {} low-risk items.",
            Lang::Es => "Limpiados {} elementos de bajo riesgo.",
        },
        "quarantined_medium_items" => match lang {
            Lang::En => "Quarantined {} medium-risk items.",
            Lang::Es => "{} elementos de riesgo medio en cuarentena.",
        },
        "low_risk_quarantined" => match lang {
            Lang::En => "{} low-risk items quarantined",
            Lang::Es => "{} elementos de bajo riesgo en cuarentena",
        },
        "moved_to_junk" => match lang {
            Lang::En => "Moved: {} → junk/",
            Lang::Es => "Movido: {} → basura/",
        },

        // ── Interactive Prompts ──
        "how_handle" => match lang {
            Lang::En => "How do you want to handle them?",
            Lang::Es => "¿Cómo quieres manejarlos?",
        },
        "review_manually" => match lang {
            Lang::En => "[1] Review manually — choose file by file",
            Lang::Es => "[1] Revisar manualmente — archivo por archivo",
        },
        "auto_quarantine" => match lang {
            Lang::En => "[2] Auto-quarantine — keep best, quarantine the rest",
            Lang::Es => "[2] Auto-cuarentena — conservar el mejor, aislar el resto",
        },
        "skip_option" => match lang {
            Lang::En => "[3] Skip — show report, don't touch anything",
            Lang::Es => "[3] Omitir — solo mostrar reporte",
        },
        "review_items" => match lang {
            Lang::En => "[1] Review — inspect items before cleaning",
            Lang::Es => "[1] Revisar — inspeccionar antes de limpiar",
        },
        "auto_clean_low" => match lang {
            Lang::En => "[2] Auto-clean low-risk — quarantine safe items",
            Lang::Es => "[2] Auto-limpiar bajo riesgo — aislar elementos seguros",
        },

        // ── Interactive Controls ──
        "toggle_file" => match lang {
            Lang::En => "[number]  Toggle file for quarantine",
            Lang::Es => "[número]  Seleccionar archivo",
        },
        "toggle_item" => match lang {
            Lang::En => "[number]  Toggle file",
            Lang::Es => "[número]  Seleccionar",
        },
        "apply_quarantine" => match lang {
            Lang::En => "A  Apply — quarantine all selected files",
            Lang::Es => "A  Aplicar — todo a cuarentena",
        },
        "apply_short" => match lang {
            Lang::En => "A  Apply quarantine",
            Lang::Es => "A  Aplicar cuarentena",
        },
        "quit_no_quarantine" => match lang {
            Lang::En => "Q  Quit without quarantining",
            Lang::Es => "Q  Salir sin aplicar",
        },
        "quit_short" => match lang {
            Lang::En => "Q  Quit",
            Lang::Es => "Q  Salir",
        },
        "keeper_help" => match lang {
            Lang::En => "★  Keeper recommendation (best file to keep)",
            Lang::Es => "★  Recomendación de conservación",
        },
        "invalid_number" => match lang {
            Lang::En => "Invalid number (1-{})",
            Lang::Es => "Número inválido (1-{})",
        },
        "invalid" => match lang {
            Lang::En => "Invalid (1-{})",
            Lang::Es => "Inválido (1-{})",
        },
        "unknown_cmd" => match lang {
            Lang::En => "Unknown command. Type ? for help.",
            Lang::Es => "Comando desconocido. Escribe ? para ayuda.",
        },
        "unknown_type_help" => match lang {
            Lang::En => "Unknown. Type ? for help.",
            Lang::Es => "Desconocido. Escribe ? para ayuda.",
        },
        "unknown_prompt" => match lang {
            Lang::En => "Unknown. Type [1-{}], [A]pply, or [Q]uit.",
            Lang::Es => "Desconocido. Usa [1-{}], [A]plicar o [Q]salir.",
        },

        "actions_prompt" => match lang {
            Lang::En => "Actions: [1-{}] toggle  [A]pply quarantine  [Q]uit",
            Lang::Es => "Acciones: [1-{}] seleccionar  [A]plicar  [Q]salir",
        },
        "toggle_apply_quit" => match lang {
            Lang::En => "[1-N] toggle  [A]pply  [Q]uit",
            Lang::Es => "[1-N] seleccionar  [A]plicar  [Q]salir",
        },
        "files_preselected" => match lang {
            Lang::En => "Files pre-selected for quarantine (★ keepers are excluded).",
            Lang::Es => "Archivos preseleccionados (★ conservar están excluidos).",
        },
        "files_preselected_short" => match lang {
            Lang::En => "Files pre-selected for quarantine.",
            Lang::Es => "Archivos preseleccionados para cuarentena.",
        },
        "prompt_mark" => match lang {
            Lang::En => "> ",
            Lang::Es => "> ",
        },

        // ── Wizard ──
        "wizard_banner_title" => match lang {
            Lang::En => "Z E R O D U P E",
            Lang::Es => "Z E R O D U P E",
        },
        "wizard_banner_subtitle" => match lang {
            Lang::En => "Find & clean duplicate files",
            Lang::Es => "Encuentra y limpia archivos duplicados",
        },
        "step1_exact" => match lang {
            Lang::En => "STEP 1 — Exact Duplicates",
            Lang::Es => "PASO 1 — Duplicados exactos",
        },
        "step2_similar" => match lang {
            Lang::En => "STEP 2 — Similar Images",
            Lang::Es => "PASO 2 — Imágenes similares",
        },
        "step3_hygiene" => match lang {
            Lang::En => "STEP 3 — Hygiene Cleanup",
            Lang::Es => "PASO 3 — Limpieza de basura",
        },
        "continue_similar" => match lang {
            Lang::En => "Continue with similar images scan? [Y] Yes  [N] No, exit",
            Lang::Es => "¿Continuar con escaneo de imágenes similares? [S] Sí  [N] No, salir",
        },
        "path_to_scan" => match lang {
            Lang::En => "Path to scan",
            Lang::Es => "Ruta a escanear",
        },
        "path_not_found" => match lang {
            Lang::En => "Path not found",
            Lang::Es => "Ruta no encontrada",
        },
        "scan_another" => match lang {
            Lang::En => "Scan another location? [y/N]",
            Lang::Es => "¿Escanear otra ubicación? [s/N]",
        },
        "done_total_time" => match lang {
            Lang::En => "Done. Total time: {}",
            Lang::Es => "Hecho. Tiempo total: {}",
        },

        // ── Reports ──
        "report" => match lang {
            Lang::En => "Report",
            Lang::Es => "Reporte",
        },
        "report_saved" => match lang {
            Lang::En => "Report saved to {}",
            Lang::Es => "Reporte guardado en {}",
        },
        "opening_report" => match lang {
            Lang::En => "Opening report...",
            Lang::Es => "Abriendo reporte...",
        },
        "html_report_saved" => match lang {
            Lang::En => "HTML report saved",
            Lang::Es => "Reporte HTML guardado",
        },

        // ── Risk Levels ──
        "risk_low" => match lang {
            Lang::En => "LOW",
            Lang::Es => "BAJO",
        },
        "risk_medium" => match lang {
            Lang::En => "MED",
            Lang::Es => "MEDIO",
        },
        "risk_high" => match lang {
            Lang::En => "HIGH",
            Lang::Es => "ALTO",
        },
        "risk_levels_summary" => match lang {
            Lang::En => "Risk: {} Low · {} Medium · {} High",
            Lang::Es => "Riesgo: {} Bajo · {} Medio · {} Alto",
        },
        "items_count" => match lang {
            Lang::En => "{} items · {}",
            Lang::Es => "{} elementos · {}",
        },
        "items_risk_detail" => match lang {
            Lang::En => "{} items ({} low, {} med, {} high)",
            Lang::Es => "{} elementos ({} bajo, {} medio, {} alto)",
        },

        // ── Hygiene Interactive ──
        "hygiene_items_prompt" => match lang {
            Lang::En => "[1-{}] quarantine item",
            Lang::Es => "[1-{}] poner en cuarentena",
        },
        "apply_all" => match lang {
            Lang::En => "[A]pply all",
            Lang::Es => "[A]plicar todo",
        },
        "apply_all_quit" => match lang {
            Lang::En => "[A]pply all  [Q]uit",
            Lang::Es => "[A]plicar todo  [Q]salir",
        },

        // ── Keeper Notes ──
        "note_copy_name" => match lang {
            Lang::En => "(copy name)",
            Lang::Es => "(nombre copia)",
        },
        "note_numbered_copy" => match lang {
            Lang::En => "(numbered copy)",
            Lang::Es => "(copia numerada)",
        },
        "note_backup" => match lang {
            Lang::En => "(backup)",
            Lang::Es => "(respaldo)",
        },
        "note_old_version" => match lang {
            Lang::En => "(old version)",
            Lang::Es => "(versión antigua)",
        },

        // ── Fallback ──
        _ => key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LANG is process-global and Rust runs tests in parallel threads:
    /// the two from_env tests must not interleave their set_var calls.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn lang_from_env_es() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: LANG writes are serialized by ENV_LOCK; no other test
        // in this binary touches the environment.
        unsafe {
            std::env::set_var("LANG", "es_ES.UTF-8");
        }
        assert_eq!(Lang::from_env(), Lang::Es);

        // SAFETY: same as above.
        unsafe {
            std::env::set_var("LANG", "es_MX");
        }
        assert_eq!(Lang::from_env(), Lang::Es);

        // SAFETY: same as above.
        unsafe {
            std::env::set_var("LANG", "ES");
        }
        assert_eq!(Lang::from_env(), Lang::Es);
    }

    #[test]
    fn lang_from_env_en() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: LANG writes are serialized by ENV_LOCK; no other test
        // in this binary touches the environment.
        unsafe {
            std::env::set_var("LANG", "en_US.UTF-8");
        }
        assert_eq!(Lang::from_env(), Lang::En);

        // SAFETY: same as above.
        unsafe {
            std::env::set_var("LANG", "C");
        }
        assert_eq!(Lang::from_env(), Lang::En);

        // SAFETY: same as above.
        unsafe {
            std::env::set_var("LANG", "");
        }
        assert_eq!(Lang::from_env(), Lang::En);

        // SAFETY: remove_var is only unsafe because it could race with
        // other threads reading/writing env vars. In tests, we run
        // single-threaded and LANG is the only env var touched.
        unsafe {
            std::env::remove_var("LANG");
        }
        assert_eq!(Lang::from_env(), Lang::En);
    }

    #[test]
    fn all_keys_exist_for_both_langs() {
        let keys = &[
            "hard_abort",
            "scan_interrupted",
            "interrupted_by_user",
            "warning",
            "json_report_failed",
            "json_report_arrow",
            "path_not_utf8",
            "quarantine_open_error",
            "type_123",
            "discovering_files",
            "grouping_by_size",
            "partial_hashing",
            "full_hashing",
            "byte_verify",
            "fingerprinting",
            "fingerprinting_progress",
            "clustering",
            "discovering_images",
            "scanning_for_junk",
            "scanning_junk_in",
            "cleaning_junk",
            "reference_mode",
            "isolate_mode",
            "no_duplicates",
            "duplicate_group",
            "exact_duplicates_found",
            "keeper",
            "keeper_star",
            "files_marked_keeper",
            "total_reclaimable",
            "reclaimable_across",
            "groups_files_duplicates",
            "no_similar_images",
            "similar_images_found",
            "similarity_score",
            "similar_groups_summary",
            "reclaimable_similar",
            "similar_display_group",
            "no_junk",
            "no_junk_roots",
            "junk_found",
            "hygiene_summary",
            "junk_items_found_detail",
            "no_junk_files_found",
            "items_found_at",
            "quarantined",
            "quarantined_files",
            "quarantined_items",
            "quarantine_preserved",
            "exiting_no_changes",
            "exiting_no_files_moved",
            "skipped_no_files",
            "quarantine_empty",
            "similar_quarantined",
            "files_quarantined_keepers",
            "auto_quarantined_keepers",
            "auto_cleaned_items",
            "quarantined_medium_items",
            "low_risk_quarantined",
            "moved_to_junk",
            "how_handle",
            "review_manually",
            "auto_quarantine",
            "skip_option",
            "review_items",
            "auto_clean_low",
            "toggle_file",
            "toggle_item",
            "apply_quarantine",
            "apply_short",
            "quit_no_quarantine",
            "quit_short",
            "keeper_help",
            "invalid_number",
            "invalid",
            "unknown_cmd",
            "unknown_type_help",
            "unknown_prompt",
            "actions_prompt",
            "toggle_apply_quit",
            "files_preselected",
            "files_preselected_short",
            "prompt_mark",
            "wizard_banner_title",
            "wizard_banner_subtitle",
            "step1_exact",
            "step2_similar",
            "step3_hygiene",
            "continue_similar",
            "path_to_scan",
            "path_not_found",
            "scan_another",
            "done_total_time",
            "report",
            "report_saved",
            "opening_report",
            "html_report_saved",
            "risk_low",
            "risk_medium",
            "risk_high",
            "risk_levels_summary",
            "items_count",
            "items_risk_detail",
            "hygiene_items_prompt",
            "apply_all",
            "apply_all_quit",
            "note_copy_name",
            "note_numbered_copy",
            "note_backup",
            "note_old_version",
        ];

        for &key in keys {
            let en = t(Lang::En, key);
            let es = t(Lang::Es, key);
            assert!(!en.is_empty(), "English translation empty for key: {key}");
            assert!(!es.is_empty(), "Spanish translation empty for key: {key}");
            assert_ne!(
                es, key,
                "Spanish translation missing (fell back to key) for: {key}"
            );
            // English value may legitimately equal the key name (e.g. "warning")
        }
    }

    #[test]
    fn no_missing_english_fallback() {
        // Unknown keys should return the key itself (identity fallback)
        assert_eq!(
            t(Lang::En, "nonexistent_key_12345"),
            "nonexistent_key_12345"
        );
        assert_eq!(
            t(Lang::Es, "nonexistent_key_12345"),
            "nonexistent_key_12345"
        );
    }
}
