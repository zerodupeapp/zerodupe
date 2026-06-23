//! Internacionalización para reportes HTML.
//!
//! Soporta español (`es`) e inglés (`en`), detectando el idioma desde la variable
//! de entorno `LANG`. La struct [`Strings`] contiene todas las cadenas traducidas
//! usadas en títulos, etiquetas, pies de página y secciones del reporte HTML.
//!
//! Para agregar un nuevo idioma basta con definir una nueva constante `Strings`
//! y agregar una rama en [`Strings::for_lang`].

/// Detecta el idioma del usuario desde la variable de entorno `LANG`.
///
/// Devuelve `"es"` si `LANG` comienza con `es_` o `es-`; `"en"` para
/// cualquier otro valor (incluyendo cuando la variable no está definida).
pub fn detect_lang() -> &'static str {
    let lang = std::env::var("LANG").unwrap_or_default();
    if lang.starts_with("es_") || lang.starts_with("es-") {
        "es"
    } else {
        "en"
    }
}

/// Cadenas traducidas para todos los textos de los reportes HTML.
///
/// Cubre títulos, etiquetas de stats, encabezados de tabla, pies de página,
/// y las secciones de higiene y archivos protegidos. Los idiomas soportados
/// se obtienen con [`Strings::for_lang`].
pub struct Strings {
    pub lang_attr: &'static str,
    pub report_title_exact: &'static str,
    pub report_title_similar: &'static str,
    pub scanned: &'static str,
    pub date: &'static str,
    pub groups_found: &'static str,
    pub files_cleaned: &'static str,
    pub space_saved: &'static str,
    pub duration: &'static str,
    pub kept: &'static str,
    pub cleaned: &'static str,
    pub original: &'static str,
    pub group_prefix: &'static str,
    pub group_files: &'static str,
    pub footer_template: &'static str,
    pub hy_title: &'static str,
    pub hy_desc: &'static str,
    pub hy_th_file: &'static str,
    pub hy_th_category: &'static str,
    pub hy_th_size: &'static str,
    pub hy_summary_files: &'static str,
    pub hy_summary_reclaimed: &'static str,
    pub pro_title: &'static str,
    pub pro_desc: &'static str,
    pub pro_manual_review: &'static str,
    pub pro_group_label: &'static str,
    pub pro_protected_label: &'static str,
    pub pro_cleaned_label: &'static str,
    pub pro_total_groups: &'static str,
    pub pro_protected_space: &'static str,
    pub pro_can_clean: &'static str,
    pub similar_conf: &'static str,
    pub similar_total_files: &'static str,
    pub similar_footer: &'static str,
    pub confidence: &'static str,
}

impl Strings {
    /// Selecciona las cadenas traducidas según el código de idioma.
    ///
    /// `"es"` devuelve las cadenas en español; cualquier otro valor
    /// devuelve las cadenas en inglés.
    pub fn for_lang(lang: &str) -> Self {
        if lang == "es" { SPANISH } else { ENGLISH }
    }
}

const ENGLISH: Strings = Strings {
    lang_attr: "en",
    report_title_exact: "ZeroDupe — Cleanup Report",
    report_title_similar: "ZeroDupe — Similar Images Report",
    scanned: "Scanned",
    date: "Date",
    groups_found: "groups found",
    files_cleaned: "files cleaned",
    space_saved: "space saved",
    duration: "duration",
    kept: "★ KEPT",
    cleaned: "✗ CLEANED",
    original: "Original",
    group_prefix: "Group",
    group_files: "files",
    footer_template: "ZeroDupe · {date} · {groups} groups · {kept} kept · {cleaned} cleaned · {saved} MB saved",
    hy_title: "Files cleaned",
    hy_desc: "ZeroDupe removed junk files left by operating systems and applications.",
    hy_th_file: "File",
    hy_th_category: "Category",
    hy_th_size: "Size",
    hy_summary_files: "files",
    hy_summary_reclaimed: "reclaimed",
    pro_title: "Protected Duplicates — Not Modified",
    pro_desc: "These files are duplicates but were NOT moved to quarantine because they are in system-protected locations or are critical system files.",
    pro_manual_review: "Manual review is recommended. You can delete unprotected files manually if needed.",
    pro_group_label: "Group {index} — {total} files ({size})",
    pro_protected_label: "PROTECTED (not modified)",
    pro_cleaned_label: "Cleaned or kept",
    pro_total_groups: "Total protected groups",
    pro_protected_space: "Protected space",
    pro_can_clean: "Files you CAN clean manually",
    similar_conf: "confidence",
    similar_total_files: "total files",
    similar_footer: "ZeroDupe · {date} · {groups} groups · {total} similar images",
    confidence: "confidence",
};

const SPANISH: Strings = Strings {
    lang_attr: "es",
    report_title_exact: "ZeroDupe — Reporte de limpieza",
    report_title_similar: "ZeroDupe — Reporte de imágenes similares",
    scanned: "Escaneado",
    date: "Fecha",
    groups_found: "grupos encontrados",
    files_cleaned: "archivos limpiados",
    space_saved: "espacio liberado",
    duration: "duración",
    kept: "★ CONSERVADO",
    cleaned: "✗ LIMPIADO",
    original: "Original",
    group_prefix: "Grupo",
    group_files: "archivos",
    footer_template: "ZeroDupe · {date} · {groups} grupos · {kept} conservados · {cleaned} limpiados · {saved} MB liberados",
    hy_title: "Archivos limpiados",
    hy_desc: "ZeroDupe eliminó archivos basura dejados por sistemas operativos y aplicaciones.",
    hy_th_file: "Archivo",
    hy_th_category: "Categoría",
    hy_th_size: "Tamaño",
    hy_summary_files: "archivos",
    hy_summary_reclaimed: "recuperado",
    pro_title: "Duplicados protegidos — No modificados",
    pro_desc: "Estos archivos son duplicados pero NO se movieron a cuarentena porque están en ubicaciones protegidas del sistema o son archivos críticos.",
    pro_manual_review: "Se recomienda revisión manual. Puedes eliminar los archivos no protegidos manualmente si es necesario.",
    pro_group_label: "Grupo {index} — {total} archivos ({size})",
    pro_protected_label: "PROTEGIDO (no modificado)",
    pro_cleaned_label: "Limpiado o conservado",
    pro_total_groups: "Total de grupos protegidos",
    pro_protected_space: "Espacio protegido",
    pro_can_clean: "Archivos que PUEDES limpiar manualmente",
    similar_conf: "confianza",
    similar_total_files: "archivos totales",
    similar_footer: "ZeroDupe · {date} · {groups} grupos · {total} imágenes similares",
    confidence: "confianza",
};
