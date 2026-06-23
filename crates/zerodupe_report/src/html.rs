//! Generación de reportes HTML para los tres pilares de ZeroDupe.
//!
//! Este módulo produce archivos HTML autocontenidos con CSS embebido y diseño
//! responsivo. Cada pilar tiene su propia función generadora:
//!
//! - [`generate_exact_html_report`]: reporte de duplicados exactos, con grupos,
//!   archivos conservados/limpiados, cuarentena y resumen de espacio.
//! - [`generate_similar_html_report`]: reporte de imágenes similares, con nivel
//!   de confianza por grupo y keeper scoring.
//! - [`append_hygiene_section`]: sección de higiene que se inyecta en un HTML
//!   existente (antes de `</body>`), con tabla de archivos basura y categorías.
//! - [`append_protected_section`]: sección de duplicados protegidos no movidos
//!   a cuarentena, con archivos protegidos y limpiables separados.
//!
//! Los textos usan internacionalización vía [`crate::i18n::Strings`].

use std::io;
use std::path::{Path, PathBuf};

use zerodupe_core::ByteCompareReport;
use zerodupe_hygiene::types::HygieneReport;
use zerodupe_similar::SimilarityReport;

use crate::i18n::Strings;

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn chrono_lite() -> String {
    // Return the current local date and time, formatted as:
    // `Mon DD, YYYY · HH:MM` (e.g. `Jan 01, 2024 · 14:30`).
    //
    // Uses the system's local timezone. Falls back to UTC if the local
    // offset cannot be determined (e.g. in containers without tzdata).
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let (y, m, d) = (now.year(), now.month() as u32, now.day());
    let (h, min) = (now.hour(), now.minute());
    format!(
        "{} {:02}, {} · {:02}:{:02}",
        month_name(m as i64),
        d,
        y,
        h,
        min
    )
}

fn month_name(m: i64) -> &'static str {
    match m {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    }
}

/// Genera un reporte HTML para duplicados exactos y lo escribe a disco.
///
/// El HTML incluye:
/// - Cabecera con ruta escaneada, fecha y resumen de stats (grupos, archivos
///   limpiados, espacio ahorrado, duración).
/// - Una sección por cada grupo de duplicados, mostrando el archivo conservado
///   (keeper) y los archivos limpiados con su ruta de cuarentena.
/// - Pie de página con resumen final.
///
/// Devuelve la ruta del archivo generado.
pub fn generate_exact_html_report(
    lang: &str,
    scan_path: &Path,
    output_path: &Path,
    compare: &ByteCompareReport,
    quarantine_paths: &std::collections::HashMap<String, String>,
    elapsed: std::time::Duration,
) -> io::Result<PathBuf> {
    let s = Strings::for_lang(lang);

    let dup_count: usize = compare
        .confirmed_groups
        .iter()
        .map(|g| g.files.len() - 1)
        .sum();
    let total_files: usize = compare.confirmed_groups.iter().map(|g| g.files.len()).sum();
    let savings: u64 = compare
        .confirmed_groups
        .iter()
        .map(|g| g.size_bytes * (g.files.len() as u64 - 1))
        .sum();

    let mut html = String::new();
    html.push_str(&format!(
        "<!DOCTYPE html><html lang=\"{}\"><head><meta charset=\"UTF-8\">",
        s.lang_attr
    ));
    html.push_str(&format!("<title>{}</title>", s.report_title_exact));
    html.push_str("<style>");
    html.push_str("body{font-family:system-ui,sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem;color:#1a1a2e;background:#f8f9fa}");
    html.push_str("h1{color:#1e7a78;border-bottom:2px solid #1e7a78;padding-bottom:.5rem}");
    html.push_str(".summary{display:flex;gap:1.5rem;margin:1.5rem 0}");
    html.push_str(".stat{background:#fff;padding:1rem 1.5rem;border-radius:14px;box-shadow:0 2px 8px rgba(0,0,0,.06)}");
    html.push_str(".stat .num{font-size:1.8rem;font-weight:700;color:#1e7a78}");
    html.push_str(".stat .label{font-size:.85rem;color:#666;margin-top:.25rem}");
    html.push_str(
        ".group{margin:1.5rem 0;border:1px solid #e0e0e0;border-radius:14px;overflow:hidden}",
    );
    html.push_str(
        ".group-header{background:#1e7a78;color:#fff;padding:.75rem 1rem;font-weight:600}",
    );
    html.push_str(".keeper{background:#e8f5e9;padding:.6rem 1rem;border-left:4px solid #2e7d32}");
    html.push_str(".cleaned{background:#fff3e0;padding:.6rem 1rem;border-left:4px solid #e65100}");
    html.push_str(".file{font-family:'JetBrains Mono',monospace;font-size:.85rem;margin:.2rem 0}");
    html.push_str(".link{color:#1e7a78;text-decoration:underline}");
    html.push_str(".foot{text-align:center;color:#999;font-size:.8rem;margin-top:3rem}");
    html.push_str("</style></head><body>");

    html.push_str(&format!(
        "<h1>{}</h1><p>{}: <code>{}</code><br>{}: {}</p>",
        s.report_title_exact,
        s.scanned,
        scan_path.display(),
        s.date,
        chrono_lite()
    ));

    html.push_str("<div class=\"summary\">");
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"label\">{}</div></div>",
        compare.confirmed_groups.len(),
        s.groups_found
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"label\">{}</div></div>",
        dup_count, s.files_cleaned
    ));
    if savings > 0 {
        html.push_str(&format!(
            "<div class=\"stat\"><div class=\"num\">{:.1} MB</div><div class=\"label\">{}</div></div>",
            savings as f64 / 1_000_000.0, s.space_saved
        ));
    }
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"label\">{}</div></div>",
        format_duration(elapsed),
        s.duration
    ));
    html.push_str("</div>");

    for (gi, group) in compare.confirmed_groups.iter().enumerate() {
        html.push_str(&format!(
            "<div class=\"group\"><div class=\"group-header\">{} {} — {:.1} MB — {} {}</div>",
            s.group_prefix,
            gi + 1,
            group.size_bytes as f64 / 1_000_000.0,
            group.files.len(),
            s.group_files
        ));
        for (fi, file) in group.files.iter().enumerate() {
            if fi == group.keeper_index {
                let p = file.path.as_str();
                html.push_str(&format!(
                    "<div class=\"keeper\"><strong>{}</strong><br>\
                     <span class=\"file\"><a class=\"link\" href=\"file://{}\">{}</a></span></div>",
                    s.kept, p, p
                ));
            } else {
                let original = file.path.as_str();
                let q_path = quarantine_paths
                    .get(original)
                    .map(|s| s.as_str())
                    .unwrap_or(original);
                html.push_str(&format!(
                    "<div class=\"cleaned\"><strong>{}</strong><br>\
                     <span class=\"file\">{}: {}</span><br>\
                     <span class=\"file\">→ <a class=\"link\" href=\"file://{}\">{}</a></span></div>",
                    s.cleaned, s.original, original, q_path, q_path
                ));
            }
        }
        html.push_str("</div>");
    }

    let footer = s
        .footer_template
        .replace("{date}", &chrono_lite())
        .replace("{groups}", &compare.confirmed_groups.len().to_string())
        .replace("{kept}", &(total_files - dup_count).to_string())
        .replace("{cleaned}", &dup_count.to_string())
        .replace("{saved}", &format!("{:.1}", savings as f64 / 1_000_000.0));
    html.push_str(&format!("<div class=\"foot\">{footer}</div>"));
    html.push_str("</body></html>");

    std::fs::write(output_path, html)?;
    Ok(output_path.to_path_buf())
}

/// Genera un reporte HTML para imágenes similares y lo escribe a disco.
///
/// El HTML incluye:
/// - Cabecera con ruta escaneada, fecha y resumen de stats (grupos, archivos
///   totales, duración).
/// - Una sección por cada grupo de imágenes similares, con nivel de confianza
///   y el archivo conservado (keeper) según el keeper scoring.
/// - Archivos no conservados con su ruta de cuarentena.
/// - Pie de página con resumen final.
///
/// Devuelve la ruta del archivo generado.
pub fn generate_similar_html_report(
    lang: &str,
    scan_path: &Path,
    output_path: &Path,
    report: &SimilarityReport,
    quarantine_paths: &std::collections::HashMap<String, String>,
    elapsed: std::time::Duration,
) -> io::Result<PathBuf> {
    let s = Strings::for_lang(lang);
    let total_files: usize = report.groups.iter().map(|g| g.files.len()).sum();

    let mut html = String::new();
    html.push_str(&format!(
        "<!DOCTYPE html><html lang=\"{}\"><head><meta charset=\"UTF-8\">",
        s.lang_attr
    ));
    html.push_str(&format!("<title>{}</title>", s.report_title_similar));
    html.push_str("<style>");
    html.push_str("body{font-family:system-ui,sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem;color:#1a1a2e;background:#f8f9fa}");
    html.push_str("h1{color:#1e7a78;border-bottom:2px solid #1e7a78;padding-bottom:.5rem}");
    html.push_str(".summary{display:flex;gap:1.5rem;margin:1.5rem 0}");
    html.push_str(".stat{background:#fff;padding:1rem 1.5rem;border-radius:14px;box-shadow:0 2px 8px rgba(0,0,0,.06)}");
    html.push_str(".stat .num{font-size:1.8rem;font-weight:700;color:#1e7a78}");
    html.push_str(".stat .label{font-size:.85rem;color:#666;margin-top:.25rem}");
    html.push_str(
        ".group{margin:1.5rem 0;border:1px solid #e0e0e0;border-radius:14px;overflow:hidden}",
    );
    html.push_str(
        ".group-header{background:#1e7a78;color:#fff;padding:.75rem 1rem;font-weight:600}",
    );
    html.push_str(".keeper{background:#e8f5e9;padding:.6rem 1rem;border-left:4px solid #2e7d32}");
    html.push_str(".cleaned{background:#fff3e0;padding:.6rem 1rem;border-left:4px solid #e65100}");
    html.push_str(".file{font-family:'JetBrains Mono',monospace;font-size:.85rem;margin:.2rem 0}");
    html.push_str(".link{color:#1e7a78;text-decoration:underline}");
    html.push_str(".conf{color:#888;font-size:.85rem}");
    html.push_str(".foot{text-align:center;color:#999;font-size:.8rem;margin-top:3rem}");
    html.push_str("</style></head><body>");

    html.push_str(&format!(
        "<h1>{}</h1><p>{}: <code>{}</code><br>{}: {}</p>",
        s.report_title_similar,
        s.scanned,
        scan_path.display(),
        s.date,
        chrono_lite()
    ));

    html.push_str("<div class=\"summary\">");
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"label\">{}</div></div>",
        report.groups.len(),
        s.groups_found
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"label\">{}</div></div>",
        total_files, s.similar_total_files
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"label\">{}</div></div>",
        format_duration(elapsed),
        s.duration
    ));
    html.push_str("</div>");

    for (gi, group) in report.groups.iter().enumerate() {
        html.push_str(&format!(
            "<div class=\"group\"><div class=\"group-header\">{} {} — {} {} — {} {}</div>",
            s.group_prefix,
            gi + 1,
            group.confidence,
            s.confidence,
            group.files.len(),
            s.group_files
        ));
        for (fi, file) in group.files.iter().enumerate() {
            if fi == group.keeper_index {
                let p = file.path.as_str();
                html.push_str(&format!(
                    "<div class=\"keeper\"><strong>{}</strong><br>\
                     <span class=\"file\"><a class=\"link\" href=\"file://{}\">{}</a></span></div>",
                    s.kept, p, p
                ));
            } else {
                let original = file.path.as_str();
                let q_path = quarantine_paths
                    .get(original)
                    .map(|s| s.as_str())
                    .unwrap_or(original);
                html.push_str(&format!(
                    "<div class=\"cleaned\"><strong>{}</strong><br>\
                     <span class=\"file\">{}: {}</span><br>\
                     <span class=\"file\">→ <a class=\"link\" href=\"file://{}\">{}</a></span></div>",
                    s.cleaned, s.original, original, q_path, q_path
                ));
            }
        }
        html.push_str("</div>");
    }

    let footer = s
        .similar_footer
        .replace("{date}", &chrono_lite())
        .replace("{groups}", &report.groups.len().to_string())
        .replace("{total}", &total_files.to_string());
    html.push_str(&format!("<div class=\"foot\">{footer}</div>"));
    html.push_str("</body></html>");

    std::fs::write(output_path, html)?;
    Ok(output_path.to_path_buf())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Inyecta una sección de higiene en un archivo HTML existente (antes de `</body>`).
///
/// La sección contiene:
/// - Título y descripción de la limpieza realizada.
/// - Tabla con archivos basura encontrados: ruta, categoría y tamaño.
/// - Resumen con cantidad de archivos limpiados y bytes recuperados.
///
/// Si el HTML no tiene cierre `</body>`, la sección se agrega al final del archivo.
pub fn append_hygiene_section(
    lang: &str,
    html_path: &Path,
    hygiene_report: &HygieneReport,
) -> io::Result<()> {
    let s = Strings::for_lang(lang);
    let mut html = std::fs::read_to_string(html_path)?;

    let mut section = String::new();
    section.push_str("<div style='margin-top:40px;padding-top:24px;border-top:2px solid #e2e8f0'>");
    section.push_str(&format!(
        "<h2 style='font-family:-apple-system,sans-serif;color:#1e293b'>{}</h2>",
        s.hy_title
    ));
    section.push_str(&format!(
        "<p style='color:#64748b;font-size:14px'>{}</p>",
        s.hy_desc
    ));
    section.push_str("<table style='width:100%;border-collapse:collapse;margin-top:16px'>");
    section.push_str("<thead><tr style='text-align:left;border-bottom:1px solid #e2e8f0'>");
    section.push_str(&format!(
        "<th style='padding:8px;font-size:12px;color:#64748b'>{}</th>",
        s.hy_th_file
    ));
    section.push_str(&format!(
        "<th style='padding:8px;font-size:12px;color:#64748b'>{}</th>",
        s.hy_th_category
    ));
    section.push_str(&format!(
        "<th style='padding:8px;font-size:12px;color:#64748b;text-align:right'>{}</th>",
        s.hy_th_size
    ));
    section.push_str("</tr></thead><tbody>");

    for item in &hygiene_report.items {
        if item.can_clean {
            let cat_name = format!("{}", item.category);
            let size = format_size(item.size_bytes);
            section.push_str(&format!(
                "<tr style='border-bottom:1px solid #f1f5f9'><td style='padding:8px;font-size:13px;font-family:monospace'>{}</td><td style='padding:8px;font-size:12px;color:#64748b'>{}</td><td style='padding:8px;font-size:12px;text-align:right'>{}</td></tr>",
                item.path, cat_name, size
            ));
        }
    }

    section.push_str("</tbody></table>");
    section.push_str(&format!(
        "<p style='margin-top:12px;font-size:13px;color:#64748b'><strong>{}</strong> {} · <strong>{}</strong> {}</p>",
        hygiene_report.items.iter().filter(|i| i.can_clean).count(),
        s.hy_summary_files,
        format_size(hygiene_report.items.iter().filter(|i| i.can_clean).map(|i| i.size_bytes).sum()),
        s.hy_summary_reclaimed,
    ));
    section.push_str("</div>");

    if let Some(pos) = html.rfind("</body>") {
        html.insert_str(pos, &section);
    } else {
        html.push_str(&section);
    }

    std::fs::write(html_path, html)?;
    Ok(())
}

/// Inyecta una sección de archivos protegidos en un HTML existente (antes de `</body>`).
///
/// Muestra los duplicados que **no** se movieron a cuarentena por estar en
/// ubicaciones protegidas del sistema o ser archivos críticos. Por cada grupo:
/// - Archivos protegidos (no modificados) con el motivo de protección.
/// - Archivos que sí se limpiaron o conservaron.
/// - Resumen global con espacio protegido y archivos que pueden limpiarse manualmente.
///
/// Si `protected_groups` está vacío, la función no modifica el HTML.
pub fn append_protected_section(
    lang: &str,
    html_path: &Path,
    protected_groups: &[zerodupe_core::ProtectedGroup],
) -> io::Result<()> {
    if protected_groups.is_empty() {
        return Ok(());
    }

    let s = Strings::for_lang(lang);
    let mut html = std::fs::read_to_string(html_path)?;

    let mut section = String::new();
    section.push_str("<div style='margin-top:40px;padding-top:24px;border-top:2px solid #f59e0b'>");
    section.push_str(&format!(
        "<h2 style='font-family:-apple-system,sans-serif;color:#92400e'>{}</h2>",
        s.pro_title
    ));
    section.push_str(&format!(
        "<p style='color:#64748b;font-size:14px;margin-bottom:4px'>{}</p>",
        s.pro_desc
    ));
    section.push_str(&format!(
        "<p style='color:#94a3b8;font-size:12px;margin-top:0'>{}</p>",
        s.pro_manual_review
    ));

    let mut total_protected_bytes: u64 = 0;
    let mut total_unprotected_files: usize = 0;
    let mut total_unprotected_bytes: u64 = 0;

    for group in protected_groups {
        total_protected_bytes += group.protected_bytes;

        for f in &group.cleaned_files {
            total_unprotected_files += 1;
            total_unprotected_bytes += f.size_bytes;
        }

        section.push_str(
            "<div style='background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:16px;margin-top:20px'>",
        );
        let group_label = s
            .pro_group_label
            .replace("{index}", &(group.group_index + 1).to_string())
            .replace("{total}", &group.total_files.to_string())
            .replace(
                "{size}",
                &format_size(
                    group.protected_bytes
                        + group
                            .cleaned_files
                            .iter()
                            .map(|f| f.size_bytes)
                            .sum::<u64>(),
                ),
            );
        section.push_str(&format!(
            "<h3 style='font-size:14px;color:#92400e;margin-top:0'>{group_label}</h3>"
        ));

        if !group.protected_files.is_empty() {
            section.push_str(&format!(
                "<p style='font-size:12px;color:#d97706;font-weight:600;margin-bottom:8px'>{}:</p>",
                s.pro_protected_label
            ));
            section
                .push_str("<table style='width:100%;border-collapse:collapse;margin-bottom:12px'>");
            for f in &group.protected_files {
                let reason_short = if f.reason.len() > 60 {
                    format!("{}...", &f.reason[..57])
                } else {
                    f.reason.clone()
                };
                section.push_str(&format!(
                    "<tr style='border-bottom:1px solid #fef3c7'><td style='padding:6px 8px;font-size:12px;font-family:monospace;color:#475569'>{}</td><td style='padding:6px 8px;font-size:11px;color:#d97706'>{}</td><td style='padding:6px 8px;font-size:11px;text-align:right;color:#94a3b8'>{}</td></tr>",
                    f.path,
                    reason_short,
                    format_size(f.size_bytes)
                ));
            }
            section.push_str("</table>");
        }

        if !group.cleaned_files.is_empty() {
            section.push_str(&format!(
                "<p style='font-size:12px;color:#059669;font-weight:600;margin-bottom:8px'>{}:</p>",
                s.pro_cleaned_label
            ));
            section.push_str("<table style='width:100%;border-collapse:collapse'>");
            for f in &group.cleaned_files {
                section.push_str(&format!(
                    "<tr style='border-bottom:1px solid #fef3c7'><td style='padding:6px 8px;font-size:12px;font-family:monospace;color:#475569'>{}</td><td style='padding:6px 8px;font-size:11px;text-align:right;color:#94a3b8'>{}</td></tr>",
                    f.path,
                    format_size(f.size_bytes)
                ));
            }
            section.push_str("</table>");
        }

        section.push_str("</div>");
    }

    section.push_str(
        "<div style='background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:16px;margin-top:24px'>",
    );
    section.push_str(&format!(
        "<p style='font-size:13px;color:#92400e;margin:0'><strong>{}:</strong> {}</p>",
        s.pro_total_groups,
        protected_groups.len()
    ));
    section.push_str(&format!(
        "<p style='font-size:13px;color:#92400e;margin:4px 0'><strong>{}:</strong> {} (NOT recovered — files untouched)</p>",
        s.pro_protected_space, format_size(total_protected_bytes)
    ));
    if total_unprotected_files > 0 {
        section.push_str(&format!(
            "<p style='font-size:13px;color:#059669;margin:4px 0'><strong>{}:</strong> {} ({})</p>",
            s.pro_can_clean,
            total_unprotected_files,
            format_size(total_unprotected_bytes)
        ));
    }
    section.push_str("</div>");

    section.push_str("</div>");

    if let Some(pos) = html.rfind("</body>") {
        html.insert_str(pos, &section);
    } else {
        html.push_str(&section);
    }

    std::fs::write(html_path, html)?;
    Ok(())
}
