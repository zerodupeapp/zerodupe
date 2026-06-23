//! Generación de reportes HTML para el Pilar 3 — Higiene.
//!
//! Produce un archivo `ZeroDupe_Hygiene_Report.html` autocontenido con:
//!
//! - Fecha y ruta escaneada
//! - Resumen con total de ítems, tamaño y porcentajes por nivel de riesgo
//! - Desglose por categoría con tabla de archivos (ruta, tamaño, riesgo, explicación)
//! - Tabla resumen final por categoría
//!
//! El HTML usa estilos inline (sin dependencias externas) y enlaces `file://`
//! para abrir cada archivo desde el navegador.

use camino::Utf8Path;
use std::io;

use crate::types::{HygieneReport, RiskLevel};

fn chrono_lite() -> String {
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            let days_since_epoch = secs / 86400;
            let mut y = 1970i64;
            let mut remaining = days_since_epoch as i64;
            loop {
                let year_days = if is_leap(y) { 366 } else { 365 };
                if remaining < year_days {
                    break;
                }
                remaining -= year_days;
                y += 1;
            }
            let month_days = if is_leap(y) {
                [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            } else {
                [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            };
            let mut m = 1;
            for &md in &month_days {
                if remaining < md {
                    break;
                }
                remaining -= md;
                m += 1;
            }
            let day = remaining + 1;
            let total_secs_today = secs % 86400;
            let h = total_secs_today / 3600;
            let min = (total_secs_today % 3600) / 60;
            format!("{} {:02}, {} · {:02}:{:02}", month_name(m), day, y, h, min)
        }
        Err(_) => "unknown date".to_string(),
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
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

fn format_size(bytes: u64) -> String {
    const KB: f64 = 1_000.0;
    const MB: f64 = 1_000_000.0;
    const GB: f64 = 1_000_000_000.0;
    if bytes as f64 >= GB {
        format!("{:.2} GB", bytes as f64 / GB)
    } else if bytes as f64 >= MB {
        format!("{:.2} MB", bytes as f64 / MB)
    } else if bytes as f64 >= KB {
        format!("{:.2} KB", bytes as f64 / KB)
    } else {
        format!("{} B", bytes)
    }
}

fn risk_color(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "#2e7d32",
        RiskLevel::Medium => "#ef6c00",
        RiskLevel::High => "#c62828",
    }
}

fn risk_bg(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "#e8f5e9",
        RiskLevel::Medium => "#fff3e0",
        RiskLevel::High => "#ffebee",
    }
}

fn risk_label(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
    }
}

/// Genera un reporte HTML autocontenido en `ZeroDupe_Hygiene_Report.html`
/// dentro del directorio de escaneo.
///
/// El reporte incluye:
/// - Cabecera con ruta escaneada y fecha/hora
/// - Panel de resumen: total de ítems, tamaño total, % por nivel de riesgo
/// - Tablas por categoría con cada archivo, su tamaño, badge de riesgo y explicación
/// - Tabla resumen final con conteos y tamaños por categoría
///
/// Los badges de riesgo usan código de colores:
/// - 🟢 Low: verde sobre fondo verde claro
/// - 🟠 Medium: naranja sobre fondo naranja claro
/// - 🔴 High: rojo sobre fondo rojo claro
///
/// Devuelve la ruta completa al archivo HTML generado.
pub fn generate_html_report(
    report: &HygieneReport,
    scan_path: &Utf8Path,
) -> io::Result<camino::Utf8PathBuf> {
    let path = scan_path.join("ZeroDupe_Hygiene_Report.html");

    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">");
    html.push_str("<title>ZeroDupe Hygiene Report</title>");
    html.push_str("<style>");
    html.push_str("body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a2e;background:#f8f9fa}");
    html.push_str("h1{color:#1e7a78;border-bottom:2px solid #1e7a78;padding-bottom:.5rem}");
    html.push_str(".summary{display:flex;gap:1.5rem;margin:1.5rem 0;flex-wrap:wrap}");
    html.push_str(".stat{background:#fff;padding:1rem 1.5rem;border-radius:14px;box-shadow:0 2px 8px rgba(0,0,0,.06);min-width:120px}");
    html.push_str(".stat .num{font-size:1.8rem;font-weight:700;color:#1e7a78}");
    html.push_str(".stat .label{font-size:.85rem;color:#666;margin-top:.25rem}");
    html.push_str(".category-section{margin:1.5rem 0}");
    html.push_str(".category-header{background:#1e7a78;color:#fff;padding:.75rem 1rem;font-weight:600;border-radius:14px 14px 0 0;font-size:.95rem}");
    html.push_str(".category-body{background:#fff;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 14px 14px;overflow:hidden}");
    html.push_str("table{width:100%;border-collapse:collapse}");
    html.push_str("th{text-align:left;padding:.6rem 1rem;font-size:.8rem;color:#888;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #e0e0e0}");
    html.push_str("td{padding:.55rem 1rem;font-size:.88rem;border-bottom:1px solid #f0f0f0}");
    html.push_str("tr:last-child td{border-bottom:none}");
    html.push_str(
        ".file{font-family:'JetBrains Mono',monospace;font-size:.82rem;word-break:break-all}",
    );
    html.push_str(".risk-badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em}");
    html.push_str(".explanation{color:#888;font-size:.8rem;margin-top:2px}");
    html.push_str(".link{color:#1e7a78;text-decoration:underline}");
    html.push_str(".foot{text-align:center;color:#999;font-size:.8rem;margin-top:3rem}");
    html.push_str(".zero-state{text-align:center;padding:3rem;color:#888;font-size:1.1rem}");
    html.push_str("</style></head><body>");

    html.push_str(&format!(
        "<h1>ZeroDupe — Hygiene Report</h1>\
         <p>Scanned: <code>{}</code><br>Date: {}</p>",
        scan_path.as_str(),
        chrono_lite()
    ));

    html.push_str("<div class=\"summary\">");
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"label\">total items</div></div>",
        report.summary.total_items
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{}</div><div class=\"label\">total size</div></div>",
        format_size(report.summary.total_size_bytes)
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{:.1}%</div><div class=\"label\">low risk</div></div>",
        if report.summary.total_items > 0 {
            (report.summary.low_risk_count as f64 / report.summary.total_items as f64) * 100.0
        } else {
            0.0
        }
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{:.1}%</div><div class=\"label\">medium risk</div></div>",
        if report.summary.total_items > 0 {
            (report.summary.medium_risk_count as f64 / report.summary.total_items as f64) * 100.0
        } else {
            0.0
        }
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"num\">{:.1}%</div><div class=\"label\">high risk</div></div>",
        if report.summary.total_items > 0 {
            (report.summary.high_risk_count as f64 / report.summary.total_items as f64) * 100.0
        } else {
            0.0
        }
    ));
    html.push_str("</div>");

    html.push_str("<h2>Breakdown by Category</h2>");

    if report.summary.by_category.is_empty() {
        html.push_str("<div class=\"category-section\"><div class=\"zero-state\">No junk items found — your directory is clean!</div></div>");
    }

    for (cat_name, count, size) in &report.summary.by_category {
        let items: Vec<_> = report
            .items
            .iter()
            .filter(|item| format!("{}", item.category) == *cat_name)
            .collect();

        html.push_str("<div class=\"category-section\">");
        html.push_str(&format!(
            "<div class=\"category-header\">{} — {} item{} — {}</div>",
            cat_name,
            count,
            if *count == 1 { "" } else { "s" },
            format_size(*size)
        ));
        html.push_str("<div class=\"category-body\"><table>");
        html.push_str("<thead><tr><th>Path</th><th>Size</th><th>Risk</th><th>Explanation</th></tr></thead><tbody>");

        for item in &items {
            let color = risk_color(item.risk);
            let bg = risk_bg(item.risk);
            let label = risk_label(item.risk);
            let p = item.path.as_str();
            html.push_str(&format!(
                "<tr>\
                 <td><div class=\"file\"><a class=\"link\" href=\"file://{}\">{}</a></div></td>\
                 <td>{}</td>\
                 <td><span class=\"risk-badge\" style=\"background:{};color:{}\">{}</span></td>\
                 <td><div class=\"explanation\">{}</div></td>\
                 </tr>",
                p,
                p,
                format_size(item.size_bytes),
                bg,
                color,
                label,
                item.explanation
            ));
        }

        html.push_str("</tbody></table></div></div>");
    }

    html.push_str("<div class=\"category-section\">");
    html.push_str("<h2>Category Summary</h2>");
    html.push_str("<div class=\"category-body\"><table>");
    html.push_str("<thead><tr><th>Category</th><th>Items</th><th>Size</th></tr></thead><tbody>");
    for (cat_name, count, size) in &report.summary.by_category {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            cat_name,
            count,
            format_size(*size)
        ));
    }
    html.push_str("</tbody></table></div></div>");

    html.push_str(&format!(
        "<div class=\"foot\">ZeroDupe · {} · {} items · low {} · med {} · high {} · {}</div>",
        chrono_lite(),
        report.summary.total_items,
        report.summary.low_risk_count,
        report.summary.medium_risk_count,
        report.summary.high_risk_count,
        format_size(report.summary.total_size_bytes)
    ));
    html.push_str("</body></html>");

    std::fs::write(path.as_std_path(), html)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HygieneReport, JunkCategory, JunkItem, RiskLevel};

    fn make_item(
        path_str: &str,
        category: JunkCategory,
        risk: RiskLevel,
        size: u64,
        explanation: &str,
    ) -> JunkItem {
        JunkItem {
            path: camino::Utf8PathBuf::from(path_str),
            category,
            risk,
            size_bytes: size,
            explanation: explanation.to_string(),
            can_clean: true,
        }
    }

    #[test]
    fn generates_html_file() {
        let items = vec![
            make_item(
                "/tmp/empty.txt",
                JunkCategory::EmptyFile,
                RiskLevel::Low,
                0,
                "Empty file",
            ),
            make_item(
                "/tmp/tmp_abc123",
                JunkCategory::TemporaryFile,
                RiskLevel::Medium,
                4096,
                "Temporary file",
            ),
        ];
        let report = HygieneReport::new(items);
        let dir = tempfile::tempdir().unwrap();
        let scan_path = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let html_path = generate_html_report(&report, &scan_path).unwrap();
        assert!(html_path.as_std_path().exists());

        let html = std::fs::read_to_string(&*html_path).unwrap();
        assert!(html.contains("<html"));
        assert!(html.contains("Hygiene"));
        assert!(html.contains("empty.txt"));
        assert!(html.contains("tmp_abc123"));
    }

    #[test]
    fn empty_report_generates_html() {
        let report = HygieneReport::new(vec![]);
        let dir = tempfile::tempdir().unwrap();
        let scan_path = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let html_path = generate_html_report(&report, &scan_path).unwrap();
        assert!(html_path.as_std_path().exists());

        let html = std::fs::read_to_string(&*html_path).unwrap();
        assert!(html.contains("<html"));
        assert!(html.contains("Hygiene"));
        assert!(html.contains("No junk items found"));
    }

    #[test]
    fn generated_html_contains_item_paths() {
        let items = vec![
            make_item(
                "/home/user/duplicate_file.bak",
                JunkCategory::CacheFile,
                RiskLevel::Low,
                1024,
                "Cache file",
            ),
            make_item(
                "/home/user/broken_link",
                JunkCategory::BrokenSymlink,
                RiskLevel::High,
                0,
                "Broken symlink",
            ),
        ];
        let report = HygieneReport::new(items);
        let dir = tempfile::tempdir().unwrap();
        let scan_path = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let html_path = generate_html_report(&report, &scan_path).unwrap();
        let html = std::fs::read_to_string(&*html_path).unwrap();

        assert!(html.contains("duplicate_file.bak"));
        assert!(html.contains("broken_link"));
        assert!(html.contains("Cache file"));
        assert!(html.contains("Broken symlink"));
    }
}
