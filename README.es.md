# ZeroDupe Engine

*[English](README.md)*

![Licencia](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-edici%C3%B3n_2024-orange)
![Plataforma](https://img.shields.io/badge/plataforma-Linux-333)
![Privacidad](https://img.shields.io/badge/nube-ninguna-success)

**Un buscador de duplicados rápido y cuidadoso, y herramienta de higiene digital — 100% local, no envía nada a la nube.** Este es el motor de código abierto y la CLI detrás de ZeroDupe.

No solo *encuentra* duplicados: te ayuda a decidir **cuál copia conservar**, y nunca borra nada de forma irreversible.

## Funcionalidades

- 🎯 **Duplicados exactos** — Pipeline progresivo que hace el menor trabajo posible: agrupar por tamaño → comprobación de identidad física (hardlinks) → BLAKE3 parcial (4 KB cabeza+cola) → BLAKE3 completo (256 bits) → **verificación final byte a byte**. No se actúa sobre nada hasta confirmar que dos archivos son idénticos byte a byte.
- 🖼️ **Imágenes similares** — Hash perceptual (pHash + dHash) sobre un BK-tree con invarianza geométrica: espejo H/V, rotaciones (90/180/270°) y recorte central, no solo recompresiones/redimensionados. Formatos RAW comunes (CR2, NEF, ARW, DNG y más) vía su vista previa JPEG embebida (`rawler`). Cada grupo trae una etiqueta de confianza.
- 🧹 **Higiene digital** — Siete detectores para archivos/carpetas vacíos, temporales, symlinks rotos, basura del sistema (`.DS_Store`, `Thumbs.db`), cachés de compilación y sidecars huérfanos, clasificados en tres niveles de riesgo. Una lista de seguridad nunca toca `.git`, `node_modules` activos, etc.
- 🏆 **Selección de keeper** — Decide cuál archivo conservar a partir de calidad de contenido, metadatos EXIF, nombre y ruta — no "el primero" ni "el de nombre más corto".
- ♻️ **Cuarentena reversible** — Los archivos se mueven a una cuarentena con journal SQLite mediante rename atómico, nunca se borran. Restaura lo que quieras; auto-purga a los 30 días.
- ⚡ **Caché inteligente** — Un caché de hashes en SQLite indexado por device/inode/tamaño/mtime convierte los re-escaneos de minutos a milisegundos. Testigos con precisión de nanosegundo (device/inode/tamaño/mtime) protegen contra entradas de caché obsoletas.
- 🌐 **CLI bilingüe** — Salida en inglés y español, autodetectada desde `LANG`.

## Arquitectura

Un workspace de Rust con 16 crates (`edition = "2024"`, MSRV 1.95):

| Capa         | Crates                                          | Rol                                             |
|--------------|-------------------------------------------------|-------------------------------------------------|
| Núcleo       | `core` · `fs` · `hash` · `platform` · `config`  | Tipos, descubrimiento, hashing, SO, configuración |
| Exactos      | `scan` · `cache`                                | Pipeline de duplicados exactos + caché de hashes |
| Similares    | `similar` · `similar_image` · `policy`          | Hash perceptual + selección de keeper           |
| Higiene      | `hygiene`                                       | Siete detectores de basura, tres niveles de riesgo |
| Operación    | `workflow` · `safety` · `report`                | Máquina de estados, cuarentena, reportes HTML   |
| Interfaz     | `cli` · `benchkit`                              | Línea de comandos + dataset de benchmark reproducible |

## Compilar

Requiere una toolchain de Rust reciente (ver `rust-toolchain.toml`).

```bash
git clone https://github.com/zerodupeapp/zerodupe
cd zerodupe
cargo build --release
# binario en target/release/zerodupe
```

## Uso

```bash
# Flujo interactivo (recomendado): escanea, revisa grupos, elige qué poner en cuarentena
zerodupe interactive /ruta/a/escanear

# Escaneos de un solo propósito
zerodupe similar  /ruta/a/escanear     # solo imágenes casi idénticas
zerodupe hygiene  /ruta/a/escanear     # solo basura (agrega --dry-run para reportar sin mover)

# Avanzado: ejecuta el pipeline exacto y emite JSON para scripting
zerodupe scan --candidates --partial-hash --full-hash --byte-compare --json /ruta/a/escanear

# Gestionar la cuarentena
zerodupe quarantine list
zerodupe quarantine restore-all
```

Ejecuta `zerodupe --help` para ver todos los subcomandos y flags.

## Dataset de benchmark reproducible

El crate `zerodupe_benchkit` genera un dataset sintético **determinista** con ground truth (duplicados exactos, recompresión/redimensionado JPEG, variantes geométricas, hermanos RAW+JPEG, archivos únicos y basura de higiene) para que cualquiera mida la precisión/recall de detección — contra ZeroDupe o cualquier otra herramienta:

```bash
cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /tmp/zd_bench
```

Ver `crates/zerodupe_benchkit/README.md` para el esquema del ground truth y las métricas.

## Privacidad

Sin nube, sin telemetría, sin llamadas de red. Todo corre en tu máquina.

## Licencia

MIT — ver [LICENSE](LICENSE).
