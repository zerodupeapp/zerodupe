# ZeroDupe Engine

*[English](README.md)*

**Un buscador de duplicados rápido y cuidadoso, y herramienta de higiene digital para Linux — 100% local, no envía nada a la nube.** Este es el motor de código abierto y su interfaz de línea de comandos.

ZeroDupe no solo *encuentra* duplicados: te ayuda a decidir *cuál copia conservar* y nunca borra nada de forma irreversible.

## Qué hace

- **Duplicados exactos.** Pipeline progresivo: agrupar por tamaño → comprobación de identidad física (hardlinks) → BLAKE3 parcial (4 KB cabeza+cola) → BLAKE3 completo (256 bits) → **verificación final byte a byte**. No se actúa sobre nada hasta confirmar que dos archivos son idénticos byte a byte. Una revalidación rechaza actuar sobre cualquier archivo cuyo tamaño cambió desde el escaneo (protección TOCTTOU).
- **Imágenes similares.** Hash perceptual (pHash + dHash) con BK-tree e invarianza geométrica — detecta espejo H/V, rotaciones (90/180/270°) y recorte central, no solo recompresiones y redimensionados. Soporta formatos RAW vía su vista previa JPEG embebida.
- **Higiene digital.** Detecta archivos/carpetas vacíos, temporales, symlinks rotos, basura del sistema (`.DS_Store`, `Thumbs.db`), cachés de compilación y sidecars huérfanos, agrupados por nivel de riesgo. Una lista de seguridad nunca toca `.git`, `node_modules` activos, etc.
- **Selección de keeper.** Cuando un grupo tiene duplicados, ZeroDupe decide cuál conservar según calidad de contenido, metadatos EXIF, nombre y ruta — en lugar de quedarse a ciegas con el primero o el de nombre más corto.
- **Cuarentena reversible.** Los archivos se mueven a una cuarentena (rename atómico + journal SQLite), nunca se borran. Todo se puede restaurar.

## Compilar

Requiere una toolchain de Rust reciente (ver `rust-toolchain.toml`).

```bash
git clone https://github.com/zerodupe/zerodupe-engine
cd zerodupe-engine
cargo build --release
# binario en target/release/zerodupe
```

## Uso

```bash
# Flujo interactivo (recomendado): escanea, revisa grupos, elige qué poner en cuarentena
zerodupe interactive /ruta/a/escanear

# Avanzado: ejecuta el pipeline de duplicados exactos y emite JSON
zerodupe scan --candidates --partial-hash --full-hash --byte-compare /ruta/a/escanear

# Gestionar la cuarentena
zerodupe quarantine list
zerodupe quarantine restore-all
```

Ejecuta `zerodupe --help` para ver todos los subcomandos (incluye escaneos de imágenes similares e higiene).

## Dataset de benchmark reproducible

El crate `zerodupe_benchkit` genera un dataset sintético **determinista** con ground truth (duplicados exactos, recompresión/redimensionado JPEG, variantes geométricas, hermanos RAW+JPEG, archivos únicos y basura de higiene) para que cualquiera mida la precisión/recall de detección — contra ZeroDupe o cualquier otra herramienta:

```bash
cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /tmp/zd_bench
```

Ver `crates/zerodupe_benchkit/README.md` para el esquema del ground truth y las métricas.

## Licencia

MIT — ver [LICENSE](LICENSE).
