# zerodupe_benchkit — generador de dataset con ground truth

Genera un dataset sintético **determinista** para el benchmark comparativo de
ZeroDupe contra `fdupes`, `jdupes`, `rmlint` y `czkawka`. La misma semilla y
escala reproducen el dataset byte-a-byte, así que cualquiera puede replicar la
medición.

## Uso

```bash
# Dataset base
cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /ruta/zd_bench

# Más grande (para estrés de I/O), otra semilla
cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /ruta/zd_bench --scale 8 --seed 7

# Con RAW reales (corpus CC0 de raw.pixls.us) para ejercitar el decode RAW real
cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /ruta/zd_bench --raw-samples /ruta/raws
```

Escribe el árbol de archivos bajo `--out` y un `ground_truth.json` con la
verdad de terreno exacta.

## Qué se planta (todo etiquetado en el ground truth)

| Categoría | Carpeta | Qué prueba |
|---|---|---|
| Duplicados exactos | `exact/` | Copias byte-idénticas en carpetas/nombres distintos (imagen, binario, texto; uno grande de 4 MB cada 6 para I/O) |
| Similares por recompresión | `similar_recompress/` | JPEG q35/q75, resize 50%, cambio a PNG |
| **Variantes geométricas** | `similar_geometric/` | Espejo H/V, rotación 90/180/270°, recorte 80% — **la prueba clave** (la mayoría de hashes perceptuales NO son invariantes a rotación/espejo) |
| Hermanos RAW+JPEG | `siblings/` | Pares que NO deben agruparse (mismo `basename`, extensiones `.jpg`/`.dng`) |
| Archivos únicos | `unique/` | Control de falsos positivos |
| Basura de higiene | `hygiene/` | Vacíos, temporales (.tmp/.bak/.swp/.crdownload), symlink roto, `.DS_Store`/`Thumbs.db`/`desktop.ini`, `__pycache__` |

## Esquema de `ground_truth.json`

- `exact_duplicate_groups[]` — `{ id, kind, files[] }`: un detector acierta si
  agrupa **exactamente** esos archivos.
- `similar_clusters[]` — `{ id, kind: "recompress"|"geometric", base, variants[]:{path,transform} }`:
  cada variante debe agruparse con su `base`. Filtra por `kind == "geometric"`
  para medir el recall de espejo/rotación/recorte por separado.
- `should_not_group[]` — `{ files[], reason, real_raw }`: agrupar estos pares es
  un error (falso positivo de hermanos).
- `unique_files[]` — agrupar cualquiera es un falso positivo.
- `hygiene{}` — basura por categoría.
- `counts{}` — totales (incluye `geometric_variants`).

## Métricas a calcular contra cada herramienta

1. **Similares** — precisión / recall / F1 por cluster; y recall específico de
   variantes **geométricas** (espejo/rotación/recorte).
2. **Exactos** — tiempo, throughput, RAM (úsese `hyperfine` + `/usr/bin/time -v`).
3. **Falsos positivos** — pares de `should_not_group` agrupados + `unique_files`
   agrupados.

Para una comparación justa, ejecutar czkawka con `-H` (caché apagada) en frío.

## Notas

- Sin RAW reales (`--raw-samples`), los hermanos usan un `.dng` placeholder y se
  marca `real_raw: false` en el ground truth (el decode RAW real no se ejercita).
- El symlink roto solo se genera en Unix.
