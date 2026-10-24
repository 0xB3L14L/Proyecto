"""
EMBER2024 - Predictor de implants Win64
Score + breakdown de features + metadata PE real
"""

import sys
import os
import csv
import argparse
import numpy as np
import lightgbm as lgb
import pefile

try:
    from thrember.features import PEFeatureExtractor
except ImportError:
    print("[!] thrember no instalado:")
    print("    pip install git+https://github.com/FutureComputing4AI/EMBER2024.git")
    sys.exit(1)

MODEL_PATH = "EMBER2024_Win64.model"

# Orden y tamaño de cada bloque en el vector de 2568 dims
FEATURE_DIMS = {
    "GeneralFileInfo":       7,
    "ByteHistogram":        256,
    "ByteEntropyHistogram": 256,
    "StringExtractor":      177,
    "HeaderFileInfo":        74,
    "SectionInfo":          174,
    "ImportsInfo":         1282,
    "ExportsInfo":          129,
    "DataDirectories":       34,
    "RichHeader":            33,
    "AuthenticodeSignature":  8,
    "PEFormatWarnings":     138,
}


# ─── Core ────────────────────────────────────────────────────────────────────

def load_model(model_path: str) -> lgb.Booster:
    return lgb.Booster(model_file=model_path)


def predict_pe(model: lgb.Booster, pe_bytes: bytes):
    extractor = PEFeatureExtractor()
    vec = np.array(extractor.feature_vector(pe_bytes), dtype=np.float32)
    score = float(model.predict([vec])[0])
    return score, vec


def score_label(score: float) -> str:
    if score >= 0.90: return "MALICIOUS    [!!!]"
    if score >= 0.70: return "SUSPICIOUS   [!!] "
    if score >= 0.50: return "BORDERLINE   [!]  "
    return "LIKELY BENIGN [ok]"


# ─── Feature breakdown ────────────────────────────────────────────────────────

def feature_breakdown(vec: np.ndarray):
    """
    Muestra el 'calor' relativo de cada grupo en el vector.
    Las barras están normalizadas al grupo con mayor media,
    así que el tamaño absoluto de los valores no importa.
    """
    # Calcular medias por grupo
    means, maxvals, nonzeros = {}, {}, {}
    offset = 0
    for name, dim in FEATURE_DIMS.items():
        if offset + dim > len(vec):
            break
        chunk = vec[offset:offset + dim]
        means[name]   = float(np.mean(np.abs(chunk)))
        maxvals[name] = float(np.max(np.abs(chunk)))
        nonzeros[name] = float(np.count_nonzero(chunk)) / dim * 100
        offset += dim

    global_max = max(means.values()) if means else 1.0

    print("\n  [Feature group breakdown]  (barras = peso relativo al grupo más activo)")
    print(f"  {'Group':<25} {'Mean':>10}  {'Nonzero%':>9}  Relative weight")
    print("  " + "-" * 70)

    for name, mean in means.items():
        bar_len = int((mean / global_max) * 30)
        bar = "█" * bar_len
        print(f"  {name:<25} {mean:>10.4f}  {nonzeros[name]:>8.1f}%  {bar}")


# ─── PE metadata via pefile ───────────────────────────────────────────────────

def pe_metadata(pe_bytes: bytes):
    try:
        pe = pefile.PE(data=pe_bytes)
    except Exception as e:
        print(f"\n  [!] pefile error: {e}")
        return

    # General
    print("\n  [General]")
    print(f"    size       : {len(pe_bytes):,} bytes")
    print(f"    machine    : {hex(pe.FILE_HEADER.Machine)}")
    print(f"    timestamp  : {pe.FILE_HEADER.TimeDateStamp}")
    print(f"    subsystem  : {pe.OPTIONAL_HEADER.Subsystem}")
    print(f"    dll_chars  : {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")
    print(f"    entry_point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")

    # Secciones
    print("\n  [Sections]")
    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00")
        entropy = s.get_entropy()
        flags = []
        if s.Characteristics & 0x20000000: flags.append("EXEC")
        if s.Characteristics & 0x80000000: flags.append("WRITE")
        if s.Characteristics & 0x40000000: flags.append("READ")
        print(f"    {name:<12} vsize={s.Misc_VirtualSize:<8} "
              f"raw={s.SizeOfRawData:<8} entropy={entropy:.3f}  [{' '.join(flags)}]")

    # Imports
    print("\n  [Imports]")
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        total_funcs = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace")
            funcs = []
            for imp in entry.imports:
                fn = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                funcs.append(fn)
            total_funcs += len(funcs)
            print(f"    {dll}  ({len(funcs)} funcs)")
            for fn in funcs:
                print(f"      - {fn}")
        print(f"    Total: {len(pe.DIRECTORY_ENTRY_IMPORT)} DLLs, {total_funcs} funcs importadas")
    else:
        print("    (sin imports en IAT)")

    # Exports
    print("\n  [Exports]")
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        syms = pe.DIRECTORY_ENTRY_EXPORT.symbols
        print(f"    {len(syms)} entries")
        for exp in syms[:12]:
            name = exp.name.decode(errors="replace") if exp.name else f"ordinal_{exp.ordinal}"
            print(f"      - {name}")
        if len(syms) > 12:
            print(f"      ... +{len(syms) - 12} más")
    else:
        print("    (sin exports)")

    # Firma
    print("\n  [Signature]")
    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
        print("    Signed: Si  (usar sigcheck para validar)")
    else:
        print("    Signed: No")

    pe.close()


# ─── CSV ─────────────────────────────────────────────────────────────────────

def write_csv(results: list, out_path: str):
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "score", "verdict"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[*] Guardado en {out_path}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="EMBER2024 Win64 predictor")
    parser.add_argument("target", nargs="?", help="PE file o directorio")
    parser.add_argument("-m", "--model",   default=MODEL_PATH)
    parser.add_argument("-d", "--dir",     action="store_true", help="Escanear directorio recursivo")
    parser.add_argument("-v", "--verbose", action="store_true", help="PE metadata + feature breakdown")
    parser.add_argument("-c", "--csv",     metavar="OUT.csv",   help="Guardar resultados en CSV")
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(0)

    if not os.path.exists(args.model):
        print(f"[!] Modelo no encontrado: {args.model}")
        sys.exit(1)

    model = load_model(args.model)

    targets = []
    if args.dir and os.path.isdir(args.target):
        for root, _, files in os.walk(args.target):
            for f in files:
                if f.lower().endswith((".exe", ".dll")):
                    targets.append(os.path.join(root, f))
    else:
        targets = [args.target]

    print(f"\n{'FILE':<45} {'SCORE':>8}  VERDICT")
    print("-" * 75)

    results = []
    for path in targets:
        try:
            with open(path, "rb") as f:
                data = f.read()

            if data[:2] != b"MZ":
                print(f"{'[skip] ' + os.path.basename(path):<45} {'---':>8}  No es PE")
                continue

            score, vec = predict_pe(model, data)
            label = score_label(score)
            print(f"{os.path.basename(path):<45} {score:>8.4f}  {label}")
            results.append({"file": os.path.basename(path),
                            "score": f"{score:.4f}",
                            "verdict": label.strip()})

            if args.verbose:
                feature_breakdown(vec)
                pe_metadata(data)
                print()

        except Exception as e:
            print(f"{os.path.basename(path):<45} {'ERROR':>8}  {e}")

    if args.csv:
        write_csv(results, args.csv)

    print()


if __name__ == "__main__":
    main()