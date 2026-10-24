# Deceiver Ops

Proyecto de investigación para evaluar capacidades de detección de EDR/SIEM frente a una cadena ofensiva multi-etapa.  
Desarrollado como proyecto de título de Ingeniería en Ciberseguridad — AIEP.

---

## Cadena de ataque

```
version.dll (DLL Proxy)
  └─ cargada por el proceso objetivo (ej. Slack via DLL search order hijack)
  └─ se activa en la llamada a GetFileVersionInfoSizeW
       │
       ▼
Threadless Injection → hook sobre NtOpenFile en notepad.exe
  └─ trampoline CALL rel32 instalado sobre los primeros 5 bytes de NtOpenFile
  └─ hook shellcode guarda registros, llama el payload, restaura, salta al original
  └─ cualquier apertura de archivo en el proceso objetivo activa la ejecución
       │
       ▼
Shellcode Crystal Palace (loader Module Stomp)
  └─ generado por CPL — binario plano, position-independent
  └─ mapea chakra.dll vía NtCreateSection (SEC_IMAGE) + NtMapViewOfSection
  └─ localiza el EntryPoint en .text
  └─ NtProtectVirtualMemory → sobreescribe EntryPoint con Caro-Kann
  └─ NtCreateThreadEx → ejecuta desde la memoria del DLL sobreescrito
       │
       ▼
Caro-Kann (stub en memoria dentro de chakra.dll)
  └─ Sleep(5000) — delay para evadir escaneos de memoria disparados por el kernel
  └─ VirtualProtect → descifra payload XOR in-place
  └─ VirtualProtect → restaura protección original
  └─ jmp payload
       │
       ▼
Payload (shellcode arbitrario)
```

---

## Componentes

### 1. DLL Proxying + Threadless Injection

`version.dll` actúa como proxy de todos los exports del `version.dll` legítimo (`C:\Windows\System32\version.dll`), redirigiendo las llamadas de forma transparente. El export `GetFileVersionInfoSizeW` es secuestrado para lanzar el hilo de inyección.

**Flujo de inyección:**
1. Resuelve `NtOpenFile` en `ntdll.dll` ya cargado en memoria.
2. Busca un hueco de memoria dentro de ±`0x70000000` de `NtOpenFile` con `NtAllocateVirtualMemory` — necesario para mantenerse dentro del alcance de `CALL rel32`.
3. Escribe el hook shellcode + payload (descifrado RC4) en ese hueco.
4. Parchea los primeros 5 bytes de `NtOpenFile` con un trampoline `CALL rel32` apuntando al hook.
5. El hook shellcode guarda los registros volátiles, llama el payload, restaura el estado y salta a los bytes originales de `NtOpenFile` — la syscall continúa con normalidad.

Cualquier proceso que llame a `NtOpenFile` (ej. Notepad al abrir un archivo) dispara el payload.

**Activación manual:**
```
rundll32 version.dll,GetFileVersionInfoSizeW
```

**Cifrado del payload:** RC4 — clave y ciphertext embebidos en `shellcode.h`.

**Proceso objetivo:** `notepad.exe` (hardcodeado en `InjectionThread`; modificar el argumento de `GetTargetPid` para apuntar a otro proceso).

---

### 2. Module Stomp + Caro-Kann

Cadena de dos etapas en binario PIC (Crystal Palace) que oculta la ejecución dentro de un DLL legítimo cargado en memoria.

#### Loader Module Stomp (`module-stomp.c`)

Compilado como BOF de CPL (`.spec` → binario plano PIC). Se embebe como payload del shellcode de inyección threadless.

1. Abre `chakra.dll` desde disco con `CreateFileW`.
2. Crea una sección `SEC_IMAGE` via `NtCreateSection` y mapea una vista privada con `NtMapViewOfSection`.
3. Parsea los headers PE para localizar `AddressOfEntryPoint` dentro de `.text`.
4. Verifica que haya espacio suficiente en `.text` desde el EntryPoint para alojar el binario Caro-Kann.
5. `NtProtectVirtualMemory(PAGE_READWRITE)` → copia Caro-Kann sobre el EntryPoint → restaura la protección original.
6. `NtCreateThreadEx` desde el EntryPoint de la vista mapeada.

> `NtProtectVirtualMemory` page-alinea `*BaseAddress` in-place — se usa un `PVOID pBase` separado para no corromper `uEntryPoint` antes del copiado.

#### Caro-Kann (`carokann.c`)

Stub PIC mínimo que corre dentro del `.text` mapeado de chakra.dll.

1. `Sleep(5000)` — retrasa la ejecución para evadir escaneos de memoria por timing.
2. Lee el payload XOR-cifrado y la máscara desde su propio binario (via section blobs de CPL).
3. `VirtualProtect(PAGE_EXECUTE_READWRITE)` → descifra el payload in-place → restaura la protección original.
4. Transfiere la ejecución al payload descifrado.

**Nota de build CPL:** las funciones auxiliares no deben declararse `static`. CPL resuelve `CALL rel32` únicamente a símbolos GLOBAL en el COFF — funciones `static` producen binding LOCAL y generan el error `Can't transform CALL rel32 / No symbol at 0x00000000`.

---

### 3. Predictor EMBER2024 (`ember_predict.py`)

Herramienta Python standalone para puntuar archivos PE Win64 contra el modelo LightGBM de EMBER2024. Usada para medir qué tan detectable es cada etapa de la cadena desde una perspectiva de ML estático.

**Instalación:**
```
pip install lightgbm pefile
pip install git+https://github.com/FutureComputing4AI/EMBER2024.git
```

**Uso:**
```bash
# Puntuar un archivo individual
python ember_predict.py implant.dll

# Escanear un directorio recursivamente
python ember_predict.py -d ./build/

# Verbose: metadata PE + desglose de grupos de features
python ember_predict.py -v implant.dll

# Exportar resultados a CSV
python ember_predict.py -d ./build/ -c resultados.csv
```

**Ejemplo de salida:**
```
FILE                                          SCORE  VERDICT
---------------------------------------------------------------------------
carokann.bin                                 0.1243  LIKELY BENIGN [ok]
module-stomp.bin                             0.3871  BORDERLINE    [!]
version.dll                                  0.8912  MALICIOUS     [!!!]
```

Umbrales: ≥ 0.90 → MALICIOUS, ≥ 0.70 → SUSPICIOUS, ≥ 0.50 → BORDERLINE, < 0.50 → LIKELY BENIGN.

---

## Estructura del repositorio

```
├── DLL Proxying + Threadless Injection/
│   ├── dllmain.c       # Proxy DLL + lógica de inyección threadless
│   ├── header.h        # Typedefs de NT API
│   └── shellcode.h     # Payload CPL cifrado con RC4 + clave
│
├── Module Stomp + Caro Kann/
│   ├── module-stomp.c  # Loader CPL: NtCreateSection → stomp EntryPoint con Caro-Kann
│   ├── carokann.c      # Stub CPL: sleep → XOR decrypt in-place → ejecutar payload
│   ├── payload.c       # Stub de payload (POC MessageBoxW)
│   ├── loader.spec     # Spec CPL: ensambla loader + resolve + libtcg + carokann.bin
│   ├── carokann.spec   # Spec CPL: ensambla carokann + payload XOR-cifrado + máscara 128-bit
│   └── payload.spec    # Spec CPL: compila payload como PIC y lo expone para carokann.spec
│
└── Ember2024/
    ├── ember_predict.py        # Scorer ML estático EMBER2024
    └── EMBER2024_Win64.model   # Modelo LightGBM (binario)
```

---

## Referencias

- [Threadless Process Injection](https://github.com/CCob/ThreadlessInject)
- [Avantguard – Threadless Ops](https://avantguard.io/en/blog/threadless-ops)
- [Avantguard – Threadless Ops II](https://avantguard.io/en/blog/threadless-ops-ii-enhanced-evasion)
- [Crystal Palace (CPL)](https://github.com/Cracked5pider/CrystalPalace)
- [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024)
