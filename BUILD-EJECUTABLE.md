# Cómo generar el ejecutable

El proyecto tiene un entrypoint end-to-end (`main.py`) que corre el pipeline completo en
un solo proceso, **sin root ni Npcap** (ideal para un ejecutable portable de demo):

    perfil -> escenario -> planta Modbus real -> tráfico legítimo de fondo -> ataques ->
    detección -> mitigación -> cadena de evidencia -> reporte (HTML + JSON).

La orquestación vive en `core/pipeline.py` y publica cada etapa como evento; el tablero
web (`dashboard/`) y la CLI consumen la misma simulación.

Los 5 ataques (scan, spoofing, replay, escritura ilegítima y flood) corren por defecto en
**modo portable** sobre sockets Modbus TCP reales contra el PLC local: no hace falta scapy,
root, Npcap ni ejecutar como Administrador. Las variantes con paquetes crudos (SYN scan,
IP spoofing y reinyección de frames con scapy) siguen disponibles en `redteam/` para
entornos con privilegios.

## Modo RAW opcional (`--raw`)

El flag `--raw` (CLI, o la casilla "Modo RAW" del tablero) ejecuta scan/spoofing/replay
con **scapy** (paquetes IP/TCP crudos) sobre la interfaz **loopback**, contra el PLC en
`127.0.0.1:15100`. Sigue siendo 100% local: no sale tráfico de la máquina.

Requiere privilegios de red cruda:
- **Linux:** root o `CAP_NET_RAW` (`sudo ./simulador-ics-scada --raw`, o
  `setcap cap_net_raw,cap_net_admin+eip`).
- **Windows:** Npcap instalado + ejecutar como Administrador.

Si se pide `--raw` sin privilegios, `core/pipeline.py` lo detecta con `hay_privilegios_raw()`
y **cae automáticamente a las variantes portables** (avisa por evento; no omite ataques).
El spoofing raw forja la IP origen e inyecta el paquete a ciegas (las respuestas irían a la
IP falsa): demuestra el spoofing de red real, no una sesión Modbus bidireccional.

## Correrlo sin empaquetar

```bash
python main.py                                   # tablero web en http://127.0.0.1:8501
python main.py --puerto 8080 --no-navegador      # tablero en otro puerto, sin abrir Chrome
python main.py --cli                             # consola: municipal, dificultad normal
python main.py --cli --perfil nacional --dificultad dificil --salida ./reporte_nac
```

Genera `reporte/reporte_incidente.html` (+ `.pdf` si weasyprint está instalado) y
`reporte/cadena_evidencia.json`. En el ejecutable, `reporte/` se crea al lado del
binario, no en el directorio de trabajo.

## Generar el binario (PyInstaller)

Ya está incluido `simulador-ics-scada.spec` (multiplataforma). PyInstaller **no**
cross-compila: produce un binario para el SO donde corre.

```bash
pip install pyinstaller
pyinstaller simulador-ics-scada.spec
```

- En Windows queda `dist\simulador-ics-scada.exe`
- En Linux queda `dist/simulador-ics-scada`

El binario es autocontenido: embebe `config/`, la plantilla del reporte y el HTML del
tablero, así que corre en una máquina sin Python ni el código fuente.

Doble clic abre el tablero en el navegador. Por consola:

```cmd
simulador-ics-scada.exe --cli --perfil nacional --dificultad dificil
```

## Rebuild del `.exe` desde Linux (Wine)

El `.exe` entregado se construyó en Ubuntu con Wine + Python 3.10 para Windows. Para
reproducirlo:

```bash
sudo dpkg --add-architecture i386 && sudo apt-get update
sudo apt-get install -y wine64 wine32

export WINEPREFIX=$HOME/.wine-build
wineboot --init

# Python 3.10 embeddable (el instalador .exe oficial falla bajo Wine)
curl -LO https://www.python.org/ftp/python/3.10.11/python-3.10.11-embed-amd64.zip
unzip python-3.10.11-embed-amd64.zip -d "$WINEPREFIX/drive_c/Py310"
cd "$WINEPREFIX/drive_c/Py310"
mkdir -p Lib DLLs Lib/site-packages && unzip -o python310.zip -d Lib && mv python310.zip python310.zip.bak
cp *.pyd DLLs/
printf 'Lib\n.\nDLLs\n\nimport site\n' > python310._pth   # habilita site-packages/pip

curl -LO https://bootstrap.pypa.io/pip/get-pip.py
wine 'C:\Py310\python.exe' get-pip.py
wine 'C:\Py310\python.exe' -m pip install pymodbus==3.6.9 scapy==2.6.1 \
    pydantic==2.10.4 pyyaml==6.0.2 jinja2==3.1.6 pyinstaller==6.11.1

cd /ruta/al/proyecto
wine 'C:\Py310\python.exe' -m PyInstaller --clean \
    --distpath dist_win --workpath build_win simulador-ics-scada.spec
```

Queda `dist_win/simulador-ics-scada.exe` (PE32+ consola, x86-64, ~14 MB).
Para probarlo: `wine dist_win/simulador-ics-scada.exe --puerto 8700 --no-navegador` y abrir
esa URL, o `--cli --perfil nacional --dificultad dificil | cat`.

> Bajo Wine, redirigir la salida a un archivo (`> out.txt`) rompe la consola del bootloader
> de PyInstaller; con pipe (`| cat`) o consola directa funciona. En Windows real no pasa.
> `fastapi`/`uvicorn`/`streamlit` no se instalan para este build: `main.py` no los usa.
