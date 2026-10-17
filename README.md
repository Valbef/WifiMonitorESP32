# WifiMonitorESP32
Herramienta para usar ESP32 WROOM-32 como monitor wifi y verlo en WireShark.

((Funciona en Windows y Linix pero por ahora da errores en la informacion,
proximamente los resolveré en las siguientes actualizaciones.))


Carga el Firmware en el esp32 con Arduino id:

1. Abre Arduino id

2. Selecciona la placa (habitualmente "ALKS esp32")

3. Copia el contenido de Firmwareextcap.txt

4. Cargalo en el esp32 .

====================

Windows

====================

Instalar dependencias:

 Abre powershell:

py -m pip install pyserial

    En Wireshark, abre Ayuda → Acerca de Wireshark → Carpetas 
    y localiza la carpeta Personal Extcap o Global Extcap.

    Copia esp32_extcap.py en esa carpeta.

    Crea allí un archivo esp32_sniffer.bat con este contenido, ajustando la ruta si es necesario:

bat

@echo off
py "C:\ruta\extcap\esp32_extcap.py" %*

4. Reinicia Wireshark.


=======================

Linux

======================
Localiza la carpeta extcap en Wireshark. Una ubicación habitual es:
bash

~/.local/lib/wireshark/extcap/

Instala el script:
bash

mkdir -p ~/.local/lib/wireshark/extcap
cp esp32_extcap.py ~/.local/lib/wireshark/extcap/
chmod +x ~/.local/lib/wireshark/extcap/esp32_extcap.py

Comprueba que Python está disponible en la ruta indicada por el shebang (#!/usr/bin/env python3). Si tu distribución utiliza otra carpeta extcap, usa la que indique Wireshark.

En Linux también puede ser necesario conceder acceso al puerto serie:
bash

sudo usermod -aG dialout "$USER"

Cierra la sesión y vuelve a entrar para que se aplique el cambio. 
El nombre del grupo puede variar según la distribución.

3. Seleccionar la interfaz

Reinicia Wireshark. En la lista de interfaces de captura debería aparecer ESP32 Wi-Fi Monitor. Configura el puerto correcto (COM5, /dev/ttyUSB0, etc.) y la velocidad 921600.

Selecciona Marcador A5 5A 
