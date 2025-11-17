# NetFlow Monitor - Sistema de Monitoreo y Control Automatizado de Interfaces

## Descripción
Sistema inteligente de monitoreo y control automatizado de interfaces de red utilizando RESTCONF y Python. Conectado al sandbox de Cisco DevNet (router Cisco IOS XE), moderniza la supervisión del estado y tráfico de dispositivos de red mediante un enfoque programable y estandarizado con API RESTCONF y modelos YANG/JSON.

## Características
- **Monitoreo en tiempo real**: Visualización dinámica del estado de interfaces, tráfico y métricas
- **Control remoto de interfaces**: Activar/desactivar interfaces vía PATCH/PUT RESTCONF
- **Sistema de alertas automatizado**: Detecta anomalías y variaciones anómalas en el tráfico
- **Procesamiento JSON**: Extracción y análisis de datos estructurados
- **Gráficos interactivos**: Visualización actualizada en tiempo real

## Requisitos
- Python 3.8+
- Acceso al Cisco DevNet Sandbox (IOS XE con RESTCONF habilitado)

## Instalación
```bash
git clone <repository-url>
cd netflow-monitor
chmod +x ./install.sh
./install.sh
pip install -r requirements.txt
```

## Uso
```bash
 python3 network_monitor_gui.py
```


## Tecnologías
- Python (requests, matplotlib, json, time)
- RESTCONF API
- Modelo YANG: ietf-interfaces
- Formato de datos: JSON
