import requests
import json
import time
import matplotlib.pyplot as plt
import urllib3
from datetime import datetime
import getpass

# Deshabilitar advertencias SSL (necesario para sandbox con certificado auto-firmado)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CiscoIOSXEMonitor:
    def __init__(self, host, username, password):
        self.base_url = f"https://{host}"
        self.auth = (username, password)
        self.headers = {
            'Accept': 'application/yang-data+json',
            'Content-Type': 'application/yang-data+json'
        }
        
        # Almacenamiento para métricas históricas
        self.traffic_history = {}
        self.alert_threshold = 0.5  # 50% de variación para alertas
        
    def get_interfaces_state(self):
        """Obtener el estado operativo de todas las interfaces"""
        url = f"{self.base_url}/restconf/data/ietf-interfaces:interfaces-state"
        
        try:
            response = requests.get(
                url, 
                auth=self.auth, 
                headers=self.headers, 
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error al obtener estado de interfaces: {e}")
            return None
    
    def get_interface_config(self, interface_name):
        """Obtener configuración específica de una interfaz"""
        url = f"{self.base_url}/restconf/data/ietf-interfaces:interfaces/interface={interface_name}"
        
        try:
            response = requests.get(
                url, 
                auth=self.auth, 
                headers=self.headers, 
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error al obtener configuración de {interface_name}: {e}")
            return None
    
    def configure_interface(self, interface_name, enabled):
        """Habilitar o deshabilitar una interfaz"""
        url = f"{self.base_url}/restconf/data/ietf-interfaces:interfaces/interface={interface_name}"
        
        payload = {
            "ietf-interfaces:interface": {
                "name": interface_name,
                "enabled": enabled
            }
        }
        
        try:
            response = requests.patch(
                url,
                json=payload,
                auth=self.auth,
                headers=self.headers,
                verify=False,
                timeout=10
            )
            
            if response.status_code in [200, 204]:
                print(f"Interfaz {interface_name} {'HABILITADA' if enabled else 'DESHABILITADA'} correctamente")
                return True
            else:
                print(f"Error al configurar interfaz: {response.status_code}")
                print(f"Respuesta: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")
            return False
    
    def get_admin_status(self, interface_name):
        """Obtener estado administrativo de una interfaz de forma segura"""
        config = self.get_interface_config(interface_name)
        
        if not config:
            return "unknown"
        
        # Manejar diferentes estructuras de respuesta
        if isinstance(config, dict):
            # Estructura esperada: {'ietf-interfaces:interface': {...}}
            interface_data = config.get('ietf-interfaces:interface', {})
            if isinstance(interface_data, dict):
                enabled = interface_data.get('enabled', True)
                return "up" if enabled else "down"
            elif isinstance(interface_data, list) and len(interface_data) > 0:
                # Si es una lista, tomar el primer elemento
                enabled = interface_data[0].get('enabled', True)
                return "up" if enabled else "down"
        
        elif isinstance(config, list) and len(config) > 0:
            # Si la respuesta es directamente una lista
            interface_data = config[0]
            if isinstance(interface_data, dict):
                enabled = interface_data.get('enabled', True)
                return "up" if enabled else "down"
        
        return "unknown"
    
    def safe_int_convert(self, value):
        """Convertir valor a entero de forma segura"""
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0
    
    def format_traffic_bytes(self, bytes_count):
        """Formatear bytes para mejor visualización"""
        # Convertir a entero de forma segura
        bytes_count = self.safe_int_convert(bytes_count)
        
        if bytes_count == 0:
            return "0 B"
        elif bytes_count < 1024:
            return f"{bytes_count} B"
        elif bytes_count < 1024 * 1024:
            return f"{bytes_count/1024:.1f} KB"
        else:
            return f"{bytes_count/(1024*1024):.1f} MB"
    
    def display_interfaces_status(self, interfaces_data):
        """Mostrar estado de interfaces en formato tabla"""
        if not interfaces_data:
            print("No se pudieron obtener datos de interfaces")
            return
        
        print("\n" + "="*95)
        print(f"{'ESTADO DE INTERFACES':^95}")
        print("="*95)
        print(f"{'Interfaz':<18} {'Admin':<8} {'Oper':<8} {'Tráfico Entrada':<18} {'Tráfico Salida':<18} {'Estado'}")
        print("-"*95)
        
        # Obtener la lista de interfaces
        interfaces_state = interfaces_data.get('ietf-interfaces:interfaces-state', {})
        interfaces = interfaces_state.get('interface', [])
        
        if not interfaces:
            print("No se encontraron interfaces")
            return
        
        for interface in interfaces:
            name = interface.get('name', 'N/A')
            oper_status = interface.get('oper-status', 'unknown')
            
            # Obtener estadísticas si están disponibles
            stats = interface.get('statistics', {})
            in_octets = stats.get('in-octets', 0)
            out_octets = stats.get('out-octets', 0)
            
            # Obtener estado administrativo de forma segura
            admin_status = self.get_admin_status(name)
            
            # Formatear tráfico (conversión segura a enteros)
            in_traffic = self.format_traffic_bytes(in_octets)
            out_traffic = self.format_traffic_bytes(out_octets)
            
            # Determinar estado general
            if admin_status == "up" and oper_status == "up":
                status = "ACTIVA"
            elif admin_status == "down" and oper_status == "down":
                status = "ADMIN-DOWN"
            elif admin_status == "up" and oper_status == "down":
                status = "CAIDA"
            else:
                status = "DESCONOCIDO"
            
            print(f"{name:<18} {admin_status:<8} {oper_status:<8} {in_traffic:<18} {out_traffic:<18} {status}")
            
            # Almacenar métricas para análisis (usando valores numéricos)
            in_octets_num = self.safe_int_convert(in_octets)
            out_octets_num = self.safe_int_convert(out_octets)
            self.store_traffic_metrics(name, in_octets_num, out_octets_num)
        
        print("="*95)
        print(f"Total de interfaces: {len(interfaces)}")
    
    def store_traffic_metrics(self, interface_name, in_octets, out_octets):
        """Almacenar métricas históricas de tráfico"""
        if interface_name not in self.traffic_history:
            self.traffic_history[interface_name] = {
                'in_octets': [],
                'out_octets': [],
                'timestamps': []
            }
        
        # Mantener solo las últimas 10 mediciones
        if len(self.traffic_history[interface_name]['in_octets']) >= 10:
            self.traffic_history[interface_name]['in_octets'].pop(0)
            self.traffic_history[interface_name]['out_octets'].pop(0)
            self.traffic_history[interface_name]['timestamps'].pop(0)
        
        self.traffic_history[interface_name]['in_octets'].append(in_octets)
        self.traffic_history[interface_name]['out_octets'].append(out_octets)
        self.traffic_history[interface_name]['timestamps'].append(datetime.now())
    
    def check_anomalies(self, interface_name, current_in_octets, current_out_octets):
        """Detectar anomalías en el tráfico"""
        history = self.traffic_history.get(interface_name, {})
        in_history = history.get('in_octets', [])
        out_history = history.get('out_octets', [])
        
        if len(in_history) < 3:  # Necesitamos al menos 3 mediciones para análisis
            return
        
        # Calcular promedio histórico (excluyendo el valor actual)
        avg_in = sum(in_history[:-1]) / len(in_history[:-1]) if len(in_history) > 1 else current_in_octets
        avg_out = sum(out_history[:-1]) / len(out_history[:-1]) if len(out_history) > 1 else current_out_octets
        
        # Verificar variaciones significativas
        if avg_in > 0:
            in_variation = abs(current_in_octets - avg_in) / avg_in
            if in_variation > self.alert_threshold:
                self.generate_alert(interface_name, f"Variacion anomala en trafico de entrada: {in_variation:.2%}")
        
        if avg_out > 0:
            out_variation = abs(current_out_octets - avg_out) / avg_out
            if out_variation > self.alert_threshold:
                self.generate_alert(interface_name, f"Variacion anomala en trafico de salida: {out_variation:.2%}")
    
    def generate_alert(self, interface_name, message):
        """Generar alerta del sistema"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"ALERTA [{timestamp}] Interfaz {interface_name}: {message}")
    
    def real_time_monitoring(self, interval=10):
        """Monitoreo en tiempo real"""
        print("Iniciando monitoreo en tiempo real...")
        print("Presiona Ctrl+C para detener el monitoreo")
        
        try:
            while True:
                interfaces_data = self.get_interfaces_state()
                if interfaces_data:
                    self.display_interfaces_status(interfaces_data)
                    
                    # Verificar anomalías para cada interfaz
                    interfaces_state = interfaces_data.get('ietf-interfaces:interfaces-state', {})
                    interfaces = interfaces_state.get('interface', [])
                    
                    for interface in interfaces:
                        name = interface.get('name')
                        stats = interface.get('statistics', {})
                        in_octets = self.safe_int_convert(stats.get('in-octets', 0))
                        out_octets = self.safe_int_convert(stats.get('out-octets', 0))
                        oper_status = interface.get('oper-status', 'unknown')
                        
                        # Verificar cambios de estado
                        if hasattr(self, 'previous_oper_status'):
                            if self.previous_oper_status.get(name) == 'up' and oper_status == 'down':
                                self.generate_alert(name, "Interfaz cambio de UP a DOWN")
                        
                        self.check_anomalies(name, in_octets, out_octets)
                    
                    # Actualizar estado anterior
                    self.previous_oper_status = {iface.get('name'): iface.get('oper-status') for iface in interfaces}
                else:
                    print("No se pudieron obtener datos del dispositivo")
                
                print(f"\nEsperando {interval} segundos para proxima actualizacion...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nMonitoreo detenido por el usuario")
    
    def test_connection(self):
        """Probar la conexión básica"""
        print("Probando conexion con el dispositivo...")
        data = self.get_interfaces_state()
        if data:
            print("Conexion exitosa!")
            return True
        else:
            print("Error en la conexion")
            return False

def main():
    # Configuración del sandbox
    HOST = "10.10.20.48"
    USERNAME = "developer"
    PASSWORD = "C1sco12345"
    
    print("SISTEMA DE MONITOREO Y CONTROL DE INTERFACES CISCO IOS XE")
    print("=" * 60)
    
    # Crear instancia del monitor
    monitor = CiscoIOSXEMonitor(HOST, USERNAME, PASSWORD)
    
    # Probar conexión primero
    if not monitor.test_connection():
        print("No se pudo establecer conexion. Verifique:")
        print("1. La IP del dispositivo")
        print("2. Las credenciales")
        print("3. La conectividad de red")
        return
    
    while True:
        print("\nMENU PRINCIPAL:")
        print("1. Mostrar estado actual de interfaces")
        print("2. Monitoreo en tiempo real")
        print("3. Controlar interfaz (Habilitar/Deshabilitar)")
        print("4. Probar conexion")
        print("5. Salir")
        
        choice = input("\nSeleccione una opcion (1-5): ").strip()
        
        if choice == "1":
            print("\nObteniendo estado de interfaces...")
            data = monitor.get_interfaces_state()
            monitor.display_interfaces_status(data)
            
        elif choice == "2":
            print("\nIniciando monitoreo continuo...")
            monitor.real_time_monitoring(interval=10)
            
        elif choice == "3":
            print("\nCONTROL DE INTERFACES")
            interface_name = input("Nombre de la interfaz (ej: GigabitEthernet2): ").strip()
            action = input("Accion (1=Habilitar, 2=Deshabilitar): ").strip()
            
            if action == "1":
                monitor.configure_interface(interface_name, True)
            elif action == "2":
                monitor.configure_interface(interface_name, False)
            else:
                print("Opcion invalida")
                
        elif choice == "4":
            monitor.test_connection()
                
        elif choice == "5":
            print("Terminando")
            break
            
        else:
            print("Opcion invalida. Intente nuevamente.")

if __name__ == "__main__":
    main()