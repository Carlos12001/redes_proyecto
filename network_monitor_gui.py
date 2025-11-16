import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime

# Importar la clase del monitor principal
from network_monitor import CiscoIOSXEMonitor

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Monitoreo Cisco IOS XE - RESTCONF")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        
        # Variables de control
        self.monitor = None
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Configuración por defecto
        self.host = tk.StringVar(value="10.10.20.48")
        self.username = tk.StringVar(value="developer")
        self.password = tk.StringVar(value="C1sco12345")

        self.setup_gui()
        
    def setup_gui(self):
        """Configurar la interfaz gráfica"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar grid weights para responsive
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Título
        title_label = ttk.Label(main_frame, 
                               text="Sistema de Monitoreo y Control de Interfaces Cisco IOS XE",
                               font=('Arial', 16, 'bold'),
                               foreground='#2c3e50')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Frame de configuración
        config_frame = ttk.LabelFrame(main_frame, text="Configuración del Dispositivo", padding="10")
        config_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        
        ttk.Label(config_frame, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        ttk.Entry(config_frame, textvariable=self.host, width=20).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(config_frame, text="Usuario:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        ttk.Entry(config_frame, textvariable=self.username, width=15).grid(row=0, column=3, sticky=tk.W, padx=(0, 10))
        
        ttk.Label(config_frame, text="Contraseña:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        ttk.Entry(config_frame, textvariable=self.password, show="*", width=15).grid(row=0, column=5, sticky=tk.W, padx=(0, 10))
        
        ttk.Button(config_frame, text="Conectar", command=self.connect_device).grid(row=0, column=6, padx=(10, 0))
        
        # Frame de controles
        control_frame = ttk.LabelFrame(main_frame, text="Controles", padding="10")
        control_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(control_frame, text="Actualizar Estado", 
                  command=self.update_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Iniciar Monitoreo", 
                  command=self.start_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Detener Monitoreo", 
                  command=self.stop_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Limpiar Logs", 
                  command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        
        # Frame de control de interfaz
        interface_frame = ttk.LabelFrame(main_frame, text="Control de Interfaz", padding="10")
        interface_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(interface_frame, text="Interfaz:").pack(side=tk.LEFT)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var, width=20, state="readonly")
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(interface_frame, text="Habilitar", 
                  command=lambda: self.control_interface(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(interface_frame, text="Deshabilitar", 
                  command=lambda: self.control_interface(False)).pack(side=tk.LEFT, padx=5)
        ttk.Button(interface_frame, text="Refrescar Lista", 
                  command=self.refresh_interface_list).pack(side=tk.LEFT, padx=5)
        
        # Frame de estado con notebook (pestañas)
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Pestaña de interfaces
        interfaces_frame = ttk.Frame(notebook, padding="5")
        notebook.add(interfaces_frame, text="Interfaces")
        interfaces_frame.columnconfigure(0, weight=1)
        interfaces_frame.rowconfigure(0, weight=1)
        
        # Treeview para interfaces
        columns = ('interface', 'admin_status', 'oper_status', 'in_traffic', 'out_traffic', 'status')
        self.tree = ttk.Treeview(interfaces_frame, columns=columns, show='headings', height=15)
        
        # Configurar columnas
        self.tree.heading('interface', text='Interfaz')
        self.tree.heading('admin_status', text='Estado Admin')
        self.tree.heading('oper_status', text='Estado Oper')
        self.tree.heading('in_traffic', text='Tráfico Entrada')
        self.tree.heading('out_traffic', text='Tráfico Salida')
        self.tree.heading('status', text='Estado')
        
        self.tree.column('interface', width=150)
        self.tree.column('admin_status', width=100)
        self.tree.column('oper_status', width=100)
        self.tree.column('in_traffic', width=120)
        self.tree.column('out_traffic', width=120)
        self.tree.column('status', width=100)
        
        # Scrollbar para treeview
        tree_scrollbar = ttk.Scrollbar(interfaces_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Pestaña de logs
        logs_frame = ttk.Frame(notebook, padding="5")
        notebook.add(logs_frame, text="Logs y Alertas")
        logs_frame.columnconfigure(0, weight=1)
        logs_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(logs_frame, height=15, width=100, font=('Consolas', 10))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Desconectado - Configure el dispositivo y presione Conectar")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, padding="5")
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        # Configurar bindings
        self.tree.bind('<Double-1>', self.on_interface_double_click)
        
    def log_message(self, message, alert=False):
        """Agregar mensaje al log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if alert:
            formatted_message = f"[{timestamp}] ⚠️  {message}\n"
        else:
            formatted_message = f"[{timestamp}] ℹ️  {message}\n"
        
        self.log_text.insert(tk.END, formatted_message)
        self.log_text.see(tk.END)
        self.root.update()
    
    def connect_device(self):
        """Conectar al dispositivo"""
        if self.monitor and self.is_monitoring:
            messagebox.showwarning("Advertencia", "Detenga el monitoreo antes de reconectar")
            return
        
        try:
            self.monitor = CiscoIOSXEMonitor(
                self.host.get(),
                self.username.get(),
                self.password.get()
            )
            
            # Probar conexión
            if self.monitor.test_connection():
                self.status_var.set(f"Conectado a {self.host.get()} - Listo")
                self.log_message(f"Conexión exitosa con {self.host.get()}")
                self.refresh_interface_list()
            else:
                self.status_var.set("Error de conexión")
                self.log_message("Error: No se pudo conectar al dispositivo", alert=True)
                messagebox.showerror("Error", "No se pudo conectar al dispositivo. Verifique la configuración.")
                
        except Exception as e:
            self.status_var.set("Error de conexión")
            self.log_message(f"Error de conexión: {e}", alert=True)
            messagebox.showerror("Error", f"Error de conexión: {e}")
    
    def refresh_interface_list(self):
        """Actualizar lista de interfaces"""
        if not self.monitor:
            messagebox.showwarning("Advertencia", "Conecte al dispositivo primero")
            return
        
        data = self.monitor.get_interfaces_state()
        if data:
            interfaces_state = data.get('ietf-interfaces:interfaces-state', {})
            interfaces = interfaces_state.get('interface', [])
            interface_names = [iface.get('name') for iface in interfaces if iface.get('name')]
            self.interface_combo['values'] = interface_names
            if interface_names:
                self.interface_var.set(interface_names[0])
            self.log_message(f"Lista de interfaces actualizada: {len(interface_names)} interfaces encontradas")
    
    def update_status(self):
        """Actualizar estado de interfaces"""
        if not self.monitor:
            messagebox.showwarning("Advertencia", "Conecte al dispositivo primero")
            return
        
        def update_thread():
            self.status_var.set("Actualizando estado de interfaces...")
            data = self.monitor.get_interfaces_state()
            
            if data:
                # Limpiar treeview
                for item in self.tree.get_children():
                    self.tree.delete(item)
                
                interfaces_state = data.get('ietf-interfaces:interfaces-state', {})
                interfaces = interfaces_state.get('interface', [])
                
                for interface in interfaces:
                    name = interface.get('name', 'N/A')
                    oper_status = interface.get('oper-status', 'unknown')
                    
                    stats = interface.get('statistics', {})
                    in_octets = stats.get('in-octets', 0)
                    out_octets = stats.get('out-octets', 0)
                    
                    admin_status = self.monitor.get_admin_status(name)
                    
                    # Formatear tráfico
                    in_traffic = self.monitor.format_traffic_bytes(in_octets)
                    out_traffic = self.monitor.format_traffic_bytes(out_octets)
                    
                    # Determinar estado
                    if admin_status == "up" and oper_status == "up":
                        status = "ACTIVA"
                    elif admin_status == "down" and oper_status == "down":
                        status = "ADMIN-DOWN"
                    elif admin_status == "up" and oper_status == "down":
                        status = "CAIDA"
                    else:
                        status = "DESCONOCIDO"
                    
                    # Insertar en treeview
                    self.tree.insert('', tk.END, values=(
                        name, admin_status, oper_status, in_traffic, out_traffic, status
                    ))
                
                self.status_var.set(f"Estado actualizado - {len(interfaces)} interfaces")
                self.log_message(f"Estado actualizado - {len(interfaces)} interfaces")
            else:
                self.status_var.set("Error al obtener datos")
                self.log_message("Error al obtener datos del dispositivo", alert=True)
        
        # Ejecutar en hilo separado para no bloquear la GUI
        thread = threading.Thread(target=update_thread)
        thread.daemon = True
        thread.start()
    
    def start_monitoring(self):
        """Iniciar monitoreo en tiempo real"""
        if not self.monitor:
            messagebox.showwarning("Advertencia", "Conecte al dispositivo primero")
            return
        
        if self.is_monitoring:
            messagebox.showinfo("Información", "El monitoreo ya está en ejecución")
            return
        
        self.is_monitoring = True
        
        def monitor_thread():
            while self.is_monitoring:
                self.update_status()
                time.sleep(10)  # Actualizar cada 10 segundos
        
        self.monitor_thread = threading.Thread(target=monitor_thread)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.status_var.set("Monitoreo en tiempo real ACTIVO - Actualizando cada 10 segundos")
        self.log_message("Monitoreo en tiempo real iniciado")
    
    def stop_monitoring(self):
        """Detener monitoreo en tiempo real"""
        self.is_monitoring = False
        self.status_var.set("Monitoreo detenido")
        self.log_message("Monitoreo en tiempo real detenido")
    
    def control_interface(self, enabled):
        """Controlar interfaz (habilitar/deshabilitar)"""
        if not self.monitor:
            messagebox.showwarning("Advertencia", "Conecte al dispositivo primero")
            return
        
        interface_name = self.interface_var.get()
        if not interface_name:
            messagebox.showwarning("Advertencia", "Seleccione una interfaz")
            return
        
        def control_thread():
            action = "HABILITAR" if enabled else "DESHABILITAR"
            self.status_var.set(f"{action} interfaz {interface_name}...")
            
            success = self.monitor.configure_interface(interface_name, enabled)
            
            if success:
                self.status_var.set(f"Interfaz {interface_name} {action.lower()}ada correctamente")
                self.log_message(f"Interfaz {interface_name} {action.lower()}ada correctamente")
                # Actualizar estado después de modificar
                self.update_status()
            else:
                self.status_var.set(f"Error al {action.lower()} interfaz {interface_name}")
                self.log_message(f"Error al {action.lower()} interfaz {interface_name}", alert=True)
        
        thread = threading.Thread(target=control_thread)
        thread.daemon = True
        thread.start()
    
    def on_interface_double_click(self, event):
        """Manejar doble click en interfaz"""
        item = self.tree.selection()[0]
        values = self.tree.item(item, 'values')
        if values:
            interface_name = values[0]
            self.interface_var.set(interface_name)
            self.log_message(f"Interfaz {interface_name} seleccionada")
    
    def clear_logs(self):
        """Limpiar los logs"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("Logs limpiados")

def main():
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()