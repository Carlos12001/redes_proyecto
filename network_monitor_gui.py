import os
import threading
import time
from datetime import datetime

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Importar la clase del monitor principal
from network_monitor import CiscoIOSXEMonitor


class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Monitoreo Cisco IOS XE - RESTCONF")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")

        # Variables de control
        self.monitor = None
        self.is_monitoring = False
        self.monitor_thread = None

        # Configuración por defecto (sandbox IOS XE on Cat8kv)
        self.host = tk.StringVar(value="10.10.20.48")
        self.username = tk.StringVar(value="developer")
        self.password = tk.StringVar(value="C1sco12345")

        # Variable de interfaz seleccionada
        self.interface_var = tk.StringVar()

        # Figura para gráficos
        self.fig = None
        self.ax = None
        self.graph_canvas = None

        self.setup_gui()

    # ==========================================================
    #   CONFIGURACIÓN GENERAL DE LA GUI
    # ==========================================================
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
        title_label = ttk.Label(
            main_frame,
            text="Sistema de Monitoreo y Control de Interfaces Cisco IOS XE",
            font=("Arial", 16, "bold"),
            foreground="#2c3e50",
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # ------------------------------------------------------
        # Frame de configuración
        # ------------------------------------------------------
        config_frame = ttk.LabelFrame(
            main_frame, text="Configuración del Dispositivo", padding="10"
        )
        config_frame.grid(
            row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )
        config_frame.columnconfigure(1, weight=1)

        ttk.Label(config_frame, text="Host:").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 5)
        )
        ttk.Entry(config_frame, textvariable=self.host, width=20).grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10)
        )

        ttk.Label(config_frame, text="Usuario:").grid(
            row=0, column=2, sticky=tk.W, padx=(0, 5)
        )
        ttk.Entry(config_frame, textvariable=self.username, width=15).grid(
            row=0, column=3, sticky=tk.W, padx=(0, 10)
        )

        ttk.Label(config_frame, text="Contraseña:").grid(
            row=0, column=4, sticky=tk.W, padx=(0, 5)
        )
        ttk.Entry(config_frame, textvariable=self.password, show="*", width=15).grid(
            row=0, column=5, sticky=tk.W, padx=(0, 10)
        )

        ttk.Button(
            config_frame, text="Conectar", command=self.connect_device
        ).grid(row=0, column=6, padx=(10, 0))

        # ------------------------------------------------------
        # Frame de controles
        # ------------------------------------------------------
        control_frame = ttk.LabelFrame(main_frame, text="Controles", padding="10")
        control_frame.grid(
            row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )

        ttk.Button(
            control_frame, text="Actualizar Estado", command=self.update_status
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            control_frame, text="Iniciar Monitoreo", command=self.start_monitoring
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            control_frame, text="Detener Monitoreo", command=self.stop_monitoring
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            control_frame, text="Limpiar Logs", command=self.clear_logs
        ).pack(side=tk.LEFT, padx=5)

        # ------------------------------------------------------
        # Frame de control de interfaz
        # ------------------------------------------------------
        interface_frame = ttk.LabelFrame(
            main_frame, text="Control de Interfaz", padding="10"
        )
        interface_frame.grid(
            row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )

        ttk.Label(interface_frame, text="Interfaz:").pack(side=tk.LEFT)
        self.interface_combo = ttk.Combobox(
            interface_frame,
            textvariable=self.interface_var,
            width=20,
            state="readonly",
        )
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        ttk.Button(
            interface_frame, text="Habilitar", command=lambda: self.control_interface(True)
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            interface_frame,
            text="Deshabilitar",
            command=lambda: self.control_interface(False),
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            interface_frame, text="Refrescar Lista", command=self.refresh_interface_list
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            interface_frame,
            text="Cambiar Descripción",
            command=self.change_description,
        ).pack(side=tk.LEFT, padx=5)

        # ------------------------------------------------------
        # Notebook (pestañas)
        # ------------------------------------------------------
        notebook = ttk.Notebook(main_frame)
        notebook.grid(
            row=4,
            column=0,
            columnspan=3,
            sticky=(tk.W, tk.E, tk.N, tk.S),
            pady=(0, 10),
        )

        # ---------------- Pestaña de interfaces ----------------
        interfaces_frame = ttk.Frame(notebook, padding="5")
        notebook.add(interfaces_frame, text="Interfaces")
        interfaces_frame.columnconfigure(0, weight=1)
        interfaces_frame.rowconfigure(0, weight=1)

        columns = (
            "interface",
            "admin_status",
            "oper_status",
            "in_traffic",
            "out_traffic",
            "status",
        )
        self.tree = ttk.Treeview(
            interfaces_frame, columns=columns, show="headings", height=15
        )

        self.tree.heading("interface", text="Interfaz")
        self.tree.heading("admin_status", text="Estado Admin")
        self.tree.heading("oper_status", text="Estado Oper")
        self.tree.heading("in_traffic", text="Tráfico Entrada")
        self.tree.heading("out_traffic", text="Tráfico Salida")
        self.tree.heading("status", text="Estado")

        self.tree.column("interface", width=150)
        self.tree.column("admin_status", width=100)
        self.tree.column("oper_status", width=100)
        self.tree.column("in_traffic", width=120)
        self.tree.column("out_traffic", width=120)
        self.tree.column("status", width=100)

        # Colores por estado
        self.tree.tag_configure("active", background="#d5f5e3")      # Verde claro
        self.tree.tag_configure("admin_down", background="#f2f3f4")  # Gris
        self.tree.tag_configure("down", background="#f5b7b1")        # Rojo suave
        self.tree.tag_configure("unknown", background="#fcf3cf")     # Amarillo claro

        tree_scrollbar = ttk.Scrollbar(
            interfaces_frame, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=tree_scrollbar.set)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # ---------------- Pestaña de logs ----------------
        logs_frame = ttk.Frame(notebook, padding="5")
        notebook.add(logs_frame, text="Logs y Alertas")
        logs_frame.columnconfigure(0, weight=1)
        logs_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            logs_frame, height=15, width=100, font=("Consolas", 10)
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # ---------------- Pestaña de gráficos ----------------
        graph_frame = ttk.Frame(notebook, padding="5")
        notebook.add(graph_frame, text="Gráficos de Tráfico")
        graph_frame.columnconfigure(0, weight=1)
        graph_frame.rowconfigure(0, weight=1)

        self.fig = Figure(figsize=(6, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("Tráfico de Entrada - seleccione una interfaz")
        self.ax.set_xlabel("Muestras")
        self.ax.set_ylabel("Bytes")

        self.graph_canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.graph_canvas.draw()
        self.graph_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # ------------------------------------------------------
        # Status bar
        # ------------------------------------------------------
        self.status_var = tk.StringVar(
            value="Desconectado - Configure el dispositivo y presione Conectar"
        )
        status_bar = ttk.Label(
            main_frame, textvariable=self.status_var, relief=tk.SUNKEN, padding="5"
        )
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E))

        # Binding doble clic en una fila de la tabla
        self.tree.bind("<Double-1>", self.on_interface_double_click)

    # ==========================================================
    #   LOGS
    # ==========================================================
    def save_log_to_file(self, message: str):
        """Guardar logs en archivo persistente."""
        try:
            if not os.path.exists("logs"):
                os.makedirs("logs")

            filename = f"logs/monitor_{datetime.now().strftime('%Y-%m-%d')}.log"
            with open(filename, "a", encoding="utf-8") as f:
                f.write(message + "\n")
        except Exception:
            # No romper la GUI si falla escritura de log
            pass

    def log_message(self, message: str, alert: bool = False):
        """Agregar mensaje al log (GUI + archivo)."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = "⚠️" if alert else "ℹ️"
        formatted_message = f"[{timestamp}] {prefix} {message}"

        self.log_text.insert(tk.END, formatted_message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

        self.save_log_to_file(formatted_message)

    # ==========================================================
    #   CONEXIÓN Y CONFIGURACIÓN DEL DISPOSITIVO
    # ==========================================================
    def connect_device(self):
        """Conectar al dispositivo."""
        if self.monitor and self.is_monitoring:
            messagebox.showwarning(
                "Advertencia", "Detenga el monitoreo antes de reconectar"
            )
            return

        try:
            self.monitor = CiscoIOSXEMonitor(
                self.host.get(), self.username.get(), self.password.get()
            )

            if self.monitor.test_connection():
                self.status_var.set(f"Conectado a {self.host.get()} - Listo")
                self.log_message(f"Conexión exitosa con {self.host.get()}")
                self.refresh_interface_list()
            else:
                self.status_var.set("Error de conexión")
                self.log_message(
                    "Error: No se pudo conectar al dispositivo", alert=True
                )
                messagebox.showerror(
                    "Error",
                    "No se pudo conectar al dispositivo. Verifique la configuración.",
                )

        except Exception as e:
            self.status_var.set("Error de conexión")
            self.log_message(f"Error de conexión: {e}", alert=True)
            messagebox.showerror("Error", f"Error de conexión: {e}")

    def refresh_interface_list(self):
        """Actualizar lista de interfaces."""
        if not self.monitor:
            messagebox.showwarning(
                "Advertencia", "Conecte al dispositivo primero"
            )
            return

        data = self.monitor.get_interfaces_state()
        if data:
            interfaces_state = data.get("ietf-interfaces:interfaces-state", {})
            interfaces = interfaces_state.get("interface", [])
            interface_names = [
                iface.get("name") for iface in interfaces if iface.get("name")
            ]
            self.interface_combo["values"] = interface_names
            if interface_names:
                self.interface_var.set(interface_names[0])
            self.log_message(
                f"Lista de interfaces actualizada: {len(interface_names)} interfaces encontradas"
            )
        else:
            self.log_message(
                "No se pudieron obtener interfaces (respuesta vacía)", alert=True
            )

    # ==========================================================
    #   ACTUALIZACIÓN DE ESTADO Y GRÁFICOS
    # ==========================================================
    def update_status(self):
        """Actualizar estado de interfaces."""
        if not self.monitor:
            messagebox.showwarning(
                "Advertencia", "Conecte al dispositivo primero"
            )
            return

        def update_thread():
            self.status_var.set("Actualizando estado de interfaces...")
            data = self.monitor.get_interfaces_state()

            if data:
                # Limpiar treeview
                for item in self.tree.get_children():
                    self.tree.delete(item)

                interfaces_state = data.get("ietf-interfaces:interfaces-state", {})
                interfaces = interfaces_state.get("interface", [])

                for interface in interfaces:
                    name = interface.get("name", "N/A")
                    oper_status = interface.get("oper-status", "unknown")

                    stats = interface.get("statistics", {})
                    in_octets = stats.get("in-octets", 0)
                    out_octets = stats.get("out-octets", 0)

                    try:
                        self.monitor.store_traffic_metrics(name, int(in_octets), int(out_octets))
                    except:
                        pass

                    admin_status = self.monitor.get_admin_status(name)

                    in_traffic = self.monitor.format_traffic_bytes(in_octets)
                    out_traffic = self.monitor.format_traffic_bytes(out_octets)

                    # Determinar estado lógico
                    if admin_status == "up" and oper_status == "up":
                        status = "ACTIVA"
                        tag = "active"
                    elif admin_status == "down" and oper_status == "down":
                        status = "ADMIN-DOWN"
                        tag = "admin_down"
                    elif admin_status == "up" and oper_status == "down":
                        status = "CAIDA"
                        tag = "down"
                    else:
                        status = "DESCONOCIDO"
                        tag = "unknown"

                    self.tree.insert(
                        "",
                        tk.END,
                        values=(
                            name,
                            admin_status,
                            oper_status,
                            in_traffic,
                            out_traffic,
                            status,
                        ),
                        tags=(tag,),
                    )

                self.status_var.set(
                    f"Estado actualizado - {len(interfaces)} interfaces"
                )
                self.log_message(
                    f"Estado actualizado - {len(interfaces)} interfaces"
                )

                # Actualizar gráfico para la interfaz seleccionada, si aplica
                selected_if = self.interface_var.get()
                if selected_if:
                    self.update_graph(selected_if)
            else:
                self.status_var.set("Error al obtener datos")
                self.log_message(
                    "Error al obtener datos del dispositivo", alert=True
                )

        thread = threading.Thread(target=update_thread, daemon=True)
        thread.start()

    def update_graph(self, interface_name: str):
        """Actualizar gráfico de tráfico de entrada para una interfaz."""
        if not self.monitor:
            return

        history = self.monitor.traffic_history.get(interface_name, {})
        in_data = history.get("in_octets", [])

        if len(in_data) < 2:
            # No hay suficientes muestras para graficar
            self.ax.clear()
            self.ax.set_title(
                f"Tráfico de Entrada - {interface_name} (insuficientes muestras)"
            )
            self.ax.set_xlabel("Muestras")
            self.ax.set_ylabel("Bytes")
            self.graph_canvas.draw()
            return

        self.ax.clear()
        self.ax.plot(in_data, marker="o")
        self.ax.set_title(f"Tráfico de Entrada - {interface_name}")
        self.ax.set_xlabel("Muestras")
        self.ax.set_ylabel("Bytes")
        self.ax.grid(True)
        self.graph_canvas.draw()

    # ==========================================================
    #   MONITOREO EN TIEMPO REAL
    # ==========================================================
    def start_monitoring(self):
        """Iniciar monitoreo en tiempo real."""
        if not self.monitor:
            messagebox.showwarning(
                "Advertencia", "Conecte al dispositivo primero"
            )
            return

        if self.is_monitoring:
            messagebox.showinfo(
                "Información", "El monitoreo ya está en ejecución"
            )
            return

        self.is_monitoring = True

        def monitor_thread():
            self.log_message("Monitoreo en tiempo real iniciado")
            self.status_var.set(
                "Monitoreo en tiempo real ACTIVO - Actualizando cada 10 segundos"
            )
            while self.is_monitoring:
                self.update_status()
                time.sleep(10)

        self.monitor_thread = threading.Thread(
            target=monitor_thread, daemon=True
        )
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Detener monitoreo en tiempo real."""
        self.is_monitoring = False
        self.status_var.set("Monitoreo detenido")
        self.log_message("Monitoreo en tiempo real detenido")

    # ==========================================================
    #   CONTROL DE INTERFACES (UP/DOWN + DESCRIPCIÓN)
    # ==========================================================
    def control_interface(self, enabled: bool):
        """Controlar interfaz (habilitar/deshabilitar)."""
        if not self.monitor:
            messagebox.showwarning(
                "Advertencia", "Conecte al dispositivo primero"
            )
            return

        interface_name = self.interface_var.get()
        if not interface_name:
            messagebox.showwarning(
                "Advertencia", "Seleccione una interfaz"
            )
            return

        def control_thread():
            action = "HABILITAR" if enabled else "DESHABILITAR"
            self.status_var.set(f"{action} interfaz {interface_name}...")

            success = self.monitor.configure_interface(interface_name, enabled)

            if success:
                self.status_var.set(
                    f"Interfaz {interface_name} {action.lower()}ada correctamente"
                )
                self.log_message(
                    f"Interfaz {interface_name} {action.lower()}ada correctamente"
                )
                self.update_status()
            else:
                self.status_var.set(
                    f"Error al {action.lower()} interfaz {interface_name}"
                )
                self.log_message(
                    f"Error al {action.lower()} interfaz {interface_name}",
                    alert=True,
                )

        thread = threading.Thread(target=control_thread, daemon=True)
        thread.start()

    def change_description(self):
        """Cambiar descripción de la interfaz seleccionada (PUT)."""
        if not self.monitor:
            messagebox.showwarning(
                "Advertencia", "Conecte al dispositivo primero"
            )
            return

        interface_name = self.interface_var.get()
        if not interface_name:
            messagebox.showwarning(
                "Advertencia", "Seleccione una interfaz"
            )
            return

        new_desc = simpledialog.askstring(
            "Descripción",
            f"Nueva descripción para {interface_name}:",
            parent=self.root,
        )

        if not new_desc:
            return

        def desc_thread():
            self.status_var.set(
                f"Cambiando descripción de {interface_name}..."
            )
            try:
                # Este método debe existir en CiscoIOSXEMonitor
                success = self.monitor.set_interface_description(
                    interface_name, new_desc
                )
            except AttributeError:
                self.log_message(
                    "Error: set_interface_description() no está implementado en network_monitor.py",
                    alert=True,
                )
                self.status_var.set(
                    "Error: método set_interface_description no disponible"
                )
                return

            if success:
                self.log_message(
                    f"Descripción de {interface_name} actualizada a: '{new_desc}'"
                )
                self.status_var.set(
                    f"Descripción de {interface_name} actualizada correctamente"
                )
                self.update_status()
            else:
                self.log_message(
                    f"Error al actualizar descripción de {interface_name}",
                    alert=True,
                )
                self.status_var.set(
                    f"Error al actualizar descripción de {interface_name}"
                )

        thread = threading.Thread(target=desc_thread, daemon=True)
        thread.start()

    # ==========================================================
    #   OTROS MÉTODOS AUXILIARES
    # ==========================================================
    def on_interface_double_click(self, event):
        """Manejar doble clic en una interfaz: seleccionarla y loguear."""
        selected = self.tree.selection()
        if not selected:
            return

        item = selected[0]
        values = self.tree.item(item, "values")
        if values:
            interface_name = values[0]
            self.interface_var.set(interface_name)
            self.log_message(f"Interfaz {interface_name} seleccionada")

    def clear_logs(self):
        """Limpiar los logs del panel (no borra el archivo)."""
        self.log_text.delete(1.0, tk.END)
        self.log_message("Logs limpiados")


def main():
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
