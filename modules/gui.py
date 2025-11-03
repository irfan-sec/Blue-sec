"""
Blue-sec GUI Module
Graphical User Interface for the Blue-sec framework
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
from loguru import logger

from modules.config import BlueSecConfig, load_config
from modules.scanner import DeviceScanner, BluetoothDevice, scan_bluetooth_devices
from modules.vulnerabilities import CVEDatabase, VulnerabilityScanner
from modules.attacks import AttackManager
from modules.hid_attacks import HIDPayload, HIDKeyboardInjector, PayloadGenerator
from modules.reporting import ReportGenerator
from modules.utils import validate_mac_address, console


class BlueSecGUI:
    """Main GUI application for Blue-sec"""
    
    def __init__(self, root: tk.Tk, config: Optional[BlueSecConfig] = None):
        self.root = root
        self.root.title("Blue-sec - Bluetooth Security Testing Framework")
        self.root.geometry("1200x800")
        
        # Configuration
        self.config = config or BlueSecConfig()
        
        # State
        self.discovered_devices: List[BluetoothDevice] = []
        self.selected_device: Optional[BluetoothDevice] = None
        self.scanning = False
        self.loop = None
        
        # Initialize components
        self.scanner = DeviceScanner(self.config.scanner)
        self.cve_db = CVEDatabase()
        self.vuln_scanner = VulnerabilityScanner(self.cve_db)
        self.attack_manager = AttackManager(self.config.attack, self.config.security)
        self.report_gen = ReportGenerator(self.config.reporting.output_directory)
        
        # Setup GUI
        self.setup_ui()
        
        # Start async loop in background thread
        self.setup_async_loop()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Menu bar
        self.setup_menu()
        
        # Main container with notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.setup_scanner_tab()
        self.setup_vuln_scan_tab()
        self.setup_hid_attack_tab()
        self.setup_attack_tab()
        self.setup_logs_tab()
        
        # Status bar
        self.setup_status_bar()
    
    def setup_menu(self):
        """Setup menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Config", command=self.load_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="List CVEs", command=self.show_cves)
        tools_menu.add_command(label="Generate Report", command=self.generate_report)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_docs)
    
    def setup_scanner_tab(self):
        """Setup device scanner tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Device Scanner")
        
        # Top frame for controls
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Scan Type:").pack(side=tk.LEFT, padx=5)
        self.scan_type = ttk.Combobox(control_frame, values=["all", "ble", "classic"], state="readonly", width=10)
        self.scan_type.set("all")
        self.scan_type.pack(side=tk.LEFT, padx=5)
        
        self.scan_btn = ttk.Button(control_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_scan_btn = ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_scan_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Clear", command=self.clear_devices).pack(side=tk.LEFT, padx=5)
        
        # Device list
        list_frame = ttk.Frame(tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview for devices
        columns = ("address", "name", "type", "rssi", "services")
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        self.device_tree.heading("address", text="MAC Address")
        self.device_tree.heading("name", text="Device Name")
        self.device_tree.heading("type", text="Type")
        self.device_tree.heading("rssi", text="RSSI (dBm)")
        self.device_tree.heading("services", text="Services")
        
        self.device_tree.column("address", width=150)
        self.device_tree.column("name", width=200)
        self.device_tree.column("type", width=100)
        self.device_tree.column("rssi", width=100)
        self.device_tree.column("services", width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscroll=scrollbar.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection
        self.device_tree.bind("<<TreeviewSelect>>", self.on_device_select)
        
        # Device info panel
        info_frame = ttk.LabelFrame(tab, text="Device Information")
        info_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        
        self.device_info_text = scrolledtext.ScrolledText(info_frame, height=8, state=tk.DISABLED)
        self.device_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_vuln_scan_tab(self):
        """Setup vulnerability scanning tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Vulnerability Scanner")
        
        # Control frame
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Target Device:").pack(side=tk.LEFT, padx=5)
        self.vuln_target = ttk.Entry(control_frame, width=20)
        self.vuln_target.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Use Selected", command=self.use_selected_device_vuln).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Scan", command=self.start_vuln_scan).pack(side=tk.LEFT, padx=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(tab, text="Vulnerabilities Found")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.vuln_text = scrolledtext.ScrolledText(results_frame, height=20)
        self.vuln_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_hid_attack_tab(self):
        """Setup HID attack tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="HID Attacks")
        
        # Warning label
        warning_frame = ttk.Frame(tab)
        warning_frame.pack(fill=tk.X, padx=5, pady=5)
        
        warning_label = ttk.Label(
            warning_frame, 
            text="⚠️ WARNING: HID attacks should only be used on authorized devices!",
            foreground="red",
            font=("TkDefaultFont", 10, "bold")
        )
        warning_label.pack()
        
        # Control frame
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Target Device:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.hid_target = ttk.Entry(control_frame, width=20)
        self.hid_target.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Button(control_frame, text="Use Selected", command=self.use_selected_device_hid).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Payload:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.hid_payload_path = ttk.Entry(control_frame, width=40)
        self.hid_payload_path.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Button(control_frame, text="Browse", command=self.browse_payload).grid(row=1, column=2, padx=5, pady=5)
        
        # Payload list
        payload_frame = ttk.LabelFrame(tab, text="Available Payloads")
        payload_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.payload_listbox = tk.Listbox(payload_frame, height=8)
        self.payload_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.payload_listbox.bind("<<ListboxSelect>>", self.on_payload_select)
        
        # Load available payloads
        self.load_payloads()
        
        # Execute button
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="⚠️ Execute Payload", command=self.execute_hid_payload).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Test Connection", command=self.test_hid_connection).pack(side=tk.LEFT, padx=5)
        
        # Results
        results_frame = ttk.LabelFrame(tab, text="Execution Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.hid_results_text = scrolledtext.ScrolledText(results_frame, height=10)
        self.hid_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_attack_tab(self):
        """Setup attack simulation tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Attack Simulation")
        
        # Warning
        warning_frame = ttk.Frame(tab)
        warning_frame.pack(fill=tk.X, padx=5, pady=5)
        
        warning_label = ttk.Label(
            warning_frame,
            text="⚠️ WARNING: Attack simulations should only be used on authorized devices!",
            foreground="red",
            font=("TkDefaultFont", 10, "bold")
        )
        warning_label.pack()
        
        # Control frame
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Attack Type:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.attack_type = ttk.Combobox(
            control_frame,
            values=["mitm", "bluesnarfing", "bluebugging", "bluejacking", "pin_bruteforce"],
            state="readonly",
            width=20
        )
        self.attack_type.set("bluejacking")
        self.attack_type.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(control_frame, text="Target:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.attack_target = ttk.Entry(control_frame, width=20)
        self.attack_target.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Button(control_frame, text="Use Selected", command=self.use_selected_device_attack).grid(row=1, column=2, padx=5, pady=5)
        
        ttk.Button(control_frame, text="⚠️ Execute Attack", command=self.execute_attack).grid(row=2, column=1, padx=5, pady=10, sticky=tk.W)
        
        # Results
        results_frame = ttk.LabelFrame(tab, text="Attack Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.attack_results_text = scrolledtext.ScrolledText(results_frame, height=15)
        self.attack_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_logs_tab(self):
        """Setup logs/console tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Logs")
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(tab, height=25, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_async_loop(self):
        """Setup asyncio event loop in background thread"""
        def run_loop():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()
        
        thread = threading.Thread(target=run_loop, daemon=True)
        thread.start()
    
    def run_async(self, coro):
        """Run coroutine in async loop"""
        if self.loop:
            future = asyncio.run_coroutine_threadsafe(coro, self.loop)
            return future.result()
        return None
    
    # Scanner tab methods
    def start_scan(self):
        """Start Bluetooth device scan"""
        if self.scanning:
            return
        
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_scan_btn.config(state=tk.NORMAL)
        self.update_status("Scanning for devices...")
        self.log_message("Starting Bluetooth scan...")
        
        # Run scan in background thread
        def scan_thread():
            try:
                scan_type = self.scan_type.get()
                devices = self.run_async(scan_bluetooth_devices(self.config.scanner, scan_type))
                
                # Update UI in main thread
                self.root.after(0, self.scan_complete, devices)
            except Exception as e:
                self.root.after(0, self.scan_error, str(e))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def stop_scan(self):
        """Stop device scan"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_scan_btn.config(state=tk.DISABLED)
        self.update_status("Scan stopped")
        self.log_message("Scan stopped by user")
    
    def scan_complete(self, devices: List[BluetoothDevice]):
        """Handle scan completion"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_scan_btn.config(state=tk.DISABLED)
        
        if devices:
            self.discovered_devices = devices
            self.update_device_list()
            self.update_status(f"Found {len(devices)} device(s)")
            self.log_message(f"Scan complete: Found {len(devices)} device(s)")
        else:
            self.update_status("No devices found")
            self.log_message("Scan complete: No devices found")
    
    def scan_error(self, error: str):
        """Handle scan error"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_scan_btn.config(state=tk.DISABLED)
        self.update_status(f"Scan failed: {error}")
        self.log_message(f"ERROR: Scan failed - {error}")
        messagebox.showerror("Scan Error", f"Failed to scan devices:\n{error}")
    
    def update_device_list(self):
        """Update device list in treeview"""
        # Clear existing items
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # Add devices
        for device in self.discovered_devices:
            self.device_tree.insert("", tk.END, values=(
                device.address,
                device.name or "Unknown",
                device.device_type,
                f"{device.rssi}" if device.rssi else "N/A",
                len(device.services)
            ))
    
    def clear_devices(self):
        """Clear device list"""
        self.discovered_devices = []
        self.selected_device = None
        self.update_device_list()
        self.device_info_text.config(state=tk.NORMAL)
        self.device_info_text.delete(1.0, tk.END)
        self.device_info_text.config(state=tk.DISABLED)
        self.update_status("Device list cleared")
    
    def on_device_select(self, event):
        """Handle device selection"""
        selection = self.device_tree.selection()
        if not selection:
            return
        
        item = self.device_tree.item(selection[0])
        address = item['values'][0]
        
        # Find device
        for device in self.discovered_devices:
            if device.address == address:
                self.selected_device = device
                self.display_device_info(device)
                break
    
    def display_device_info(self, device: BluetoothDevice):
        """Display device information"""
        info = f"""Address: {device.address}
Name: {device.name or 'Unknown'}
Type: {device.device_type}
RSSI: {device.rssi or 'N/A'} dBm
Services: {len(device.services)}
First Seen: {device.first_seen}
Last Seen: {device.last_seen}
"""
        
        if device.services:
            info += "\n\nServices:\n"
            for service in device.services[:10]:  # Show first 10
                info += f"  • {service}\n"
        
        self.device_info_text.config(state=tk.NORMAL)
        self.device_info_text.delete(1.0, tk.END)
        self.device_info_text.insert(1.0, info)
        self.device_info_text.config(state=tk.DISABLED)
    
    # Vulnerability scan methods
    def use_selected_device_vuln(self):
        """Use selected device for vulnerability scan"""
        if self.selected_device:
            self.vuln_target.delete(0, tk.END)
            self.vuln_target.insert(0, self.selected_device.address)
    
    def start_vuln_scan(self):
        """Start vulnerability scan"""
        target = self.vuln_target.get().strip()
        
        if not target:
            messagebox.showwarning("No Target", "Please enter a target MAC address")
            return
        
        if not validate_mac_address(target):
            messagebox.showerror("Invalid Address", "Invalid MAC address format")
            return
        
        self.update_status(f"Scanning {target} for vulnerabilities...")
        self.log_message(f"Starting vulnerability scan for {target}")
        self.vuln_text.delete(1.0, tk.END)
        self.vuln_text.insert(tk.END, "Scanning...\n")
        
        def scan_thread():
            try:
                # Get device info
                device = self.run_async(self.scanner.get_device_info(target))
                
                if not device:
                    self.root.after(0, lambda: messagebox.showerror("Connection Failed", 
                                    f"Could not connect to device {target}"))
                    return
                
                # Scan for vulnerabilities
                vulns = self.run_async(self.vuln_scanner.scan_device(device))
                
                # Update UI
                self.root.after(0, self.vuln_scan_complete, device, vulns)
            except Exception as e:
                self.root.after(0, lambda: self.log_message(f"ERROR: Vulnerability scan failed - {e}"))
                self.root.after(0, lambda: messagebox.showerror("Scan Error", f"Vulnerability scan failed:\n{e}"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def vuln_scan_complete(self, device: BluetoothDevice, vulnerabilities: List):
        """Handle vulnerability scan completion"""
        self.vuln_text.delete(1.0, tk.END)
        
        if not vulnerabilities:
            self.vuln_text.insert(tk.END, "✓ No vulnerabilities found\n")
            self.update_status("No vulnerabilities found")
            self.log_message("Vulnerability scan complete: No vulnerabilities found")
            return
        
        result = f"Found {len(vulnerabilities)} vulnerability(ies):\n\n"
        
        for vuln in vulnerabilities:
            result += f"{'='*60}\n"
            result += f"CVE ID: {vuln.cve_id}\n"
            result += f"Severity: {vuln.severity.upper()} (CVSS: {vuln.cvss_score})\n"
            result += f"Title: {vuln.title}\n"
            result += f"Description: {vuln.description}\n"
            if vuln.mitigation:
                result += f"Mitigation: {vuln.mitigation}\n"
            result += f"\n"
        
        self.vuln_text.insert(tk.END, result)
        self.update_status(f"Found {len(vulnerabilities)} vulnerability(ies)")
        self.log_message(f"Vulnerability scan complete: Found {len(vulnerabilities)} vulnerability(ies)")
    
    # HID attack methods
    def use_selected_device_hid(self):
        """Use selected device for HID attack"""
        if self.selected_device:
            self.hid_target.delete(0, tk.END)
            self.hid_target.insert(0, self.selected_device.address)
    
    def browse_payload(self):
        """Browse for payload file"""
        filename = filedialog.askopenfilename(
            title="Select Payload File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir="data/payloads/hid"
        )
        if filename:
            self.hid_payload_path.delete(0, tk.END)
            self.hid_payload_path.insert(0, filename)
    
    def load_payloads(self):
        """Load available payloads"""
        payload_dir = Path("data/payloads/hid")
        if payload_dir.exists():
            for payload_file in payload_dir.glob("*.json"):
                self.payload_listbox.insert(tk.END, payload_file.name)
    
    def on_payload_select(self, event):
        """Handle payload selection"""
        selection = self.payload_listbox.curselection()
        if selection:
            payload_name = self.payload_listbox.get(selection[0])
            payload_path = Path("data/payloads/hid") / payload_name
            self.hid_payload_path.delete(0, tk.END)
            self.hid_payload_path.insert(0, str(payload_path))
    
    def test_hid_connection(self):
        """Test HID connection"""
        target = self.hid_target.get().strip()
        
        if not target or not validate_mac_address(target):
            messagebox.showerror("Invalid Target", "Please enter a valid MAC address")
            return
        
        self.log_message(f"Testing HID connection to {target}...")
        self.hid_results_text.delete(1.0, tk.END)
        self.hid_results_text.insert(tk.END, "Testing connection...\n")
        
        def test_thread():
            try:
                injector = HIDKeyboardInjector(self.config.attack, self.config.security)
                connected = self.run_async(injector.connect(target))
                
                if connected:
                    self.run_async(injector.disconnect())
                    self.root.after(0, lambda: self.hid_results_text.insert(tk.END, "✓ Connection successful\n"))
                    self.root.after(0, lambda: self.log_message(f"HID connection test successful for {target}"))
                else:
                    self.root.after(0, lambda: self.hid_results_text.insert(tk.END, "✗ Connection failed\n"))
                    self.root.after(0, lambda: self.log_message(f"HID connection test failed for {target}"))
            except Exception as e:
                self.root.after(0, lambda: self.hid_results_text.insert(tk.END, f"✗ Error: {e}\n"))
                self.root.after(0, lambda: self.log_message(f"HID connection error: {e}"))
        
        threading.Thread(target=test_thread, daemon=True).start()
    
    def execute_hid_payload(self):
        """Execute HID payload"""
        target = self.hid_target.get().strip()
        payload_path = self.hid_payload_path.get().strip()
        
        if not target or not validate_mac_address(target):
            messagebox.showerror("Invalid Target", "Please enter a valid MAC address")
            return
        
        if not payload_path or not Path(payload_path).exists():
            messagebox.showerror("Invalid Payload", "Please select a valid payload file")
            return
        
        # Confirm execution
        if not messagebox.askyesno("Confirm Execution",
                                   f"Execute HID payload on {target}?\n\n"
                                   "This will perform keyboard injection attacks.\n"
                                   "Only proceed if you have authorization!"):
            return
        
        self.log_message(f"Executing HID payload: {payload_path} on {target}")
        self.hid_results_text.delete(1.0, tk.END)
        self.hid_results_text.insert(tk.END, f"Executing payload: {payload_path}\n")
        
        def execute_thread():
            try:
                # Load payload
                payload = HIDPayload.from_file(payload_path)
                self.root.after(0, lambda: self.hid_results_text.insert(tk.END, 
                                f"Payload: {payload.name}\n"))
                self.root.after(0, lambda: self.hid_results_text.insert(tk.END, 
                                f"Target OS: {payload.target_os}\n"))
                self.root.after(0, lambda: self.hid_results_text.insert(tk.END, 
                                f"Commands: {len(payload.commands)}\n\n"))
                
                # Connect and execute
                injector = HIDKeyboardInjector(self.config.attack, self.config.security)
                connected = self.run_async(injector.connect(target))
                
                if not connected:
                    self.root.after(0, lambda: self.hid_results_text.insert(tk.END, 
                                    "✗ Connection failed\n"))
                    return
                
                self.root.after(0, lambda: self.hid_results_text.insert(tk.END, 
                                "Executing...\n"))
                
                result = self.run_async(injector.execute_payload(payload))
                self.run_async(injector.disconnect())
                
                # Display result
                self.root.after(0, lambda: self.display_hid_result(result))
            except Exception as e:
                self.root.after(0, lambda: self.hid_results_text.insert(tk.END, 
                                f"\n✗ Error: {e}\n"))
                self.root.after(0, lambda: self.log_message(f"HID execution error: {e}"))
        
        threading.Thread(target=execute_thread, daemon=True).start()
    
    def display_hid_result(self, result):
        """Display HID execution result"""
        if result.success:
            self.hid_results_text.insert(tk.END, "\n✓ Payload executed successfully\n")
        else:
            self.hid_results_text.insert(tk.END, "\n✗ Payload execution failed\n")
            if result.error:
                self.hid_results_text.insert(tk.END, f"Error: {result.error}\n")
        
        self.hid_results_text.insert(tk.END, f"\nCommands executed: {result.commands_executed}\n")
        self.hid_results_text.insert(tk.END, f"Duration: {result.duration:.2f} seconds\n")
        
        self.log_message(f"HID execution {'successful' if result.success else 'failed'}: "
                        f"{result.commands_executed} commands in {result.duration:.2f}s")
    
    # Attack simulation methods
    def use_selected_device_attack(self):
        """Use selected device for attack"""
        if self.selected_device:
            self.attack_target.delete(0, tk.END)
            self.attack_target.insert(0, self.selected_device.address)
    
    def execute_attack(self):
        """Execute attack simulation"""
        attack_type = self.attack_type.get()
        target = self.attack_target.get().strip()
        
        if not target or not validate_mac_address(target):
            messagebox.showerror("Invalid Target", "Please enter a valid MAC address")
            return
        
        # Confirm execution
        if not messagebox.askyesno("Confirm Attack",
                                   f"Execute {attack_type} attack on {target}?\n\n"
                                   "This is a simulation for authorized testing only.\n"
                                   "Only proceed if you have authorization!"):
            return
        
        self.log_message(f"Executing {attack_type} attack on {target}")
        self.attack_results_text.delete(1.0, tk.END)
        self.attack_results_text.insert(tk.END, f"Executing {attack_type} attack...\n")
        
        def attack_thread():
            try:
                kwargs = {'target': target}
                result = self.run_async(self.attack_manager.execute_attack(attack_type, **kwargs))
                
                # Display result
                self.root.after(0, lambda: self.display_attack_result(result))
            except Exception as e:
                self.root.after(0, lambda: self.attack_results_text.insert(tk.END, 
                                f"\n✗ Error: {e}\n"))
                self.root.after(0, lambda: self.log_message(f"Attack error: {e}"))
        
        threading.Thread(target=attack_thread, daemon=True).start()
    
    def display_attack_result(self, result):
        """Display attack result"""
        if result.success:
            self.attack_results_text.insert(tk.END, "\n✓ Attack successful\n")
        else:
            self.attack_results_text.insert(tk.END, "\n✗ Attack failed\n")
            if result.error:
                self.attack_results_text.insert(tk.END, f"Error: {result.error}\n")
        
        self.attack_results_text.insert(tk.END, f"\nAttack Type: {result.attack_type}\n")
        self.attack_results_text.insert(tk.END, f"Target: {result.target}\n")
        self.attack_results_text.insert(tk.END, f"Duration: {result.duration:.2f} seconds\n")
        self.attack_results_text.insert(tk.END, f"Timestamp: {result.timestamp}\n")
        
        if result.details:
            self.attack_results_text.insert(tk.END, "\nDetails:\n")
            for key, value in result.details.items():
                self.attack_results_text.insert(tk.END, f"  {key}: {value}\n")
        
        self.log_message(f"Attack {'successful' if result.success else 'failed'}: "
                        f"{result.attack_type} on {result.target}")
    
    # Menu methods
    def load_config(self):
        """Load configuration file"""
        filename = filedialog.askopenfilename(
            title="Select Configuration File",
            filetypes=[("YAML files", "*.yaml"), ("YAML files", "*.yml"), ("All files", "*.*")]
        )
        if filename:
            try:
                self.config = load_config(filename)
                self.log_message(f"Configuration loaded from {filename}")
                messagebox.showinfo("Config Loaded", "Configuration loaded successfully")
            except Exception as e:
                messagebox.showerror("Config Error", f"Failed to load configuration:\n{e}")
    
    def show_cves(self):
        """Show CVE database"""
        cve_window = tk.Toplevel(self.root)
        cve_window.title("CVE Database")
        cve_window.geometry("800x600")
        
        # Treeview for CVEs
        columns = ("cve_id", "title", "severity", "cvss")
        tree = ttk.Treeview(cve_window, columns=columns, show="headings")
        
        tree.heading("cve_id", text="CVE ID")
        tree.heading("title", text="Title")
        tree.heading("severity", text="Severity")
        tree.heading("cvss", text="CVSS")
        
        tree.column("cve_id", width=150)
        tree.column("title", width=400)
        tree.column("severity", width=100)
        tree.column("cvss", width=80)
        
        scrollbar = ttk.Scrollbar(cve_window, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load CVEs
        for cve_id, vuln in self.cve_db.vulnerabilities.items():
            tree.insert("", tk.END, values=(
                vuln.cve_id,
                vuln.title[:60] + "..." if len(vuln.title) > 60 else vuln.title,
                vuln.severity,
                vuln.cvss_score
            ))
    
    def generate_report(self):
        """Generate comprehensive report"""
        if not self.discovered_devices:
            messagebox.showinfo("No Data", "No devices found. Please run a scan first.")
            return
        
        try:
            report_path = self.report_gen.generate_scan_report(self.discovered_devices, format='json')
            self.log_message(f"Report generated: {report_path}")
            messagebox.showinfo("Report Generated", f"Report saved to:\n{report_path}")
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report:\n{e}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Blue-sec v2.0
Advanced Bluetooth Security Testing Framework
with Real-Time HID Attacks

Features:
• Bluetooth device scanning and enumeration
• Vulnerability assessment with CVE database
• Attack simulation (MITM, Bluesnarfing, etc.)
• Real-time HID attacks (BadUSB style)
• Interactive device testing
• Comprehensive reporting

Author: @irfan-sec
License: MIT
Website: https://cyberlearn.systems
GitHub: https://github.com/irfan-sec/Blue-sec

⚠️ For authorized security testing only!
"""
        messagebox.showinfo("About Blue-sec", about_text)
    
    def show_docs(self):
        """Show documentation link"""
        messagebox.showinfo("Documentation", 
                          "Documentation available in:\n\n"
                          "• README.md\n"
                          "• docs/USAGE.md\n"
                          "• docs/API.md\n\n"
                          "Visit: https://github.com/irfan-sec/Blue-sec")
    
    # Utility methods
    def update_status(self, message: str):
        """Update status bar"""
        self.status_bar.config(text=message)
    
    def log_message(self, message: str):
        """Add message to log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def clear_logs(self):
        """Clear log text"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def export_logs(self):
        """Export logs to file"""
        filename = filedialog.asksaveasfilename(
            title="Export Logs",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Logs Exported", f"Logs saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export logs:\n{e}")


def run_gui(config: Optional[BlueSecConfig] = None):
    """Run the GUI application"""
    root = tk.Tk()
    app = BlueSecGUI(root, config)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
