import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import sys
import ctypes
import random
import string
import json
import uuid
from cryptography.fernet import Fernet

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except WindowsError:
        return False

class HyperVHardenedLoaderGUI:
    def __init__(self, master):
        self.master = master
        master.title("Hyper-V Hardened Loader GUI")
        master.geometry("800x600")

        self.create_widgets()
        self.load_settings()

    def create_widgets(self):
        notebook = ttk.Notebook(self.master)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # Basic Settings Tab
        basic_frame = ttk.Frame(notebook)
        notebook.add(basic_frame, text="Basic Settings")
        self.create_basic_settings(basic_frame)

        # System Attributes Tab
        system_frame = ttk.Frame(notebook)
        notebook.add(system_frame, text="System Attributes")
        self.create_system_attributes(system_frame)

        # Hardware Settings Tab
        hardware_frame = ttk.Frame(notebook)
        notebook.add(hardware_frame, text="Hardware Settings")
        self.create_hardware_settings(hardware_frame)

        # Network Settings Tab
        network_frame = ttk.Frame(notebook)
        notebook.add(network_frame, text="Network Settings")
        self.create_network_settings(network_frame)

        # Security Settings Tab
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Security Settings")
        self.create_security_settings(security_frame)

        # Actions Tab
        actions_frame = ttk.Frame(notebook)
        notebook.add(actions_frame, text="Actions")
        self.create_actions(actions_frame)

        # Log Output
        self.log_text = tk.Text(self.master, height=10, width=80)
        self.log_text.pack(padx=10, pady=10, expand=True, fill="both")

        # Scrollbar for log
        scrollbar = ttk.Scrollbar(self.master, command=self.log_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_text['yscrollcommand'] = scrollbar.set

    def create_basic_settings(self, parent):
        # VM Name
        ttk.Label(parent, text="VM Name:").grid(column=0, row=0, sticky='W', padx=5, pady=5)
        self.vm_name = tk.StringVar()
        self.vm_name_entry = ttk.Entry(parent, textvariable=self.vm_name, width=50)
        self.vm_name_entry.grid(column=1, row=0, padx=5, pady=5)

        # VM Path
        ttk.Label(parent, text="VM Path:").grid(column=0, row=1, sticky='W', padx=5, pady=5)
        self.vm_path = tk.StringVar(value=r"C:\HyperV\VMs")
        self.vm_path_entry = ttk.Entry(parent, textvariable=self.vm_path, width=50)
        self.vm_path_entry.grid(column=1, row=1, padx=5, pady=5)
        ttk.Button(parent, text="Browse", command=self.browse_vm_path).grid(column=2, row=1, padx=5, pady=5)

        # VM Generation
        ttk.Label(parent, text="VM Generation:").grid(column=0, row=2, sticky='W', padx=5, pady=5)
        self.vm_generation = tk.StringVar(value="2")
        ttk.Combobox(parent, textvariable=self.vm_generation, values=["1", "2"], state="readonly").grid(column=1, row=2, padx=5, pady=5)

    def create_system_attributes(self, parent):
        # BIOS GUID
        ttk.Label(parent, text="BIOS GUID:").grid(column=0, row=0, sticky='W', padx=5, pady=5)
        self.bios_guid = tk.StringVar()
        ttk.Entry(parent, textvariable=self.bios_guid, width=40).grid(column=1, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Generate", command=self.generate_bios_guid).grid(column=2, row=0, padx=5, pady=5)

        # System Manufacturer
        ttk.Label(parent, text="System Manufacturer:").grid(column=0, row=1, sticky='W', padx=5, pady=5)
        self.system_manufacturer = tk.StringVar(value="Dell Inc.")
        ttk.Entry(parent, textvariable=self.system_manufacturer, width=40).grid(column=1, row=1, padx=5, pady=5)

        # System Model
        ttk.Label(parent, text="System Model:").grid(column=0, row=2, sticky='W', padx=5, pady=5)
        self.system_model = tk.StringVar(value="Latitude 5500")
        ttk.Entry(parent, textvariable=self.system_model, width=40).grid(column=1, row=2, padx=5, pady=5)

        # System Family
        ttk.Label(parent, text="System Family:").grid(column=0, row=3, sticky='W', padx=5, pady=5)
        self.system_family = tk.StringVar(value="Latitude")
        ttk.Entry(parent, textvariable=self.system_family, width=40).grid(column=1, row=3, padx=5, pady=5)

        # System SKU
        ttk.Label(parent, text="System SKU:").grid(column=0, row=4, sticky='W', padx=5, pady=5)
        self.system_sku = tk.StringVar(value="SKU-123456")
        ttk.Entry(parent, textvariable=self.system_sku, width=40).grid(column=1, row=4, padx=5, pady=5)

    def create_hardware_settings(self, parent):
        # Processor Count
        ttk.Label(parent, text="Processor Count:").grid(column=0, row=0, sticky='W', padx=5, pady=5)
        self.processor_count = tk.StringVar(value="2")
        ttk.Combobox(parent, textvariable=self.processor_count, values=["1", "2", "4", "8"], state="readonly").grid(column=1, row=0, padx=5, pady=5)

        # Memory Size (GB)
        ttk.Label(parent, text="Memory Size (GB):").grid(column=0, row=1, sticky='W', padx=5, pady=5)
        self.memory_size = tk.StringVar(value="4")
        ttk.Combobox(parent, textvariable=self.memory_size, values=["2", "4", "8", "16"], state="readonly").grid(column=1, row=1, padx=5, pady=5)

        # Dynamic Memory
        ttk.Label(parent, text="Dynamic Memory:").grid(column=0, row=2, sticky='W', padx=5, pady=5)
        self.dynamic_memory = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, variable=self.dynamic_memory).grid(column=1, row=2, padx=5, pady=5)

        # Nested Virtualization
        ttk.Label(parent, text="Nested Virtualization:").grid(column=0, row=3, sticky='W', padx=5, pady=5)
        self.nested_virtualization = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, variable=self.nested_virtualization).grid(column=1, row=3, padx=5, pady=5)

        # CPU Features
        ttk.Label(parent, text="CPU Features:").grid(column=0, row=4, sticky='W', padx=5, pady=5)
        self.cpu_features = tk.StringVar(value="Default")
        ttk.Combobox(parent, textvariable=self.cpu_features, values=["Default", "Compatibility", "Maximum"], state="readonly").grid(column=1, row=4, padx=5, pady=5)

    def create_network_settings(self, parent):
        # Virtual Switch
        ttk.Label(parent, text="Virtual Switch:").grid(column=0, row=0, sticky='W', padx=5, pady=5)
        self.virtual_switch = tk.StringVar()
        self.virtual_switch_combo = ttk.Combobox(parent, textvariable=self.virtual_switch, state="readonly")
        self.virtual_switch_combo.grid(column=1, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Refresh", command=self.refresh_virtual_switches).grid(column=2, row=0, padx=5, pady=5)

        # MAC Address
        ttk.Label(parent, text="MAC Address:").grid(column=0, row=1, sticky='W', padx=5, pady=5)
        self.mac_address = tk.StringVar()
        ttk.Entry(parent, textvariable=self.mac_address, width=20).grid(column=1, row=1, padx=5, pady=5)
        ttk.Button(parent, text="Randomize", command=self.randomize_mac).grid(column=2, row=1, padx=5, pady=5)

        # VLAN ID
        ttk.Label(parent, text="VLAN ID:").grid(column=0, row=2, sticky='W', padx=5, pady=5)
        self.vlan_id = tk.StringVar()
        ttk.Entry(parent, textvariable=self.vlan_id, width=10).grid(column=1, row=2, padx=5, pady=5)

        # Network Adapter Type
        ttk.Label(parent, text="Network Adapter Type:").grid(column=0, row=3, sticky='W', padx=5, pady=5)
        self.network_adapter_type = tk.StringVar(value="Default")
        ttk.Combobox(parent, textvariable=self.network_adapter_type, values=["Default", "Legacy"], state="readonly").grid(column=1, row=3, padx=5, pady=5)

    def create_security_settings(self, parent):
        # Secure Boot
        ttk.Label(parent, text="Secure Boot:").grid(column=0, row=0, sticky='W', padx=5, pady=5)
        self.secure_boot = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, variable=self.secure_boot).grid(column=1, row=0, padx=5, pady=5)

        # TPM
        ttk.Label(parent, text="Enable TPM:").grid(column=0, row=1, sticky='W', padx=5, pady=5)
        self.enable_tpm = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, variable=self.enable_tpm).grid(column=1, row=1, padx=5, pady=5)

        # Encryption
        ttk.Label(parent, text="Enable Encryption:").grid(column=0, row=2, sticky='W', padx=5, pady=5)
        self.enable_encryption = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, variable=self.enable_encryption).grid(column=1, row=2, padx=5, pady=5)

        # Shielded VM
        ttk.Label(parent, text="Shielded VM:").grid(column=0, row=3, sticky='W', padx=5, pady=5)
        self.shielded_vm = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, variable=self.shielded_vm).grid(column=1, row=3, padx=5, pady=5)

    def create_actions(self, parent):
        ttk.Button(parent, text="Create VM", command=self.create_vm).grid(column=0, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Configure VM", command=self.configure_vm).grid(column=1, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Start VM", command=self.start_vm).grid(column=2, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Stop VM", command=self.stop_vm).grid(column=3, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Save Settings", command=self.save_settings).grid(column=0, row=1, padx=5, pady=5)
        ttk.Button(parent, text="Load Settings", command=self.load_settings).grid(column=1, row=1, padx=5, pady=5)
        ttk.Button(parent, text="Generate Random Profile", command=self.generate_random_profile).grid(column=2, row=1, padx=5, pady=5)

    def configure_vm(self):
        vm_name = self.vm_name.get()
        try:
            # Set BIOS GUID
            self.powershell(f'Set-VMFirmware -VMName "{vm_name}" -BiosGUID "{self.bios_guid.get()}"')

            # Set System Information
            self.powershell(f'Set-VM -VMName "{vm_name}" -ProcessorCount {self.processor_count.get()}')
            self.powershell(f'Set-VMMemory -VMName "{vm_name}" -DynamicMemoryEnabled ${str(self.dynamic_memory.get()).lower()} -StartupBytes {int(self.memory_size.get()) * 1024 * 1024 * 1024}')
            self.powershell(f'Set-VMNetworkAdapter -VMName "{vm_name}" -SwitchName "{self.virtual_switch.get()}" -StaticMacAddress "{self.mac_address.get()}"')

            # Set Security Features
            if int(self.vm_generation.get()) == 2:
                secure_boot = "On" if self.secure_boot.get() else "Off"
                self.powershell(f'Set-VMFirmware -VMName "{vm_name}" -EnableSecureBoot {secure_boot}')

            # Enable TPM
            if self.enable_tpm.get():
                self.powershell(f'Enable-VMTPM -VMName "{vm_name}"')

            # Enable Encryption
            if self.enable_encryption.get():
                self.powershell(f'Enable-VMTPMProtection -VMName "{vm_name}"')

            # Configure as Shielded VM
            if self.shielded_vm.get():
                self.powershell(f'Set-VMSecurityPolicy -VMName "{vm_name}" -Shielded $true')

            # Modify Device Descriptions
            self.modify_device_descriptions(vm_name)

            self.log("VM configuration completed successfully.")
        except subprocess.CalledProcessError as e:
            self.log(f"Error configuring VM: {e.stderr}")

    def modify_device_descriptions(self, vm_name):
        try:
            # Example: Change network adapter name
            self.powershell(f'Rename-VMNetworkAdapter -VMName "{vm_name}" -NewName "Ethernet Adapter"')

            # Example: Change display adapter name
            self.powershell(f'Set-VMVideo -VMName "{vm_name}" -ResolutionType "1920x1080"')

            # Example: Change other device names
            # This is a placeholder for additional device modifications
            self.log("Device descriptions modified successfully.")
        except subprocess.CalledProcessError as e:
            self.log(f"Error modifying device descriptions: {e.stderr}")

    def start_vm(self):
        vm_name = self.vm_name.get()
        try:
            self.powershell(f'Start-VM -Name "{vm_name}"')
            self.log(f"VM '{vm_name}' started successfully.")
        except subprocess.CalledProcessError as e:
            self.log(f"Error starting VM: {e.stderr}")

    def stop_vm(self):
        vm_name = self.vm_name.get()
        try:
            self.powershell(f'Stop-VM -Name "{vm_name}" -Force')
            self.log(f"VM '{vm_name}' stopped successfully.")
        except subprocess.CalledProcessError as e:
            self.log(f"Error stopping VM: {e.stderr}")

    def powershell(self, command):
        full_command = f'powershell -Command "{command}"'
        result = subprocess.run(full_command, check=True, capture_output=True, text=True, shell=True)
        self.log(f"Executed: {full_command}")
        if result.stdout:
            self.log(f"Output: {result.stdout}")
        return result

    def save_settings(self):
        settings = {
            "vm_name": self.vm_name.get(),
            "vm_path": self.vm_path.get(),
            "vm_generation": self.vm_generation.get(),
            "processor_count": self.processor_count.get(),
            "memory_size": self.memory_size.get(),
            "bios_guid": self.bios_guid.get(),
            "nested_virtualization": self.nested_virtualization.get(),
            "dynamic_memory": self.dynamic_memory.get(),
            "virtual_switch": self.virtual_switch.get(),
            "mac_address": self.mac_address.get(),
            "vlan_id": self.vlan_id.get(),
            "secure_boot": self.secure_boot.get(),
            "enable_tpm": self.enable_tpm.get(),
            "enable_encryption": self.enable_encryption.get(),
            "shielded_vm": self.shielded_vm.get()
        }
        # Encrypt sensitive settings
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_settings = cipher_suite.encrypt(json.dumps(settings).encode())

        with open("hyperv_hardened_loader_settings.enc", "wb") as f:
            f.write(encrypted_settings)
        
        with open("hyperv_hardened_loader_key.key", "wb") as f:
            f.write(key)

        self.log("Settings saved and encrypted successfully.")

    def load_settings(self):
        try:
            with open("hyperv_hardened_loader_key.key", "rb") as key_file:
                key = key_file.read()

            cipher_suite = Fernet(key)
            
            with open("hyperv_hardened_loader_settings.enc", "rb") as f:
                encrypted_settings = f.read()

            decrypted_settings = cipher_suite.decrypt(encrypted_settings)
            settings = json.loads(decrypted_settings.decode())

            for key, value in settings.items():
                if hasattr(self, key):
                    getattr(self, key).set(value)
            self.log("Settings loaded and decrypted successfully.")
        except FileNotFoundError:
            self.log("No saved settings found.")
        except Exception as e:
            self.log(f"Error loading settings: {str(e)}")

    def generate_random_profile(self):
        self.vm_name.set(f"HardenedVM-{random.randint(1000, 9999)}")
        self.generate_bios_guid()
        self.randomize_mac()
        self.processor_count.set(random.choice(["2", "4"]))
        self.memory_size.set(random.choice(["4", "8"]))
        self.system_manufacturer.set(random.choice(["Dell Inc.", "HP", "Lenovo", "ASUS", "Acer"]))
        self.system_model.set(f"Model-{random.randint(1000, 9999)}")
        self.system_family.set(random.choice(["Latitude", "ThinkPad", "EliteBook", "ZenBook"]))
        self.system_sku.set(f"SKU-{random.randint(100000, 999999)}")
        self.cpu_features.set(random.choice(["Default", "Compatibility", "Maximum"]))
        self.network_adapter_type.set(random.choice(["Default", "Legacy"]))
        self.secure_boot.set(random.choice([True, False]))
        self.nested_virtualization.set(random.choice([True, False]))
        self.dynamic_memory.set(random.choice([True, False]))
        self.enable_tpm.set(random.choice([True, False]))
        self.enable_encryption.set(random.choice([True, False]))
        self.shielded_vm.set(random.choice([True, False]))
        self.log("Random profile generated.")

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def generate_bios_guid(self):
        self.bios_guid.set(str(uuid.uuid4()))

    def randomize_mac(self):
        mac = [0x00, 0x15, 0x5D,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        self.mac_address.set(':'.join(map(lambda x: "%02x" % x, mac)))

    def browse_vm_path(self):
        path = filedialog.askdirectory()
        if path:
            self.vm_path.set(path)

    def refresh_virtual_switches(self):
        try:
            result = self.powershell('Get-VMSwitch | Select-Object -ExpandProperty Name')
            switches = result.stdout.strip().split('\n')
            self.virtual_switch_combo['values'] = switches
            if switches:
                self.virtual_switch.set(switches[0])
        except subprocess.CalledProcessError as e:
            self.log(f"Error refreshing virtual switches: {e.stderr}")

if __name__ == "__main__":
    if is_admin():
        root = tk.Tk()
        app = HyperVHardenedLoaderGUI(root)
        root.mainloop()
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
