import tkinter as tk
from tkinter import ttk, filedialog, messagebox, colorchooser
import subprocess
import os
import sys
import ctypes
import winreg
import random
import string
import json


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except WindowsError:
        return False


class VBoxHardenedLoaderGUI:
    def __init__(self, master):
        self.master = master
        master.title("VirtualBox Hardened Loader GUI")
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

        # Advanced Settings Tab
        advanced_frame = ttk.Frame(notebook)
        notebook.add(advanced_frame, text="Advanced Settings")
        self.create_advanced_settings(advanced_frame)

        # Custom BIOS Tab
        bios_frame = ttk.Frame(notebook)
        notebook.add(bios_frame, text="Custom BIOS")
        self.create_bios_settings(bios_frame)

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
        # VirtualBox Path
        ttk.Label(parent, text="VirtualBox Path:").grid(column=0, row=0, sticky='W', padx=5, pady=5)
        self.vbox_path = tk.StringVar(value=r"C:\Program Files\Oracle\VirtualBox")
        self.vbox_path_entry = ttk.Entry(parent, textvariable=self.vbox_path, width=50)
        self.vbox_path_entry.grid(column=1, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Browse", command=self.browse_vbox_path).grid(column=2, row=0, padx=5, pady=5)

        # VM Name
        ttk.Label(parent, text="VM Name:").grid(column=0, row=1, sticky='W', padx=5, pady=5)
        self.vm_name = tk.StringVar()
        self.vm_name_entry = ttk.Entry(parent, textvariable=self.vm_name, width=50)
        self.vm_name_entry.grid(column=1, row=1, padx=5, pady=5)

        # Config Directory
        ttk.Label(parent, text="Config Directory:").grid(column=0, row=2, sticky='W', padx=5, pady=5)
        self.config_dir = tk.StringVar(value=os.path.join(os.getcwd(), "Binary", "data"))
        self.config_dir_entry = ttk.Entry(parent, textvariable=self.config_dir, width=50)
        self.config_dir_entry.grid(column=1, row=2, padx=5, pady=5)
        ttk.Button(parent, text="Browse", command=self.browse_config_dir).grid(column=2, row=2, padx=5, pady=5)

        # VM Configuration Type
        ttk.Label(parent, text="VM Config Type:").grid(column=0, row=3, sticky='W', padx=5, pady=5)
        self.vm_config_type = tk.StringVar(value="ahci")
        vm_config_options = ["ahci", "ide", "efiahci", "efiide"]
        ttk.Combobox(parent, textvariable=self.vm_config_type, values=vm_config_options, state="readonly").grid(column=1, row=3, padx=5, pady=5)

    def create_advanced_settings(self, parent):
        # MAC Address
        ttk.Label(parent, text="MAC Address:").grid(column=0, row=0, sticky='W', padx=5, pady=5)
        self.mac_address = tk.StringVar(value="6CF0491A6E12")
        ttk.Entry(parent, textvariable=self.mac_address, width=20).grid(column=1, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Randomize", command=self.randomize_mac).grid(column=2, row=0, padx=5, pady=5)

        # ACPI OEM ID
        ttk.Label(parent, text="ACPI OEM ID:").grid(column=0, row=1, sticky='W', padx=5, pady=5)
        self.acpi_oem_id = tk.StringVar(value="ASUS")
        ttk.Entry(parent, textvariable=self.acpi_oem_id, width=20).grid(column=1, row=1, padx=5, pady=5)

        # Paravirtualization Provider
        ttk.Label(parent, text="Paravirt Provider:").grid(column=0, row=2, sticky='W', padx=5, pady=5)
        self.paravirt_provider = tk.StringVar(value="legacy")
        ttk.Combobox(parent, textvariable=self.paravirt_provider, values=["legacy", "default", "none", "minimal"], state="readonly").grid(column=1, row=2, padx=5, pady=5)

        # Graphics Controller
        ttk.Label(parent, text="Graphics Controller:").grid(column=0, row=3, sticky='W', padx=5, pady=5)
        self.graphics_controller = tk.StringVar(value="vmsvga")
        ttk.Combobox(parent, textvariable=self.graphics_controller, values=["vmsvga", "vboxvga", "vboxsvga"], state="readonly").grid(column=1, row=3, padx=5, pady=5)

    def create_bios_settings(self, parent):
        # BIOS Vendor
        ttk.Label(parent, text="BIOS Vendor:").grid(column=0, row=0, sticky='W', padx=5, pady=5)
        self.bios_vendor = tk.StringVar(value="Asus")
        ttk.Entry(parent, textvariable=self.bios_vendor, width=30).grid(column=1, row=0, padx=5, pady=5)

        # BIOS Version
        ttk.Label(parent, text="BIOS Version:").grid(column=0, row=1, sticky='W', padx=5, pady=5)
        self.bios_version = tk.StringVar(value="MB52.88Z.0088.B05.0904162222")
        ttk.Entry(parent, textvariable=self.bios_version, width=30).grid(column=1, row=1, padx=5, pady=5)

        # System Vendor
        ttk.Label(parent, text="System Vendor:").grid(column=0, row=2, sticky='W', padx=5, pady=5)
        self.system_vendor = tk.StringVar(value="Asus")
        ttk.Entry(parent, textvariable=self.system_vendor, width=30).grid(column=1, row=2, padx=5, pady=5)

        # System Product
        ttk.Label(parent, text="System Product:").grid(column=0, row=3, sticky='W', padx=5, pady=5)
        self.system_product = tk.StringVar(value="MyBook5,2")
        ttk.Entry(parent, textvariable=self.system_product, width=30).grid(column=1, row=3, padx=5, pady=5)

        # Custom BIOS Logo
        ttk.Label(parent, text="Custom BIOS Logo:").grid(column=0, row=4, sticky='W', padx=5, pady=5)
        self.bios_logo_path = tk.StringVar()
        ttk.Entry(parent, textvariable=self.bios_logo_path, width=30).grid(column=1, row=4, padx=5, pady=5)
        ttk.Button(parent, text="Browse", command=self.browse_bios_logo).grid(column=2, row=4, padx=5, pady=5)

    def create_actions(self, parent):
        ttk.Button(parent, text="Configure VM", command=self.configure_vm).grid(column=0, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Start Monitoring", command=self.start_monitoring).grid(column=1, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Stop Monitoring", command=self.stop_monitoring).grid(column=2, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Show VBox Version", command=self.show_vbox_version).grid(column=3, row=0, padx=5, pady=5)
        ttk.Button(parent, text="Save Settings", command=self.save_settings).grid(column=0, row=1, padx=5, pady=5)
        ttk.Button(parent, text="Load Settings", command=self.load_settings).grid(column=1, row=1, padx=5, pady=5)
        ttk.Button(parent, text="Generate Random Profile", command=self.generate_random_profile).grid(column=2, row=1, padx=5, pady=5)

    def browse_vbox_path(self):
        path = filedialog.askdirectory()
        if path:
            self.vbox_path.set(path)

    def browse_config_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.config_dir.set(path)

    def browse_bios_logo(self):
        path = filedialog.askopenfilename(filetypes=[("BMP files", "*.bmp")])
        if path:
            self.bios_logo_path.set(path)

    def randomize_mac(self):
        mac = [0x6C, 0xF0, 0x49,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        self.mac_address.set(':'.join(map(lambda x: "%02x" % x, mac)))

    def configure_vm(self):
        vm_name = self.vm_name.get()
        vbox_manage_path = os.path.join(self.vbox_path.get(), "VBoxManage.exe")
        config_dir = self.config_dir.get()
        config_type = self.vm_config_type.get()

        if not all([vm_name, vbox_manage_path, config_dir]):
            messagebox.showerror("Error", "All parameters must be provided.")
            return

        try:
            # Set extradata
            self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/CPUM/EnableHVP" 0')
            self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/TM/TSCMode" RealTSCOffset')

            # Set BIOS information
            bios_settings = {
                "DmiBIOSVendor": self.bios_vendor.get(),
                "DmiBIOSVersion": self.bios_version.get(),
                "DmiBIOSReleaseDate": "08/10/13",
                "DmiBIOSReleaseMajor": "5",
                "DmiBIOSReleaseMinor": "9",
                "DmiBIOSFirmwareMajor": "1",
                "DmiBIOSFirmwareMinor": "0"
            }
            for key, value in bios_settings.items():
                self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/Devices/pcbios/0/Config/{key}" "{value}"')

            # Set system information
            system_settings = {
                "DmiSystemVendor": self.system_vendor.get(),
                "DmiSystemProduct": self.system_product.get(),
                "DmiSystemVersion": "1.0",
                "DmiSystemSerial": ''.join(random.choices(string.ascii_uppercase + string.digits, k=17)),
                "DmiSystemSKU": "FM550EA#ACB",
                "DmiSystemFamily": "Ultrabook",
                "DmiSystemUuid": f"{random.randint(0, 0xFFFFFFFF):08x}-{random.randint(0, 0xFFFF):04x}-{random.randint(0, 0xFFFF):04x}-{random.randint(0, 0xFFFF):04x}-{random.randint(0, 0xFFFFFFFFFFFF):012x}"
            }
            for key, value in system_settings.items():
                self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/Devices/pcbios/0/Config/{key}" "{value}"')

            # Set board information
            board_settings = {
                "DmiBoardVendor": self.system_vendor.get(),
                "DmiBoardProduct": f"{self.system_product.get()}-Board",
                "DmiBoardVersion": "3.0",
                "DmiBoardSerial": ''.join(random.choices(string.ascii_uppercase + string.digits, k=17)),
                "DmiBoardAssetTag": "Base Board Asset Tag#",
                "DmiBoardLocInChass": "Board Loc In",
                "DmiBoardBoardType": "10"
            }
            for key, value in board_settings.items():
                self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/Devices/pcbios/0/Config/{key}" "{value}"')

            # Set chassis information
            chassis_settings = {
                "DmiChassisVendor": f"{self.system_vendor.get()} Inc.",
                "DmiChassisType": "10",
                "DmiChassisVersion": self.system_product.get(),
                "DmiChassisSerial": ''.join(random.choices(string.ascii_uppercase + string.digits, k=17)),
                "DmiChassisAssetTag": "Asset-1234567890"
            }
            for key, value in chassis_settings.items():
                self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/Devices/pcbios/0/Config/{key}" "{value}"')

            # Set OEM information
            self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer" "Extended version info: 1.00.00"')
            self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev" "Extended revision info: 1A"')

            # Set storage controller information based on config type
            if config_type in ['ahci', 'efiahci']:
                controller = 'ahci'
            else:
                controller = 'piix3ide'

            storage_settings = {
                "Port0/ModelNumber": "Hitachi HTS543230AAA384",
                "Port0/FirmwareRevision": "ES2OA60W",
                "Port0/SerialNumber": ''.join(random.choices(string.ascii_uppercase + string.digits, k=17)),
                "Port1/ModelNumber": "Slimtype DVD A  DS8A8SH",
                "Port1/FirmwareRevision": "KAA2",
                "Port1/SerialNumber": ''.join(random.choices(string.ascii_uppercase + string.digits, k=16)),
                "Port1/ATAPIVendorId": "Slimtype",
                "Port1/ATAPIProductId": "DVD A  DS8A8SH",
                "Port1/ATAPIRevision": "KAA2"
            }
            for key, value in storage_settings.items():
                self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/Devices/{controller}/0/Config/{key}" "{value}"')

            # Set ACPI and other VM settings
            self.vboxmanage(f'setextradata "{vm_name}" "VBoxInternal/Devices/acpi/0/Config/AcpiOemId" "{self.acpi_oem_id.get()}"')
            self.vboxmanage(f'modifyvm "{vm_name}" --macaddress1 {self.mac_address.get()}')
            self.vboxmanage(f'modifyvm "{vm_name}" --paravirtprovider {self.paravirt_provider.get()}')
            
            if self.bios_logo_path.get():
                self.vboxmanage(f'modifyvm "{vm_name}" --bioslogoimagepath "{self.bios_logo_path.get()}"')

            # Set various VM options
            vm_options = [
                "--hwvirtex on", "--vtxvpid on", "--vtxux on", "--apic on",
                "--pae on", "--longmode on", "--hpet on", "--nestedpaging on",
                "--largepages on", f"--graphicscontroller {self.graphics_controller.get()}", "--mouse ps2"
            ]
            for option in vm_options:
                self.vboxmanage(f'modifyvm "{vm_name}" {option}')

            # Set file paths for ACPI tables and BIOS
            file_paths = {
                "VBoxInternal/Devices/acpi/0/Config/DsdtFilePath": "ACPI-DSDT.bin",
                "VBoxInternal/Devices/acpi/0/Config/SsdtFilePath": "ACPI-SSDT.bin",
                "VBoxInternal/Devices/vga/0/Config/BiosRom": "vgabios386.bin",
                "VBoxInternal/Devices/pcbios/0/Config/BiosRom": "pcbios386.bin"
            }
            for key, value in file_paths.items():
                full_path = os.path.join(config_dir, value)
                self.vboxmanage(f'setextradata "{vm_name}" "{key}" "{full_path}"')

            self.log("VM configuration completed successfully.")
        except subprocess.CalledProcessError as e:
            self.log(f"Error configuring VM: {e.stderr}")

    def start_monitoring(self):
        if not is_admin():
            messagebox.showerror("Error", "Administrative privileges are required.")
            return

        loader_path = os.path.join(os.getcwd(), 'Binary', 'loader.exe')
        command = f'"{loader_path}"'

        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True, shell=True)
            self.log(f"Monitoring started:\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            self.log(f"Error starting monitoring: {e.stderr}")

    def stop_monitoring(self):
        if not is_admin():
            messagebox.showerror("Error", "Administrative privileges are required.")
            return

        loader_path = os.path.join(os.getcwd(), 'Binary', 'loader.exe')
        command = f'"{loader_path}" /s'

        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True, shell=True)
            self.log(f"Monitoring stopped:\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            self.log(f"Error stopping monitoring: {e.stderr}")

    def show_vbox_version(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox")
            version = winreg.QueryValueEx(key, "VersionExt")[0]
            winreg.CloseKey(key)
            self.log(f"VirtualBox Version: {version}")
        except WindowsError:
            self.log("Unable to retrieve VirtualBox version.")

    def vboxmanage(self, command):
        vboxmanage_path = os.path.join(self.vbox_path.get(), "VBoxManage.exe")
        full_command = f'"{vboxmanage_path}" {command}'
        result = subprocess.run(full_command, check=True, capture_output=True, text=True, shell=True)
        self.log(f"Executed: {full_command}")
        if result.stdout:
            self.log(f"Output: {result.stdout}")

    def save_settings(self):
        settings = {
            "vbox_path": self.vbox_path.get(),
            "vm_name": self.vm_name.get(),
            "config_dir": self.config_dir.get(),
            "vm_config_type": self.vm_config_type.get(),
            "mac_address": self.mac_address.get(),
            "acpi_oem_id": self.acpi_oem_id.get(),
            "paravirt_provider": self.paravirt_provider.get(),
            "graphics_controller": self.graphics_controller.get(),
            "bios_vendor": self.bios_vendor.get(),
            "bios_version": self.bios_version.get(),
            "system_vendor": self.system_vendor.get(),
            "system_product": self.system_product.get(),
            "bios_logo_path": self.bios_logo_path.get()
        }
        with open("vbox_hardened_loader_settings.json", "w") as f:
            json.dump(settings, f)
        self.log("Settings saved successfully.")

    def load_settings(self):
        try:
            with open("vbox_hardened_loader_settings.json", "r") as f:
                settings = json.load(f)
            for key, value in settings.items():
                if hasattr(self, key):
                    getattr(self, key).set(value)
            self.log("Settings loaded successfully.")
        except FileNotFoundError:
            self.log("No saved settings found.")
        except json.JSONDecodeError:
            self.log("Error loading settings: Invalid JSON file.")

    def generate_random_profile(self):
        vendors = ["Asus", "Dell", "HP", "Lenovo", "Acer", "Toshiba", "Sony"]
        products = ["Laptop", "Desktop", "Workstation", "Ultrabook", "Gaming PC"]
        
        self.bios_vendor.set(random.choice(vendors))
        self.bios_version.set(f"{random.randint(1, 9)}.{random.randint(10, 99)}.{random.randint(1000, 9999)}")
        self.system_vendor.set(random.choice(vendors))
        self.system_product.set(f"{random.choice(products)}-{random.randint(1000, 9999)}")
        self.acpi_oem_id.set(self.system_vendor.get().upper()[:4])
        self.randomize_mac()
        
        self.log("Random profile generated.")

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)


if __name__ == "__main__":
    if is_admin():
        root = tk.Tk()
        app = VBoxHardenedLoaderGUI(root)
        root.mainloop()
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
