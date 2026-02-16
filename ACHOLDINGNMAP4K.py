import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import time

class ACNMpScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("ACNMp 1.x - Network Scanner")
        self.root.geometry("600x500")
        
        # Variables
        self.target_ip = tk.StringVar()
        self.start_port = tk.IntVar()
        self.end_port = tk.IntVar()
        self.scanning = False
        
        # UI Layout
        self.create_widgets()
        
    def create_widgets(self):
        # Input Frame
        input_frame = tk.LabelFrame(self.root, text="Target Configuration", padx=10, pady=10)
        input_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(input_frame, text="Target IP / Hostname:").grid(row=0, column=0, sticky="w")
        tk.Entry(input_frame, textvariable=self.target_ip, width=40).grid(row=0, column=1, padx=5, pady=2)
        
        tk.Label(input_frame, text="Start Port:").grid(row=1, column=0, sticky="w")
        tk.Entry(input_frame, textvariable=self.start_port, width=10).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        self.start_port.set(1)
        
        tk.Label(input_frame, text="End Port:").grid(row=1, column=2, sticky="w")
        tk.Entry(input_frame, textvariable=self.end_port, width=10).grid(row=1, column=3, sticky="w", padx=5, pady=2)
        self.end_port.set(1024)
        
        # Buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)
        
        # Updated Button Colors: Black Background, Blue Text
        self.start_btn = tk.Button(btn_frame, text="Start Scan", command=self.start_scan, bg="black", fg="blue")
        self.start_btn.pack(side="left", padx=10)
        
        self.stop_btn = tk.Button(btn_frame, text="Stop", command=self.stop_scan, state="disabled", bg="black", fg="blue")
        self.stop_btn.pack(side="left", padx=10)
        
        # Output Log
        tk.Label(self.root, text="Scan Results:").pack(anchor="w", padx=10)
        self.log_area = scrolledtext.ScrolledText(self.root, height=20, state='disabled')
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill="x", side="bottom")

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                self.log(f"[+] Port {port} is OPEN")
            sock.close()
        except Exception as e:
            pass

    def run_scan(self):
        ip = self.target_ip.get()
        start = self.start_port.get()
        end = self.end_port.get()
        
        if not ip:
            messagebox.showerror("Error", "Please enter a target IP or Hostname")
            self.reset_ui()
            return
            
        self.log(f"--- Starting ACNMp 1.x Scan on {ip} ---")
        self.log(f"Range: {start} - {end}")
        self.status_var.set(f"Scanning {ip}...")
        
        for port in range(start, end + 1):
            if not self.scanning:
                break
            self.scan_port(ip, port)
            time.sleep(0.01) 
            
        self.log("--- Scan Complete ---")
        self.status_var.set("Ready")
        self.reset_ui()

    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.log_area.delete('1.0', tk.END)
            
            thread = threading.Thread(target=self.run_scan)
            thread.daemon = True
            thread.start()

    def stop_scan(self):
        self.scanning = False
        self.log("Stopping scan...")
        self.status_var.set("Stopping...")

    def reset_ui(self):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.scanning = False

if __name__ == "__main__":
    root = tk.Tk()
    app = ACNMpScanner(root)
    root.mainloop()