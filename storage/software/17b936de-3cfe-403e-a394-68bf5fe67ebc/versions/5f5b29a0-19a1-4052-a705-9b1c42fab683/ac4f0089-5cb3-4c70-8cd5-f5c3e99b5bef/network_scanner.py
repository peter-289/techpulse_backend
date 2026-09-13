# netscan_gui.py
import asyncio
import ipaddress
import json
import os
import random
import ssl
from typing import Optional, Any
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys

@dataclass
class ScanResult:
    ip: str
    port: int
    service: str = "unknown"
    raw_banner: str = ""
    cert_info: Optional[dict] = None
    probe_details: Optional[dict] = None

@dataclass
class ScanConfig:
    network: str
    ports: list[int]
    timeout: float
    global_concurrency: int = 80
    per_host_concurrency: int = 6
    min_host_delay: float = 0.08
    max_host_delay: float = 0.45
    min_port_jitter: float = 0.005
    max_port_jitter: float = 0.070
    shuffle_hosts: bool = True
    shuffle_ports: bool = True

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("780x620")
        self.root.resizable(True, True)

        # ── Set window icon from the executable itself (works in --onefile) ──
        try:
            self.root.iconbitmap(sys.executable)
        except tk.TclError:
            # Fallback: silent fail or use default (dev mode shows Tk feather)
            pass

        self.scan_thread = None
        self.loop = None
        # use a thread-safe event for cross-thread cancellation
        self.cancel_event = threading.Event()
        self.results = []
        self.is_scanning = False

        self._build_ui()

    def _build_ui(self):
        main_frame = ttk.Frame(self.root, padding="12 12 12 12")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ── Input Section ───────────────────────────────────────
        input_frame = ttk.LabelFrame(main_frame, text="Scan Settings", padding="10 10 10 10")
        input_frame.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(input_frame, text="Network (CIDR):").grid(row=0, column=0, sticky=tk.W, pady=4)
        self.net_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(input_frame, textvariable=self.net_var, width=32).grid(row=0, column=1, sticky=tk.W)

        ttk.Label(input_frame, text="Ports (comma sep):").grid(row=1, column=0, sticky=tk.W, pady=4)
        self.ports_var = tk.StringVar(value="22,80,443,445,3389")
        ttk.Entry(input_frame, textvariable=self.ports_var, width=32).grid(row=1, column=1, sticky=tk.W)

        ttk.Label(input_frame, text="Timeout (seconds):").grid(row=2, column=0, sticky=tk.W, pady=4)
        self.timeout_var = tk.DoubleVar(value=2.8)
        ttk.Spinbox(input_frame, from_=0.5, to=10.0, increment=0.5, textvariable=self.timeout_var, width=8).grid(row=2, column=1, sticky=tk.W)

        ttk.Label(input_frame, text="Slow mode (evasion):").grid(row=3, column=0, sticky=tk.W, pady=4)
        self.slow_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, variable=self.slow_var, command=self._update_timing_labels).grid(row=3, column=1, sticky=tk.W)

        # consent checkbox
        self.consent_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, text="I have permission to scan these targets", variable=self.consent_var).grid(row=5, column=1, sticky=tk.W, pady=(6,0))

        # Aggression level
        ttk.Label(input_frame, text="Aggression:").grid(row=6, column=0, sticky=tk.W, pady=4)
        self.aggr_var = tk.StringVar(value="Normal")
        ttk.Combobox(input_frame, textvariable=self.aggr_var, values=["Conservative", "Normal", "Aggressive"], width=12, state="readonly").grid(row=6, column=1, sticky=tk.W)

        self.timing_label = ttk.Label(input_frame, text="Host delay ≈ 0.08 – 0.45 s")
        self.timing_label.grid(row=4, column=1, sticky=tk.W, pady=(0,6))

        # ── Control Buttons ─────────────────────────────────────
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=8)

        self.start_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan, width=14)
        self.start_btn.pack(side=tk.LEFT, padx=6)

        self.stop_btn = ttk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED, width=14)
        self.stop_btn.pack(side=tk.LEFT, padx=6)

        ttk.Button(btn_frame, text="Clear", command=self.clear_output).pack(side=tk.LEFT, padx=6)

        # ── Status & Progress ───────────────────────────────────
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10 10 10 10")
        status_frame.pack(fill=tk.X, pady=(0,10))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)

        self.progress = ttk.Progressbar(status_frame, mode="indeterminate", length=400)
        self.progress.pack(fill=tk.X, pady=(6,0))

        # ── Output Area ─────────────────────────────────────────
        output_frame = ttk.LabelFrame(main_frame, text="Results", padding="10 10 10 10")
        output_frame.pack(fill=tk.BOTH, expand=True)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=14, font=("Consolas", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)

        self.report_path_var = tk.StringVar(value="Reports will be saved here after scan")
        ttk.Label(main_frame, textvariable=self.report_path_var, wraplength=740, justify="left").pack(pady=(8,0))

    def _update_timing_labels(self):
        if self.slow_var.get():
            self.timing_label.config(text="Host delay ≈ 0.4 – 1.8 s  (paranoid)")
        else:
            self.timing_label.config(text="Host delay ≈ 0.08 – 0.45 s")

    def log(self, msg: str):
        self.output_text.insert(tk.END, msg + "\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()

    def start_scan(self):
        if self.is_scanning:
            return

        #if not self.consent_var.get():
        #   messagebox.showwarning("Consent required", "Please confirm you have permission to scan these targets.")
        #   return

        network = self.net_var.get().strip()
        ports_str = self.ports_var.get().strip()

        if not network or not ports_str:
            messagebox.showwarning("Input Error", "Network and ports are required.")
            return

        try:
            ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
            if not ports:
                raise ValueError
        except:
            messagebox.showerror("Invalid Ports", "Ports must be comma-separated numbers.")
            return

        timeout = self.timeout_var.get()
        slow = self.slow_var.get()
        aggr = self.aggr_var.get()

        # map aggression presets
        if aggr == "Conservative":
            gc = 20; phc = 2; min_hd = 0.6; max_hd = 2.2; min_j = 0.02; max_j = 0.12
        elif aggr == "Aggressive":
            gc = 160; phc = 10; min_hd = 0.02; max_hd = 0.12; min_j = 0.001; max_j = 0.02
        else:
            gc = 80; phc = 6; min_hd = 0.4 if slow else 0.08; max_hd = 1.8 if slow else 0.45; min_j = 0.005; max_j = 0.07

        config = ScanConfig(
            network=network,
            ports=ports,
            timeout=timeout,
            min_host_delay=min_hd,
            max_host_delay=max_hd,
            min_port_jitter=min_j,
            max_port_jitter=max_j,
            global_concurrency=gc,
            per_host_concurrency=phc,
        )

        self.results.clear()
        self.output_text.delete("1.0", tk.END)
        self.report_path_var.set("Scanning...")
        self.status_var.set("Preparing scan...")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(12)
        self.is_scanning = True

        self.scan_thread = threading.Thread(target=self._run_async_scan, args=(config,), daemon=True)
        self.scan_thread.start()

    def _run_async_scan(self, config: ScanConfig):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._async_scan(config))
        except Exception as e:
            self.root.after(0, lambda: self.log(f"ERROR: {e}"))
        finally:
            self.loop.close()
            self.root.after(0, self._scan_finished)

    async def _async_scan(self, config: ScanConfig):
        self.cancel_event.clear()

        hosts = list(ipaddress.ip_network(config.network, strict=False).hosts())
        if config.shuffle_hosts:
            random.shuffle(hosts)
        hosts = [str(h) for h in hosts]

        total_hosts = len(hosts)
        self.root.after(0, lambda: self.status_var.set(f"Scanning {total_hosts} hosts..."))

        sem_global = asyncio.Semaphore(config.global_concurrency)
        results = []

        async def scan_one_host(ip):
            if self.cancel_event.is_set():
                return
            self.root.after(0, lambda: self.status_var.set(f"Scanning {ip} ({len(results)} open found)"))
            await asyncio.sleep(random.uniform(config.min_host_delay, config.max_host_delay))

            sem_host = asyncio.Semaphore(config.per_host_concurrency)
            ports = config.ports[:]
            if config.shuffle_ports:
                random.shuffle(ports)

            tasks = []
            for port in ports:
                if self.cancel_event.is_set():
                    break
                await asyncio.sleep(random.uniform(config.min_port_jitter, config.max_port_jitter))
                tasks.append(self._scan_port(ip, port, config, sem_global, sem_host, results))

            await asyncio.gather(*tasks, return_exceptions=True)

        async def progress_reporter():
            while not self.cancel_event.is_set():
                await asyncio.sleep(1.5)
                self.root.after(0, lambda: self.status_var.set(f"Scanning... {len(results)} open ports"))

        reporter_task = asyncio.create_task(progress_reporter())

        host_tasks = [asyncio.create_task(scan_one_host(ip)) for ip in hosts]
        await asyncio.wait(host_tasks, return_when=asyncio.FIRST_COMPLETED if self.cancel_event.is_set() else asyncio.ALL_COMPLETED)

        reporter_task.cancel()
        self.results = sorted(results, key=lambda r: (r.ip, r.port))

    async def _scan_port(self, ip, port, config, sem_g, sem_h, results):
        async with sem_g, sem_h:
            if self.cancel_event.is_set():
                return
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=config.timeout
                )
                service, raw_banner, cert_info, probe_details = await self._detect_service(reader, writer, ip, port, config.timeout)
                result = ScanResult(ip, port, service, raw_banner=raw_banner, cert_info=cert_info, probe_details=probe_details)
                results.append(result)
                self.root.after(0, lambda: self.log(f"[OPEN] {ip:15}:{port:5} → {service}"))
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _detect_service(self, reader, writer, ip, port, timeout) -> tuple:
        raw_banner = ""
        cert_info = None
        probe_details = {}
        service_name = "unknown"

        # try banner grab
        try:
            banner = await asyncio.wait_for(reader.read(2048), 1.1)
            text = banner.decode(errors="ignore").strip()
            if text:
                raw_banner = text.replace("\n", " ").replace("\r", " ")
                probe_details.setdefault('banner', raw_banner)
                # common banner-based detections
                low = raw_banner.lower()
                if 'ssh-' in low:
                    service_name = 'ssh'
                elif 'ftp' in low:
                    service_name = 'ftp'
                elif 'smtp' in low or 'esmtp' in low:
                    service_name = 'smtp'
                elif 'http' in low or 'html' in low:
                    service_name = 'http'
        except:
            pass

        # HTTP probe (send HEAD) for common http ports
        if service_name in {'unknown', 'http'} and port in {80, 8080, 8000, 443, 8443}:
            try:
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: netscan/1.0\r\nConnection: close\r\n\r\n"
                writer.write(req.encode())
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(2048), 1.1)
                txt = resp.decode(errors='ignore')
                if txt:
                    probe_details['http_headers'] = txt.splitlines()[:6]
                    service_name = 'http'
            except:
                pass

        # TLS probe: attempt an SSL handshake to gather certs
        if port in {443, 8443, 9443}:
            try:
                ctx = ssl.create_default_context()
                r2, w2 = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip), timeout)
                sslobj = w2.get_extra_info('ssl_object')
                if sslobj is not None:
                    cert = sslobj.getpeercert()
                    cert_info = {
                        'subject': cert.get('subject'),
                        'issuer': cert.get('issuer'),
                        'notAfter': cert.get('notAfter')
                    }
                    probe_details['tls'] = {'has_cert': True}
                    service_name = 'https'
                w2.close()
                try:
                    await w2.wait_closed()
                except:
                    pass
            except:
                pass

        # SMTP probe
        if service_name in {'unknown', 'smtp'} and port in {25, 587, 2525}:
            try:
                # banner likely already read; send EHLO
                writer.write(b"EHLO scanner.local\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), 1.1)
                txt = resp.decode(errors='ignore').strip()
                if txt:
                    probe_details['smtp'] = txt.splitlines()[:6]
                    service_name = 'smtp'
            except:
                pass

        # FTP minimal probe
        if service_name in {'unknown', 'ftp'} and port == 21:
            if raw_banner:
                service_name = 'ftp'

        # SSH fallback (banner)
        if service_name == 'unknown' and port == 22 and raw_banner:
            service_name = 'ssh'

        return service_name, raw_banner, cert_info, probe_details

    def stop_scan(self):
        if not self.is_scanning:
            return
        self.cancel_event.set()
        self.status_var.set("Stopping scan (may take a few seconds)...")
        self.log("→ Cancellation requested...")

    def _scan_finished(self):
        self.is_scanning = False
        self.progress.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        if not self.results:
            self.status_var.set("Scan finished — no open ports found")
            self.log("No open services discovered.")
        else:
            self.status_var.set(f"Scan finished — {len(self.results)} open ports/services found")

        txt_path, json_path, json_ext = self._save_results()
        self.report_path_var.set(f"Results saved to:\n{txt_path}\n{json_path}\n{json_ext}")
        self.log(f"\nReports saved:\n  {txt_path}\n  {json_path}\n  {json_ext}")

    def _save_results(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_file = f"scan_{ts}.txt"
        json_file = f"scan_{ts}_summary.json"
        json_ext = f"scan_{ts}_extended.json"

        with open(txt_file, "w", encoding="utf-8") as f:
            for r in self.results:
                f.write(f"{r.ip}:{r.port:5} → {r.service}\n")

        # write a compact summary JSON and a full extended JSON with banners/certs
        summary = [{'ip': r.ip, 'port': r.port, 'service': r.service} for r in self.results]
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        with open(json_ext, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in self.results], f, indent=2)

        return os.path.abspath(txt_file), os.path.abspath(json_file), os.path.abspath(json_ext)

    def clear_output(self):
        self.output_text.delete("1.0", tk.END)

def main():
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()