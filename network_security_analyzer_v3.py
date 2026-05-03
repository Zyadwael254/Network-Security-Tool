#!/usr/bin/env python3
"""
NetSec Analyzer  ·  v3.0  —  Enterprise Cybersecurity Dashboard
Design system: Cortex / Splunk inspired. Python 3.7+ / Tkinter.
Backend logic is 100% unchanged.
"""

import json
import math
import ipaddress
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import threading


# ══════════════════════════════════════════════════════════════════════════════
#  BACKEND  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

class NetworkSecurityAnalyzer:
    def __init__(self, data):
        self.data = data; self.findings = []; self.score = 100; self.deductions = []

    def analyze(self):
        self._extract_devices()
        self.check_ip_validity(); self.check_secure_protocols()
        self.check_network_segmentation(); self.check_default_gateway()
        self.check_acl_presence(); self.check_firewall_placement()
        self.check_device_hardening(); self.check_monitoring_redundancy()
        self.check_vlan_configuration(); self.check_weak_credentials()
        self.check_open_ports(); self.check_encryption_at_rest()
        self.check_ntp_dns_security()
        self.score = max(0, self.score)
        return self.findings, self.score

    def _extract_devices(self):
        self.devices = []; d = self.data
        if "devices" in d and isinstance(d["devices"], list): self.devices = d["devices"]
        elif "nodes" in d and isinstance(d["nodes"], list): self.devices = d["nodes"]
        elif "network" in d:
            net = d["network"]
            if isinstance(net, dict): self.devices = net.get("devices", net.get("nodes", []))
        elif "topology" in d:
            topo = d["topology"]
            if isinstance(topo, dict): self.devices = topo.get("nodes", topo.get("devices", []))
        elif isinstance(d, list): self.devices = d
        self.connections = d.get("connections", d.get("links", d.get("edges", [])))
        self.acls = d.get("acls", d.get("access_lists", []))
        self.vlans = d.get("vlans", [])
        self.firewalls = [dev for dev in self.devices
                          if "firewall" in str(dev.get("type","")).lower()
                          or "fw" in str(dev.get("name","")).lower()]

    def _add(self, category, level, title, detail, fix=""):
        penalty = {"CRITICAL":15,"HIGH":10,"MEDIUM":5,"LOW":2,"INFO":0,"PASS":0}
        self.score -= penalty.get(level, 0)
        self.findings.append({"category":category,"level":level,"title":title,"detail":detail,"fix":fix})

    def _is_private(self, ip_str):
        try: return ipaddress.ip_address(ip_str).is_private
        except: return False

    def _valid_ip(self, ip_str):
        try: ipaddress.ip_address(ip_str.split("/")[0]); return True
        except: return False

    def check_ip_validity(self):
        invalid, pub = [], []
        for dev in self.devices:
            ip = dev.get("ip", dev.get("ip_address", dev.get("management_ip","")))
            if not ip: continue
            if not self._valid_ip(ip): invalid.append(f"{dev.get('name','?')} → {ip}")
            elif not self._is_private(ip.split("/")[0]): pub.append(f"{dev.get('name','?')} → {ip}")
        if invalid: self._add("IP Validation","CRITICAL","Invalid IP Addresses Detected",f"Devices with invalid IPs: {', '.join(invalid)}","Correct IP addresses to valid IPv4/IPv6 format.")
        else: self._add("IP Validation","PASS","All IP Addresses Valid","Every device has a well-formed IP address.")
        if pub: self._add("IP Validation","HIGH","Public IPs Used Internally",f"Devices using routable IPs inside private network: {', '.join(pub)}","Use RFC 1918 private address space (10.x, 172.16-31.x, 192.168.x).")
        ips = []
        for dev in self.devices:
            ip = dev.get("ip", dev.get("ip_address", dev.get("management_ip","")))
            if ip: ips.append(ip.split("/")[0])
        dups = [ip for ip in set(ips) if ips.count(ip) > 1]
        if dups: self._add("IP Validation","HIGH","Duplicate IP Addresses",f"Duplicate IPs found: {', '.join(set(dups))}","Assign unique IP addresses to each device.")

    def check_secure_protocols(self):
        insecure = {"telnet":23,"ftp":21,"http":80,"snmpv1":161,"snmpv2":161,"rsh":514,"rlogin":513}
        secure_ok = {"ssh":22,"https":443,"sftp":22,"snmpv3":161,"tls":443}
        found_insecure, found_secure = [], []
        for dev in self.devices:
            protos = dev.get("protocols", dev.get("services", dev.get("allowed_protocols",[])))
            ports = dev.get("open_ports", dev.get("ports",[]))
            name = dev.get("name","Unknown")
            if isinstance(protos, list):
                for p in protos:
                    pl = str(p).lower()
                    for ins in insecure:
                        if ins in pl: found_insecure.append(f"{name} uses {p}")
                    for sec in secure_ok:
                        if sec in pl: found_secure.append(f"{name} uses {p}")
            if isinstance(ports, list):
                for port in ports:
                    if int(str(port)) in insecure.values(): found_insecure.append(f"{name} has open port {port}")
        if found_insecure: self._add("Protocol Security","CRITICAL","Insecure Protocols Detected",f"Found: {'; '.join(found_insecure[:8])}","Replace Telnet→SSH, FTP→SFTP, HTTP→HTTPS, SNMPv1/v2→SNMPv3.")
        elif found_secure: self._add("Protocol Security","PASS","Secure Protocols in Use",f"Secure protocols confirmed: {', '.join(found_secure[:5])}")
        else: self._add("Protocol Security","INFO","No Protocol Data Found","JSON doesn't specify protocols. Ensure SSH/HTTPS are enforced.","Add 'protocols' field to each device in your JSON schema.")

    def check_network_segmentation(self):
        subnets, zones = set(), set()
        for dev in self.devices:
            ip = dev.get("ip", dev.get("ip_address",""))
            if ip and "/" in ip:
                try: subnets.add(str(ipaddress.ip_interface(ip).network))
                except: pass
            zone = dev.get("zone", dev.get("segment", dev.get("vlan","")))
            if zone: zones.add(str(zone))
        if len(subnets) >= 3 or len(zones) >= 2: self._add("Segmentation","PASS","Network Segmentation Detected",f"Found {len(subnets)} subnets and {len(zones)} security zones.")
        elif len(subnets) == 2 or len(zones) == 1: self._add("Segmentation","MEDIUM","Minimal Segmentation","Only basic segmentation found. Consider more zones.","Add DMZ, IoT VLAN, Management VLAN, and Guest VLAN at minimum.")
        else: self._add("Segmentation","HIGH","No Network Segmentation","All devices appear to be on a flat network.","Implement VLANs: DMZ (10.0.1.0/24), Internal (10.0.2.0/24), Management (10.0.3.0/24).")
        has_dmz = any("dmz" in str(dev.get("zone","")).lower() or "dmz" in str(dev.get("name","")).lower() or "dmz" in str(dev.get("segment","")).lower() for dev in self.devices)
        if not has_dmz: self._add("Segmentation","MEDIUM","No DMZ Defined","Public-facing services should reside in a DMZ segment.","Create a DMZ zone for web servers, mail servers, and DNS resolvers.")

    def check_default_gateway(self):
        gw_found = []
        for dev in self.devices:
            gw = dev.get("default_gateway", dev.get("gateway", dev.get("gw","")))
            if gw:
                gw_found.append((dev.get("name","?"), gw))
                if not self._valid_ip(gw): self._add("Gateway","HIGH","Invalid Default Gateway",f"Device {dev.get('name','?')} has invalid gateway: {gw}","Set a valid gateway IP reachable on the same subnet.")
        top_gw = self.data.get("default_gateway", self.data.get("gateway",""))
        if top_gw and self._valid_ip(top_gw): gw_found.append(("topology", top_gw))
        if gw_found: self._add("Gateway","PASS","Default Gateway Configured",f"Gateway entries found: {len(gw_found)}")
        else: self._add("Gateway","MEDIUM","Default Gateway Not Specified","No default gateway found in the topology.","Define 'default_gateway' for each device or globally in the JSON.")

    def check_acl_presence(self):
        acl_refs = []
        for dev in self.devices:
            acl = dev.get("acl", dev.get("access_list", dev.get("acls",[])))
            if acl: acl_refs.append(dev.get("name","?"))
        total = len(self.acls) + len(acl_refs)
        if total == 0: self._add("ACL","HIGH","No ACLs Defined","Access Control Lists are missing from the topology.","Apply ACLs on router/switch interfaces. Use deny-all-permit-specific approach.")
        elif total < len(self.devices) // 2: self._add("ACL","MEDIUM","Insufficient ACL Coverage",f"Only {total} ACL references for {len(self.devices)} devices.","Apply ACLs on all inter-zone boundaries and perimeter interfaces.")
        else: self._add("ACL","PASS","ACLs Present",f"Found {total} ACL configuration(s).")

    def check_firewall_placement(self):
        if not self.firewalls:
            self._add("Firewall","CRITICAL","No Firewall Detected","The topology contains no firewall device.","Add a perimeter firewall between Internet and internal zones. Consider also an internal firewall."); return
        internet_fw = any("internet" in str(fw.get("connected_to","")).lower() or "wan" in str(fw.get("interface","")).lower() or "edge" in str(fw.get("name","")).lower() or "perimeter" in str(fw.get("role","")).lower() for fw in self.firewalls)
        if internet_fw: self._add("Firewall","PASS","Perimeter Firewall Detected",f"{len(self.firewalls)} firewall(s) found including perimeter placement.")
        else: self._add("Firewall","MEDIUM","Firewall Not at Perimeter",f"Found {len(self.firewalls)} firewall(s) but none confirmed at Internet edge.","Ensure firewall is placed between Internet router and internal network.")
        if len(self.firewalls) == 1: self._add("Firewall","LOW","Single Firewall — No HA","Only one firewall. No redundancy.","Add a secondary firewall in active-standby or active-active HA mode.")

    def check_device_hardening(self):
        issues = []
        for dev in self.devices:
            name = dev.get("name","Unknown")
            creds = dev.get("credentials", dev.get("auth",{}))
            if isinstance(creds, dict):
                u = str(creds.get("username","")).lower(); p = str(creds.get("password","")).lower()
                if u in ("admin","root","cisco","user","administrator") and p in ("admin","password","cisco","123456",""): issues.append(f"{name}: default credentials")
            if not dev.get("banner") and not dev.get("motd"): issues.append(f"{name}: no login banner")
            services = dev.get("services",[])
            dangerous = [s for s in services if str(s).lower() in ("http","finger","bootp","tftp")]
            if dangerous: issues.append(f"{name}: unnecessary services {dangerous}")
            if dev.get("password_encryption") is False: issues.append(f"{name}: password encryption disabled")
        if issues:
            shown = issues[:6]; extra = len(issues) - 6
            self._add("Hardening","HIGH","Device Hardening Issues","; ".join(shown) + (f" (+{extra} more)" if extra > 0 else ""),"Apply CIS benchmarks: change defaults, enable service password-encryption, set login banners, disable unused services.")
        else: self._add("Hardening","PASS","No Obvious Hardening Issues","Devices appear to have basic hardening applied.")

    def check_monitoring_redundancy(self):
        has_syslog = any(dev.get("syslog") or dev.get("logging") for dev in self.devices)
        has_snmp = any(dev.get("snmp") for dev in self.devices)
        has_nms = any("nms" in str(dev.get("type","")).lower() or "siem" in str(dev.get("type","")).lower() or "monitor" in str(dev.get("role","")).lower() for dev in self.devices)
        if has_syslog and has_snmp: self._add("Monitoring","PASS","Logging and SNMP Configured","Syslog and SNMP monitoring detected.")
        elif has_syslog or has_snmp: self._add("Monitoring","MEDIUM","Partial Monitoring","Either Syslog or SNMP is missing.","Implement both: Syslog for event logging, SNMPv3 for performance monitoring.")
        else: self._add("Monitoring","HIGH","No Monitoring Configured","No Syslog, SNMP, or NMS device found.","Deploy centralized Syslog server, SNMPv3 polling, and a SIEM/NMS.")
        if not has_nms: self._add("Monitoring","MEDIUM","No NMS/SIEM Device","Network Management System or SIEM not found in topology.","Add a dedicated monitoring server (e.g., Nagios, Zabbix, Splunk).")
        routers = [d for d in self.devices if "router" in str(d.get("type","")).lower()]
        has_hsrp = any(d.get("hsrp") or d.get("vrrp") or d.get("glbp") for d in self.devices)
        if len(routers) >= 2: self._add("Redundancy","PASS","Router Redundancy Present",f"{len(routers)} routers detected.")
        else: self._add("Redundancy","MEDIUM","Single Router — No Redundancy","Only one router found. This is a single point of failure.","Add secondary router with HSRP/VRRP for gateway redundancy.")
        if not has_hsrp: self._add("Redundancy","LOW","No HSRP/VRRP Configured","No gateway redundancy protocol detected.","Configure HSRP or VRRP on core routers for gateway failover.")

    def check_vlan_configuration(self):
        if not self.vlans and not any(dev.get("vlan") for dev in self.devices):
            self._add("VLAN","MEDIUM","No VLAN Configuration","VLANs are not defined in the topology.","Implement VLANs for traffic isolation: Management VLAN, User VLAN, Server VLAN, DMZ VLAN."); return
        vlan1 = [dev.get("name","?") for dev in self.devices if str(dev.get("vlan","")) == "1"]
        if vlan1: self._add("VLAN","HIGH","VLAN 1 in Use (Default VLAN)",f"Devices on VLAN 1: {', '.join(vlan1)}","Avoid VLAN 1. Move devices to named VLANs and disable VLAN 1 on all trunk ports.")
        else: self._add("VLAN","PASS","VLANs Properly Configured","VLAN segmentation is present and VLAN 1 is not in use.")

    def check_weak_credentials(self):
        weak = {"admin","password","cisco","root","123456","pass","qwerty","letmein","welcome","test"}
        issues = []
        for dev in self.devices:
            creds = dev.get("credentials", dev.get("auth",{}))
            if isinstance(creds, dict):
                for field in ("password","secret","enable_password","enable_secret"):
                    val = str(creds.get(field,"")).lower()
                    if val and val in weak: issues.append(f"{dev.get('name','?')}: weak {field}")
            if str(dev.get("enable_password","")).lower() in weak: issues.append(f"{dev.get('name','?')}: weak enable password")
        if issues: self._add("Credentials","CRITICAL","Weak/Default Credentials Found",f"Affected: {'; '.join(issues[:5])}","Use strong passwords (12+ chars, mixed case, symbols). Enable AAA with RADIUS/TACACS+.")
        else: self._add("Credentials","PASS","No Obvious Weak Credentials","No default or common passwords detected in JSON.")

    def check_open_ports(self):
        risky = {21:"FTP",23:"Telnet",513:"rlogin",514:"rsh",80:"HTTP",161:"SNMP",69:"TFTP",111:"RPC",135:"MSRPC"}
        found = []
        for dev in self.devices:
            ports = dev.get("open_ports", dev.get("ports",[]))
            if isinstance(ports, list):
                for p in ports:
                    try:
                        n = int(str(p))
                        if n in risky: found.append(f"{dev.get('name','?')}:{n}({risky[n]})")
                    except: pass
        if found: self._add("Port Security","HIGH","Risky Ports Exposed",f"Exposed risky services: {', '.join(found[:6])}","Close unused ports. Use firewall rules to restrict access to management ports.")
        elif any(dev.get("open_ports") or dev.get("ports") for dev in self.devices): self._add("Port Security","PASS","No Risky Ports Detected","Open ports appear to be limited to secure services.")

    def check_encryption_at_rest(self):
        no_enc = [dev.get("name","?") for dev in self.devices if dev.get("encryption") is False or dev.get("disk_encryption") is False]
        has_enc = any(dev.get("encryption") is True or dev.get("disk_encryption") is True for dev in self.devices)
        if no_enc: self._add("Encryption","HIGH","Encryption Disabled",f"Devices with encryption off: {', '.join(no_enc)}","Enable encryption at rest on all storage devices. Use AES-256.")
        elif has_enc: self._add("Encryption","PASS","Encryption Enabled","Device-level encryption is configured.")
        else: self._add("Encryption","INFO","Encryption Status Unknown","No encryption configuration found in JSON.","Add 'encryption: true' to servers and storage nodes in your schema.")

    def check_ntp_dns_security(self):
        has_ntp = any(dev.get("ntp") or dev.get("ntp_server") for dev in self.devices)
        has_dns = any(dev.get("dns") or dev.get("dns_server") for dev in self.devices)
        if not has_ntp: self._add("Time/DNS","MEDIUM","NTP Not Configured","Synchronized time is critical for log correlation and certificate validity.","Configure NTP on all devices pointing to internal NTP server (stratum 2).")
        else: self._add("Time/DNS","PASS","NTP Configured","Time synchronization is set up.")
        if not has_dns: self._add("Time/DNS","LOW","DNS Not Specified","DNS configuration missing from topology.","Specify internal DNS servers. Consider DNS-over-TLS or DNSSEC.")
        else: self._add("Time/DNS","PASS","DNS Configured","DNS server is specified.")


# ══════════════════════════════════════════════════════════════════════════════
#  DESIGN SYSTEM  v3.0
#  Palette: Deep navy base · Slate panels · Electric blue accent
#  Inspired by: Palo Alto Cortex XDR · Darktrace · Splunk SIEM
# ══════════════════════════════════════════════════════════════════════════════

# ── Color tokens ──────────────────────────────────────────────────────────────
BG      = "#06090f"   # True dark base (almost black-blue)
SURFACE = "#0c1420"   # Card/panel surface
SURF2   = "#101c2e"   # Slightly elevated surface
SURF3   = "#152236"   # Hover / active surface
BORDER  = "#1a2d47"   # Default border
BORDER2 = "#1f3557"   # Stronger border / divider
ACCENT  = "#1a7cff"   # Primary blue (interactive)
ACCENT2 = "#0f5cd4"   # Pressed state
ACCENTG = "#0d3a8a"   # Ghost/subtle accent bg

TEXT_HI  = "#f0f4ff"  # Primary text (headings)
TEXT_MD  = "#8da3c0"  # Secondary text (labels)
TEXT_LO  = "#4a6480"  # Tertiary text (hints)
TEXT_INV = "#ffffff"  # On-accent text

# Semantic risk colors — calibrated for dark backgrounds
CLR = {
    "CRITICAL": "#f03e3e",   # Red
    "HIGH":     "#f76b15",   # Orange
    "MEDIUM":   "#e8b30a",   # Amber
    "LOW":      "#2dc78e",   # Teal-green
    "INFO":     "#3db8f5",   # Sky blue
    "PASS":     "#27c06a",   # Green
}

# Tinted backgrounds for severity chips
CLR_BG = {
    "CRITICAL": "#1f0a0a",
    "HIGH":     "#1e0f02",
    "MEDIUM":   "#1a1500",
    "LOW":      "#021910",
    "INFO":     "#011520",
    "PASS":     "#011a0d",
}

# Category display metadata
CAT_META = {
    "IP Validation":     {"icon": "IP",  "short": "IP Addr"},
    "Protocol Security": {"icon": "PR",  "short": "Protocols"},
    "Segmentation":      {"icon": "SG",  "short": "Segments"},
    "Gateway":           {"icon": "GW",  "short": "Gateway"},
    "ACL":               {"icon": "AC",  "short": "ACL"},
    "Firewall":          {"icon": "FW",  "short": "Firewall"},
    "Hardening":         {"icon": "HD",  "short": "Hardening"},
    "Monitoring":        {"icon": "MN",  "short": "Monitoring"},
    "Redundancy":        {"icon": "RD",  "short": "Redundancy"},
    "VLAN":              {"icon": "VL",  "short": "VLAN"},
    "Credentials":       {"icon": "CR",  "short": "Credentials"},
    "Port Security":     {"icon": "PT",  "short": "Ports"},
    "Encryption":        {"icon": "EN",  "short": "Encryption"},
    "Time/DNS":          {"icon": "TD",  "short": "Time/DNS"},
}

ALL_CATEGORIES = list(CAT_META.keys())

# ── Typography system ─────────────────────────────────────────────────────────
# Display: Segoe UI Semibold for headings
# Body: Segoe UI for readable text
# Mono: Consolas for technical data (IPs, configs)
T = {
    "display":   ("Segoe UI Semibold", 28, "bold"),  # Score number
    "h1":        ("Segoe UI", 13, "bold"),            # Section headers
    "h2":        ("Segoe UI", 11, "bold"),            # Card titles
    "label":     ("Segoe UI", 8,  "bold"),            # Caps labels / eyebrows
    "body":      ("Segoe UI", 9),                     # Body text
    "body_sm":   ("Segoe UI", 8),                     # Small body
    "mono":      ("Consolas", 9),                     # Technical data
    "mono_sm":   ("Consolas", 8),                     # Small technical
    "caption":   ("Segoe UI", 7,  "bold"),            # Chip labels
    "kpi":       ("Segoe UI Semibold", 20, "bold"),   # KPI numbers
}

# Spacing scale (px)
SP = {1: 2, 2: 4, 3: 8, 4: 12, 5: 16, 6: 20, 7: 24, 8: 32}

# ── Risk posture labels (refined copy) ────────────────────────────────────────
def score_meta(score):
    """Returns (color, posture_label, description)."""
    if score >= 85: return CLR["PASS"],     "PROTECTED",   "Low exposure detected"
    if score >= 70: return CLR["PASS"],     "SECURE",      "Minor issues present"
    if score >= 55: return CLR["MEDIUM"],   "MODERATE",    "Review recommended"
    if score >= 40: return CLR["HIGH"],     "ELEVATED",    "Action required"
    if score >= 20: return CLR["CRITICAL"], "VULNERABLE",  "Immediate action needed"
    return                  CLR["CRITICAL"], "COMPROMISED", "Critical exposure"


def cat_score(findings, cat):
    cats = [f for f in findings if f["category"] == cat]
    if not cats: return None
    pen = {"CRITICAL":100,"HIGH":70,"MEDIUM":40,"LOW":15,"INFO":0,"PASS":0}
    return max(0, 100 - max(pen.get(f["level"],0) for f in cats))


# ══════════════════════════════════════════════════════════════════════════════
#  COMPONENT LIBRARY
# ══════════════════════════════════════════════════════════════════════════════

def labeled_frame(parent, title=None, bg=SURFACE, border=BORDER, pad_x=SP[5], pad_y=SP[4]):
    """Returns a panel Frame with an optional eyebrow label above it."""
    wrapper = tk.Frame(parent, bg=parent.cget("bg"))
    if title:
        tk.Label(wrapper, text=title.upper(),
                 font=T["label"], bg=parent.cget("bg"),
                 fg=TEXT_LO).pack(anchor="w", pady=(0, SP[2]))
    panel = tk.Frame(wrapper, bg=bg,
                     highlightbackground=border, highlightthickness=1,
                     padx=pad_x, pady=pad_y)
    panel.pack(fill="both", expand=True)
    return wrapper, panel


def divider(parent, color=BORDER, pady=0):
    tk.Frame(parent, bg=color, height=1).pack(fill="x", pady=pady)


def chip(parent, text, fg, bg_chip, font=None):
    """Inline colored chip/badge."""
    f = tk.Frame(parent, bg=bg_chip, padx=5, pady=1)
    f.pack(side="left")
    tk.Label(f, text=text, font=font or T["caption"],
             bg=bg_chip, fg=fg).pack()
    return f


class SmoothBar(tk.Frame):
    """Animated horizontal bar — pure Frame/place, Python 3.7 safe."""
    def __init__(self, parent, width, height, value=0, color=BORDER, bg=BG, **kw):
        super().__init__(parent, bg=bg, **kw)
        self._tw = width; self._h = height
        self._val = value; self._clr = color; self._cur = 0

        track = tk.Frame(self, bg="#101d30", width=width, height=height)
        track.pack(side="left")
        track.pack_propagate(False)

        self._fill = tk.Frame(track, bg=color, width=0, height=height)
        self._fill.place(x=0, y=0, width=0, height=height)

        self.after(60, self._tick)

    def _tick(self):
        if self._cur < self._val:
            self._cur = min(self._cur + 4, self._val)
            self._fill.place(x=0, y=0,
                             width=int(self._tw * self._cur / 100),
                             height=self._h)
            self.after(14, self._tick)

    def set_value(self, value, color=None):
        self._val = value; self._cur = 0
        if color:
            self._clr = color
            self._fill.configure(bg=color)
        self._fill.place(x=0, y=0, width=0, height=self._h)
        self.after(60, self._tick)


class IconBadge(tk.Frame):
    """2-char text icon badge (replaces emoji/unicode symbols)."""
    def __init__(self, parent, text, fg, bg_badge, size=8, **kw):
        super().__init__(parent, bg=bg_badge, padx=4, pady=3, **kw)
        tk.Label(self, text=text, font=("Consolas", size, "bold"),
                 bg=bg_badge, fg=fg).pack()


class PrimaryButton(tk.Frame):
    """Styled primary action button with hover effect."""
    def __init__(self, parent, text, command, icon="", bg=ACCENT, fg=TEXT_INV,
                 hover_bg=ACCENT2, width=None, **kw):
        super().__init__(parent, bg=parent.cget("bg"), **kw)
        kw2 = {"width": width} if width else {}
        self._btn = tk.Label(self, text=f"{icon}  {text}" if icon else text,
                              font=("Segoe UI", 9, "bold"),
                              bg=bg, fg=fg, padx=SP[4], pady=SP[2],
                              cursor="hand2", **kw2)
        self._btn.pack(fill="x")
        self._bg = bg; self._hover = hover_bg; self._cmd = command
        self._btn.bind("<Enter>",   lambda e: self._btn.config(bg=self._hover))
        self._btn.bind("<Leave>",   lambda e: self._btn.config(bg=self._bg))
        self._btn.bind("<Button-1>", lambda e: command())

    def set_text(self, text):
        self._btn.config(text=text)

    def set_state(self, enabled):
        self._btn.config(fg=TEXT_INV if enabled else TEXT_LO,
                         bg=self._bg if enabled else SURF3,
                         cursor="hand2" if enabled else "arrow")
        self._is_enabled = enabled
        if not enabled:
            self._btn.unbind("<Button-1>")
        else:
            self._btn.bind("<Button-1>", lambda e: self._cmd())


class SecondaryButton(tk.Frame):
    """Ghost/outline secondary button."""
    def __init__(self, parent, text, command, icon="", **kw):
        super().__init__(parent, bg=parent.cget("bg"),
                         highlightbackground=BORDER2, highlightthickness=1, **kw)
        self._btn = tk.Label(self, text=f"{icon}  {text}" if icon else text,
                              font=T["body"], bg=SURF2, fg=TEXT_MD,
                              padx=SP[4], pady=SP[2], cursor="hand2")
        self._btn.pack(fill="x")
        self._btn.bind("<Enter>",   lambda e: self._btn.config(bg=SURF3, fg=TEXT_HI))
        self._btn.bind("<Leave>",   lambda e: self._btn.config(bg=SURF2, fg=TEXT_MD))
        self._btn.bind("<Button-1>", lambda e: command())


# ══════════════════════════════════════════════════════════════════════════════
#  SCORE RING  (drawn on tk.Canvas after pack — Python 3.7 safe)
# ══════════════════════════════════════════════════════════════════════════════

class ScoreRing(tk.Frame):
    """Circular gauge ring drawn via Canvas arcs."""
    SZ = 110  # diameter

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=parent.cget("bg"), **kw)
        self._cv = tk.Canvas(self, width=self.SZ, height=self.SZ,
                             bg=parent.cget("bg"), highlightthickness=0)
        self._cv.pack()
        self._score = 0
        self._color = TEXT_LO
        self.after(80, self._init_draw)

    def _init_draw(self):
        self._draw(self._score, self._color)

    def _draw(self, score, color):
        c = self._cv; c.delete("all")
        cx = cy = self.SZ // 2; r = 46; lw = 9
        # Track arc
        c.create_arc(cx-r, cy-r, cx+r, cy+r,
                     start=220, extent=-260,
                     style="arc", outline="#152236", width=lw)
        # Value arc
        if score > 0:
            ext = int(-260 * score / 100)
            c.create_arc(cx-r, cy-r, cx+r, cy+r,
                         start=220, extent=ext,
                         style="arc", outline=color, width=lw)
        # Center score
        c.create_text(cx, cy - 6, text=str(score),
                      font=("Segoe UI Semibold", 18, "bold"), fill=color)
        c.create_text(cx, cy + 12, text="/100",
                      font=T["caption"], fill=TEXT_LO)

    def update(self, score, color):
        self._score = score; self._color = color
        try:
            self._draw(score, color)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetSec Analyzer  ·  v3.0  |  Network Security Assessment")
        self.geometry("1440x880")
        self.minsize(1100, 700)
        self.configure(bg=BG)

        self._json_path   = tk.StringVar(value="No topology file selected")
        self._findings    = []
        self._score       = 0
        self._prev_score  = None
        self._filter_var  = tk.StringVar(value="ALL")
        self._cat_rows    = {}   # cat → (bar, pct_lbl)
        self._stat_vals   = {}   # level → (count_lbl, bar_lbl)

        self._configure_styles()
        self._build()

    # ── ttk scrollbar style ──────────────────────────────────────────────────
    def _configure_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("NS.Vertical.TScrollbar",
                    background=SURF3, troughcolor=SURFACE,
                    bordercolor=BG, arrowcolor=TEXT_LO,
                    relief="flat", width=6)
        s.map("NS.Vertical.TScrollbar", background=[("active", BORDER2)])

    # ══════════════════════════════════════════════════════════════════════════
    #  BUILD
    # ══════════════════════════════════════════════════════════════════════════

    def _build(self):
        self._build_chrome()       # top bar + toolbar
        self._build_kpi_strip()    # score cards
        divider(self, BORDER)
        self._build_workspace()    # sidebar + findings
        self._build_statusbar()

    # ── Chrome: top bar ──────────────────────────────────────────────────────
    def _build_chrome(self):
        # ── App title bar ────────────────────────────────────────────────────
        title_bar = tk.Frame(self, bg="#07101f", height=48)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        # Logo mark
        logo = tk.Frame(title_bar, bg="#07101f")
        logo.pack(side="left", padx=SP[6], fill="y")

        # Colored logo block
        mark = tk.Frame(logo, bg=ACCENT, width=3, height=28)
        mark.pack(side="left", padx=(0, SP[3]), pady=10)

        tk.Label(logo, text="NETSEC",
                 font=("Consolas", 12, "bold"),
                 bg="#07101f", fg=TEXT_HI).pack(side="left")
        tk.Label(logo, text=" ANALYZER",
                 font=("Consolas", 12),
                 bg="#07101f", fg=TEXT_LO).pack(side="left")

        # Version pill
        ver = tk.Frame(logo, bg=ACCENTG, padx=6, pady=1)
        ver.pack(side="left", padx=SP[4], pady=16)
        tk.Label(ver, text="v3.0", font=T["caption"],
                 bg=ACCENTG, fg=ACCENT).pack()

        # Right — clock
        self._clock_lbl = tk.Label(title_bar,
                                    font=("Consolas", 9),
                                    bg="#07101f", fg=TEXT_LO)
        self._clock_lbl.pack(side="right", padx=SP[6])
        tk.Label(title_bar,
                 text=f"SESSION  {datetime.now().strftime('%Y-%m-%d')}",
                 font=T["label"], bg="#07101f", fg=TEXT_LO).pack(side="right", padx=SP[3])
        self._tick()

        # Bottom edge line (accent)
        tk.Frame(title_bar, bg=ACCENT, height=1).pack(side="bottom", fill="x")

        # ── Toolbar ──────────────────────────────────────────────────────────
        toolbar = tk.Frame(self, bg=SURF2, pady=SP[3])
        toolbar.pack(fill="x")

        tb_inner = tk.Frame(toolbar, bg=SURF2)
        tb_inner.pack(padx=SP[7])

        # File input area
        tk.Label(tb_inner, text="TARGET FILE",
                 font=T["label"], bg=SURF2, fg=TEXT_LO).pack(side="left", padx=(0, SP[3]))

        file_frame = tk.Frame(tb_inner, bg=BORDER, padx=1, pady=1)
        file_frame.pack(side="left")
        file_inner = tk.Frame(file_frame, bg="#080f1c")
        file_inner.pack()
        tk.Label(file_inner, textvariable=self._json_path,
                 font=("Consolas", 8), bg="#080f1c", fg=ACCENT,
                 padx=SP[4], pady=5, width=50, anchor="w").pack()

        SecondaryButton(tb_inner, "Browse", self._browse).pack(side="left", padx=(SP[3], SP[2]))

        self._run_btn = PrimaryButton(tb_inner, "Run Analysis", self._run, icon="▶")
        self._run_btn.pack(side="left", padx=SP[2])

        SecondaryButton(tb_inner, "Export Report", self._export, icon="↓").pack(side="left", padx=SP[2])

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _tick(self):
        self._clock_lbl.config(text=datetime.now().strftime("%H : %M : %S  UTC"))
        self.after(1000, self._tick)

    # ── KPI strip ────────────────────────────────────────────────────────────
    def _build_kpi_strip(self):
        strip = tk.Frame(self, bg=BG, pady=SP[5])
        strip.pack(fill="x", padx=SP[7])

        # ── Card 1: Score ring + posture ─────────────────────────────────────
        c1 = tk.Frame(strip, bg=SURFACE,
                      highlightbackground=BORDER, highlightthickness=1)
        c1.pack(side="left")

        c1_inner = tk.Frame(c1, bg=SURFACE, padx=SP[6], pady=SP[4])
        c1_inner.pack()

        tk.Label(c1_inner, text="SECURITY SCORE",
                 font=T["label"], bg=SURFACE, fg=TEXT_LO).grid(row=0, column=0, sticky="w")

        self._ring = ScoreRing(c1_inner)
        self._ring.grid(row=1, column=0, padx=(0, SP[5]))

        posture_col = tk.Frame(c1_inner, bg=SURFACE)
        posture_col.grid(row=1, column=1, sticky="ns")

        self._posture_lbl = tk.Label(posture_col, text="AWAITING",
                                      font=("Segoe UI Semibold", 14, "bold"),
                                      bg=SURFACE, fg=TEXT_LO)
        self._posture_lbl.pack(anchor="w", pady=(SP[4], SP[1]))

        self._posture_desc = tk.Label(posture_col, text="Load a topology file",
                                       font=T["body_sm"], bg=SURFACE, fg=TEXT_LO,
                                       wraplength=120, justify="left")
        self._posture_desc.pack(anchor="w")

        # Vertical divider
        tk.Frame(strip, bg=BORDER, width=1).pack(side="left", fill="y", padx=SP[5], pady=SP[3])

        # ── Card 2: Scan comparison ───────────────────────────────────────────
        c2 = tk.Frame(strip, bg=SURFACE,
                      highlightbackground=BORDER, highlightthickness=1)
        c2.pack(side="left")

        c2_inner = tk.Frame(c2, bg=SURFACE, padx=SP[6], pady=SP[4])
        c2_inner.pack(fill="both", expand=True)

        tk.Label(c2_inner, text="SCAN COMPARISON",
                 font=T["label"], bg=SURFACE, fg=TEXT_LO).pack(anchor="w")

        cmp_row = tk.Frame(c2_inner, bg=SURFACE)
        cmp_row.pack(anchor="w", pady=(SP[3], 0))

        self._prev_score_lbl = tk.Label(cmp_row, text="—",
                                         font=T["kpi"], bg=SURFACE, fg=TEXT_LO)
        self._prev_score_lbl.pack(side="left")

        tk.Label(cmp_row, text="  →  ",
                 font=("Segoe UI", 14), bg=SURFACE, fg=TEXT_LO).pack(side="left")

        self._curr_score_lbl = tk.Label(cmp_row, text="—",
                                         font=T["kpi"], bg=SURFACE, fg=TEXT_LO)
        self._curr_score_lbl.pack(side="left")

        self._delta_lbl = tk.Label(c2_inner, text="No previous baseline",
                                    font=T["body_sm"], bg=SURFACE, fg=TEXT_LO)
        self._delta_lbl.pack(anchor="w", pady=(SP[2], 0))

        # Vertical divider
        tk.Frame(strip, bg=BORDER, width=1).pack(side="left", fill="y", padx=SP[5], pady=SP[3])

        # ── Card 3: Finding counts (critical / high / pass) ───────────────────
        c3 = tk.Frame(strip, bg=SURFACE,
                      highlightbackground=BORDER, highlightthickness=1)
        c3.pack(side="left")

        c3_inner = tk.Frame(c3, bg=SURFACE, padx=SP[6], pady=SP[4])
        c3_inner.pack(fill="both", expand=True)

        tk.Label(c3_inner, text="ALERT SUMMARY",
                 font=T["label"], bg=SURFACE, fg=TEXT_LO).pack(anchor="w")

        kpi_row = tk.Frame(c3_inner, bg=SURFACE)
        kpi_row.pack(anchor="w", pady=(SP[3], 0))

        self._kpi_counts = {}
        kpi_items = [("CRITICAL", CLR["CRITICAL"]), ("HIGH", CLR["HIGH"]),
                     ("MEDIUM",   CLR["MEDIUM"]),   ("PASS", CLR["PASS"])]
        for lvl, clr in kpi_items:
            col = tk.Frame(kpi_row, bg=SURFACE, padx=SP[4])
            col.pack(side="left")
            n = tk.Label(col, text="0", font=("Segoe UI Semibold", 18, "bold"),
                         bg=SURFACE, fg=clr)
            n.pack()
            tk.Label(col, text=lvl, font=T["caption"],
                     bg=SURFACE, fg=TEXT_LO).pack()
            self._kpi_counts[lvl] = n

        # Vertical divider
        tk.Frame(strip, bg=BORDER, width=1).pack(side="left", fill="y", padx=SP[5], pady=SP[3])

        # ── Card 4: Total devices / last scan time ────────────────────────────
        c4 = tk.Frame(strip, bg=SURFACE,
                      highlightbackground=BORDER, highlightthickness=1)
        c4.pack(side="left")

        c4_inner = tk.Frame(c4, bg=SURFACE, padx=SP[6], pady=SP[4])
        c4_inner.pack(fill="both", expand=True)

        tk.Label(c4_inner, text="SCAN METADATA",
                 font=T["label"], bg=SURFACE, fg=TEXT_LO).pack(anchor="w")

        self._meta_total = tk.Label(c4_inner, text="—  findings",
                                     font=T["h1"], bg=SURFACE, fg=TEXT_HI)
        self._meta_total.pack(anchor="w", pady=(SP[3], SP[1]))

        self._meta_time = tk.Label(c4_inner, text="Last scan:  not yet run",
                                    font=T["mono_sm"], bg=SURFACE, fg=TEXT_LO)
        self._meta_time.pack(anchor="w")

    # ── Main workspace ────────────────────────────────────────────────────────
    def _build_workspace(self):
        ws = tk.Frame(self, bg=BG)
        ws.pack(fill="both", expand=True, padx=SP[7], pady=SP[5])

        self._build_sidebar(ws)

        # Vertical separator
        tk.Frame(ws, bg=BORDER, width=1).pack(side="left", fill="y", padx=(SP[5], SP[6]))

        self._build_findings(ws)

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _build_sidebar(self, parent):
        sb = tk.Frame(parent, bg=BG, width=256)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        # ── Severity panel ────────────────────────────────────────────────────
        tk.Label(sb, text="SEVERITY BREAKDOWN",
                 font=T["label"], bg=BG, fg=TEXT_LO).pack(anchor="w")

        self._sev_panel = tk.Frame(sb, bg=SURFACE,
                                    highlightbackground=BORDER, highlightthickness=1)
        self._sev_panel.pack(fill="x", pady=(SP[2], 0))

        self._sev_rows = {}
        levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS", "INFO"]
        for i, lvl in enumerate(levels):
            clr = CLR[lvl]
            row = tk.Frame(self._sev_panel, bg=SURFACE, pady=6, padx=SP[4])
            row.pack(fill="x")
            if i > 0:
                tk.Frame(self._sev_panel, bg=BORDER, height=1).pack(fill="x")

            # Severity indicator stripe
            stripe = tk.Frame(row, bg=clr, width=3, height=18)
            stripe.pack(side="left", padx=(0, SP[3]))

            tk.Label(row, text=lvl, font=T["label"],
                     bg=SURFACE, fg=clr, width=8, anchor="w").pack(side="left")

            # Mini bar
            bar_frame = tk.Frame(row, bg=SURFACE)
            bar_frame.pack(side="left", expand=True, fill="x", padx=SP[2])
            bar_bg = tk.Frame(bar_frame, bg="#101d30", height=4)
            bar_bg.pack(fill="x", pady=7)
            bar_fill = tk.Frame(bar_bg, bg=clr, height=4, width=0)
            bar_fill.place(x=0, y=0, width=0, height=4)

            count_lbl = tk.Label(row, text="0",
                                  font=("Segoe UI Semibold", 11, "bold"),
                                  bg=SURFACE, fg=clr, width=3, anchor="e")
            count_lbl.pack(side="right")

            self._sev_rows[lvl] = (count_lbl, bar_fill, bar_bg)

        # ── Category scores ───────────────────────────────────────────────────
        tk.Label(sb, text="CATEGORY HEALTH",
                 font=T["label"], bg=BG, fg=TEXT_LO).pack(anchor="w", pady=(SP[5], SP[2]))

        cat_panel = tk.Frame(sb, bg=SURFACE,
                              highlightbackground=BORDER, highlightthickness=1)
        cat_panel.pack(fill="x")

        self._cat_rows = {}
        for i, cat in enumerate(ALL_CATEGORIES):
            meta = CAT_META[cat]
            row = tk.Frame(cat_panel, bg=SURFACE, padx=SP[4], pady=4)
            row.pack(fill="x")
            if i > 0:
                tk.Frame(cat_panel, bg=BORDER, height=1).pack(fill="x")

            # Icon badge
            badge = tk.Frame(row, bg="#10213a", padx=4, pady=2)
            badge.pack(side="left", padx=(0, SP[3]))
            tk.Label(badge, text=meta["icon"], font=("Consolas", 6, "bold"),
                     bg="#10213a", fg=ACCENT).pack()

            # Name
            tk.Label(row, text=meta["short"], font=T["body_sm"],
                     bg=SURFACE, fg=TEXT_MD, width=9, anchor="w").pack(side="left")

            # Progress bar
            bar = SmoothBar(row, width=72, height=5, value=0,
                            color=BORDER, bg=SURFACE)
            bar.pack(side="left", padx=SP[2], pady=6)

            pct = tk.Label(row, text=" — ", font=T["caption"],
                           bg=SURFACE, fg=TEXT_LO, width=5, anchor="e")
            pct.pack(side="right")

            self._cat_rows[cat] = (bar, pct)

        # ── Filter ────────────────────────────────────────────────────────────
        tk.Label(sb, text="FILTER FINDINGS",
                 font=T["label"], bg=BG, fg=TEXT_LO).pack(anchor="w", pady=(SP[5], SP[2]))

        filter_panel = tk.Frame(sb, bg=SURFACE,
                                 highlightbackground=BORDER, highlightthickness=1,
                                 padx=SP[4], pady=SP[3])
        filter_panel.pack(fill="x")

        options = [("ALL", TEXT_MD)] + [(lv, CLR[lv]) for lv in
                   ("CRITICAL","HIGH","MEDIUM","LOW","PASS","INFO")]
        for val, clr in options:
            rb_frame = tk.Frame(filter_panel, bg=SURFACE)
            rb_frame.pack(fill="x", pady=1)

            rb = tk.Radiobutton(rb_frame, text=f"  {val}",
                                variable=self._filter_var, value=val,
                                command=self._apply_filter,
                                font=("Segoe UI", 8, "bold"),
                                bg=SURFACE, fg=clr,
                                activebackground=SURF3, activeforeground=clr,
                                selectcolor=SURF3, indicatoron=True,
                                cursor="hand2")
            rb.pack(anchor="w")

    # ── Findings panel ────────────────────────────────────────────────────────
    def _build_findings(self, parent):
        right = tk.Frame(parent, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        # Header
        hdr = tk.Frame(right, bg=BG)
        hdr.pack(fill="x", pady=(0, SP[4]))

        tk.Label(hdr, text="SECURITY FINDINGS",
                 font=T["h1"], bg=BG, fg=TEXT_HI).pack(side="left")

        self._findings_count = tk.Label(hdr, text="",
                                         font=T["body_sm"], bg=BG, fg=TEXT_LO)
        self._findings_count.pack(side="left", padx=SP[4])

        # Scrollable canvas
        cf = tk.Frame(right, bg=BG)
        cf.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(cf, bg=BG, highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(cf, orient="vertical",
                             command=self._canvas.yview,
                             style="NS.Vertical.TScrollbar")
        self._canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._scroll_frame = tk.Frame(self._canvas, bg=BG)
        self._win_id = self._canvas.create_window((0, 0),
                                                   window=self._scroll_frame,
                                                   anchor="nw")
        self._scroll_frame.bind("<Configure>", self._on_scroll_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        sb = tk.Frame(self, bg="#050c18", height=26)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        tk.Frame(sb, bg=BORDER, height=1).pack(fill="x", side="top")

        self._status = tk.Label(sb, text="Ready  ·  Load a network topology JSON file to begin",
                                 font=("Consolas", 8), bg="#050c18",
                                 fg=TEXT_LO, anchor="w", padx=SP[6])
        self._status.pack(side="left", fill="x", expand=True)

        tk.Label(sb, text="NetSec Analyzer  ·  Graduation Project",
                 font=T["caption"], bg="#050c18",
                 fg=TEXT_LO, padx=SP[6]).pack(side="right")

    # ══════════════════════════════════════════════════════════════════════════
    #  EVENTS
    # ══════════════════════════════════════════════════════════════════════════

    def _on_scroll_configure(self, _):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, e):
        self._canvas.itemconfig(self._win_id, width=e.width)

    def _on_mousewheel(self, e):
        self._canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select Network Topology JSON",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])
        if path:
            self._json_path.set(path)

    # ── Analysis ──────────────────────────────────────────────────────────────
    def _run(self):
        path = self._json_path.get()
        if not path or path == "No topology file selected":
            messagebox.showwarning("No File", "Please select a JSON topology file first.")
            return
        self._run_btn.set_text("  Analyzing…")
        self._run_btn.set_state(False)
        self._status.config(text="Running security analysis  ·  Please wait…")
        threading.Thread(target=self._analysis_thread, args=(path,), daemon=True).start()

    def _analysis_thread(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            findings, score = NetworkSecurityAnalyzer(data).analyze()
            self.after(0, self._on_results, findings, score)
        except json.JSONDecodeError as e:
            self.after(0, lambda: messagebox.showerror("JSON Error", f"Invalid JSON:\n{e}"))
            self.after(0, self._reset_run_btn)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.after(0, self._reset_run_btn)

    def _reset_run_btn(self):
        self._run_btn.set_text("▶  Run Analysis")
        self._run_btn.set_state(True)
        self._status.config(text="Error during analysis.")

    # ── Render results ────────────────────────────────────────────────────────
    def _on_results(self, findings, score):
        self._findings = findings

        # Posture
        clr, posture, desc = score_meta(score)

        # Ring + posture
        self._ring.update(score, clr)
        self._posture_lbl.config(text=posture, fg=clr)
        self._posture_desc.config(text=desc)

        # Comparison
        prev = self._prev_score
        prev_clr, _, _ = score_meta(prev) if prev else (TEXT_LO, None, None)
        self._prev_score_lbl.config(text=str(prev) if prev is not None else "—", fg=prev_clr)
        self._curr_score_lbl.config(text=str(score), fg=clr)

        if prev is not None:
            d = score - prev
            dc = CLR["PASS"] if d >= 0 else CLR["CRITICAL"]
            sym = "▲" if d > 0 else ("▼" if d < 0 else "●")
            self._delta_lbl.config(text=f"{sym}  {abs(d):+d} pts vs previous scan", fg=dc)
        else:
            self._delta_lbl.config(text="First scan — no baseline", fg=TEXT_LO)

        self._prev_score = score
        self._score = score

        # Counts
        counts = {l: 0 for l in CLR}
        for f in findings:
            counts[f["level"]] = counts.get(f["level"], 0) + 1

        # KPI row
        for lvl, lbl in self._kpi_counts.items():
            lbl.config(text=str(counts.get(lvl, 0)))

        # Metadata card
        total = len(findings)
        self._meta_total.config(text=f"{total}  findings")
        self._meta_time.config(text=f"Last scan:  {datetime.now().strftime('%H:%M:%S  %Y-%m-%d')}")

        # Severity sidebar rows
        total_non_pass = max(1, sum(counts.get(l, 0) for l in CLR if l != "PASS"))
        for lvl, (count_lbl, bar_fill, bar_bg) in self._sev_rows.items():
            n = counts.get(lvl, 0)
            count_lbl.config(text=str(n))
            try:
                bar_bg.update_idletasks()
                avail = bar_bg.winfo_width()
                if avail < 2: avail = 80
                pct = n / total_non_pass if lvl != "PASS" else (n / max(1, total))
                bar_fill.place(x=0, y=0, width=int(avail * pct), height=4)
            except Exception:
                pass

        # Category bars
        for cat, (bar, pct_lbl) in self._cat_rows.items():
            cs = cat_score(findings, cat)
            if cs is None:
                bar.set_value(0, BORDER)
                pct_lbl.config(text=" N/A", fg=TEXT_LO)
            else:
                bc, _, _ = score_meta(cs)
                bar.set_value(cs, bc)
                pct_lbl.config(text=f"{cs}%", fg=bc)

        # Findings
        self._filter_var.set("ALL")
        self._render_findings(findings)

        n_crit = counts.get("CRITICAL", 0)
        n_high = counts.get("HIGH", 0)
        self._findings_count.config(
            text=f"{total} total  ·  {n_crit} critical  ·  {n_high} high",
            fg=CLR["CRITICAL"] if n_crit else (CLR["HIGH"] if n_high else TEXT_LO))

        self._status.config(
            text=f"Analysis complete  ·  Score: {score}/100  [{posture}]  ·  "
                 f"Critical: {n_crit}   High: {n_high}   "
                 f"Medium: {counts.get('MEDIUM',0)}   Pass: {counts.get('PASS',0)}")

        self._run_btn.set_text("▶  Run Analysis")
        self._run_btn.set_state(True)

    def _apply_filter(self):
        f = self._filter_var.get()
        shown = self._findings if f == "ALL" else [x for x in self._findings if x["level"] == f]
        self._render_findings(shown)

    def _render_findings(self, findings):
        for w in self._scroll_frame.winfo_children():
            w.destroy()

        if not findings:
            tk.Label(self._scroll_frame, text="No findings match the current filter.",
                     font=T["body"], bg=BG, fg=TEXT_LO).pack(pady=SP[8])
            self._canvas.yview_moveto(0)
            return

        for f in findings:
            self._make_card(f)

        self._canvas.yview_moveto(0)

    # ── Finding card ─────────────────────────────────────────────────────────
    def _make_card(self, finding):
        lvl  = finding["level"]
        clr  = CLR[lvl]
        cbg  = CLR_BG[lvl]
        cat  = finding["category"]
        meta = CAT_META.get(cat, {"icon": "?", "short": cat})

        # Outer wrapper — left accent edge
        outer = tk.Frame(self._scroll_frame, bg=clr)
        outer.pack(fill="x", pady=2, padx=0)

        card = tk.Frame(outer, bg=SURFACE, padx=0, pady=0)
        card.pack(fill="x", padx=2, pady=0)

        # ── Layout: [badge col] | [body col]
        # Badge column
        badge_col = tk.Frame(card, bg=cbg, padx=SP[4], pady=SP[4], width=68)
        badge_col.pack(side="left", fill="y")
        badge_col.pack_propagate(False)

        # Category icon
        ic_frame = tk.Frame(badge_col, bg="#10213a", padx=5, pady=3)
        ic_frame.pack(pady=(SP[2], SP[2]))
        tk.Label(ic_frame, text=meta["icon"],
                 font=("Consolas", 8, "bold"),
                 bg="#10213a", fg=ACCENT).pack()

        # Severity dot + label
        dot_frame = tk.Frame(badge_col, bg=cbg)
        dot_frame.pack()
        tk.Label(dot_frame, text="●", font=("Segoe UI", 8),
                 bg=cbg, fg=clr).pack()
        tk.Label(dot_frame, text=lvl[:4],
                 font=T["caption"], bg=cbg, fg=clr).pack()

        # Body column
        body = tk.Frame(card, bg=SURFACE, padx=SP[5], pady=SP[4])
        body.pack(side="left", fill="both", expand=True)

        # Row 1: category chip + title
        top_row = tk.Frame(body, bg=SURFACE)
        top_row.pack(fill="x")

        cat_chip = tk.Frame(top_row, bg=ACCENTG, padx=5, pady=1)
        cat_chip.pack(side="left", pady=(0, SP[2]))
        tk.Label(cat_chip, text=cat.upper(),
                 font=T["caption"], bg=ACCENTG, fg=ACCENT).pack()

        # Title
        tk.Label(body, text=finding["title"],
                 font=("Segoe UI Semibold", 10, "bold"),
                 bg=SURFACE, fg=TEXT_HI,
                 anchor="w", justify="left").pack(fill="x")

        # Detail text
        tk.Label(body, text=finding["detail"],
                 font=T["mono"],
                 bg=SURFACE, fg=TEXT_MD,
                 anchor="w", justify="left",
                 wraplength=880).pack(fill="x", pady=(SP[1], 0))

        # Remediation strip
        if finding.get("fix"):
            rem_strip = tk.Frame(body, bg="#081624", padx=SP[4], pady=SP[2])
            rem_strip.pack(fill="x", pady=(SP[3], 0))

            lbl_frame = tk.Frame(rem_strip, bg="#081624")
            lbl_frame.pack(side="left", padx=(0, SP[3]))
            tk.Label(lbl_frame, text="REMEDIATION",
                     font=T["caption"], bg="#081624", fg=ACCENT).pack()

            tk.Label(rem_strip, text=finding["fix"],
                     font=T["mono_sm"],
                     bg="#081624", fg="#6ab8f7",
                     anchor="w", justify="left",
                     wraplength=850).pack(side="left", fill="x")

    # ── Export (unchanged logic) ──────────────────────────────────────────────
    def _export(self):
        if not self._findings:
            messagebox.showinfo("Nothing to export", "Run analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt"), ("JSON", "*.json")],
            title="Export Security Report")
        if not path: return
        if path.endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"score": self._score, "findings": self._findings,
                           "date": datetime.now().isoformat()}, f, indent=2)
        else:
            _, posture, _ = score_meta(self._score)
            lines = [
                "=" * 72,
                "  NETSEC ANALYZER  ·  SECURITY ASSESSMENT REPORT",
                f"  Date     : {datetime.now().strftime('%Y-%m-%d  %H:%M')}",
                f"  Score    : {self._score} / 100",
                f"  Posture  : {posture}",
                "=" * 72, ""
            ]
            for f in self._findings:
                lines += [f"[{f['level']}]  {f['category']}  —  {f['title']}",
                          f"  Detail      : {f['detail']}"]
                if f.get("fix"):
                    lines.append(f"  Remediation : {f['fix']}")
                lines.append("")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
        messagebox.showinfo("Saved", f"Report saved:\n{path}")


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = App()
    app.mainloop()
