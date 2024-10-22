import asyncio  # running asynchronous processes
import aioping  # running asynchronous pings
import subprocess  # for nslookup
import ipaddress  # used to validate IPs
import os  # for creating a directory and write/read
import logging  # for creating log files
from logging.handlers import RotatingFileHandler
import queue  # used to create queues for pings
import threading  # used to create different threads for pings
from tkinter import ttk, StringVar  # GUI
import customtkinter as ctk  # GUI

# customtkinter appearance
ctk.set_appearance_mode("system")
ctk.set_default_color_theme("blue")

# global variables
ping_targets = {}  # list of IPs to ping
hostname_cache = {}  # cache for hostnames
results_queue = queue.Queue()

# creating the "ping_logs" directory if it doesn't exist
if not os.path.exists('ping_logs'):
    os.makedirs('ping_logs')

# function to configure logging for each IP
def configure_logging(ip):
    log_filename = os.path.join('ping_logs', f'ping_logs_{ip}.log')
    logger = logging.getLogger(ip)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(log_filename, maxBytes=5*1024*1024, backupCount=5)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    if not logger.hasHandlers():
        logger.addHandler(handler)
    return logger

# asynchronous function to ping a target IP address using aioping module
async def ping_target_async(ip, stats):
    logger = configure_logging(ip)
    try:
        delay = await asyncio.wait_for(aioping.ping(ip), timeout=0.5) * 1000  #set timeout to 0.5 seconds
        response_time = f"{delay:.2f} ms"
        logger.info(f"Ping to {ip} successful, response time: {response_time}")

        # Update the stats
        stats['pings_sent'] += 1
        stats['replies'] += 1  # Increment replies on successful ping

        return True, response_time  # IP is UP
    except asyncio.TimeoutError:
        logger.warning(f"Ping to {ip} failed (timed out)")
        stats['pings_sent'] += 1  # Increment pings sent even if it fails
        return False, "N/A"  # IP is DOWN
    except Exception as e:
        logger.error(f"Unexpected error while pinging {ip}: {e}")
        stats['pings_sent'] += 1  # Increment pings sent even if there's an error
        return False, "N/A"  # Return DOWN if there's any errors

#function to check if an IP address is valid
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

#function to get the hostname using nslookup
async def get_hostname(ip):
    if ip in hostname_cache:
        return hostname_cache[ip]
    try:
        result = await resolver.gethostbyaddr(ip)
        hostname = result[0]
        hostname_cache[ip] = hostname
        return hostname
    except Exception:
        return "N/A"

# function to ping all targets and update the GUI table
async def ping_loop(app):
    while not app.stop_ping:
        ping_results = []
        if ping_targets:
            print(f"Starting ping for {len(ping_targets)} IPs...")  # Debugging print
            tasks = [ping_target_async(ip, ping_targets[ip]) for ip in ping_targets]  # Pass stats to the function
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for ip, result in zip(ping_targets.keys(), results):
                hostname = await get_hostname(ip)
                if isinstance(result, tuple):
                    status, response_time = result
                    # No need to update counts here, as it's handled in ping_target_async
                    print(f"{ip} Response time: {response_time}")  # More debugging print
                    ping_results.append(
                        (ip, hostname, response_time, ping_targets[ip]['pings_sent'],
                         ping_targets[ip]['replies'],
                         f"{(ping_targets[ip]['replies'] / ping_targets[ip]['pings_sent'] * 100) if ping_targets[ip]['pings_sent'] > 0 else 0:.2f}%",
                         "up" if status else "down"))
                else:
                    ping_results.append((ip, hostname, "ERROR", ping_targets[ip]['pings_sent'],ping_targets[ip]['replies'], "0.00%", "error"))

        app.update_ping_results(ping_results)
        await asyncio.sleep(1)  # Delay before the next ping cycle (1 second)

# function to run the asyncio event loop in a separate thread
def run_event_loop(app):
    asyncio.run(ping_loop(app))

# Main GUI class
class PingApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.iconbitmap(os.path.join(os.path.dirname(__file__), 'icon', 'ping_pong.ico'))  #ping pong icon
        self.title("Cool Ping App")  #title of the window
        self.geometry("1080x800")  #setting dimensions of the window

        self.stop_ping = False  #flag to stop pinging when closing

        self.ip_var = StringVar()  #StringVars for input
        self.start_ip_var = StringVar()  #StringVar for Start IP
        self.end_ip_var = StringVar()  #StringVar for End IP

        #single/list input Section
        self.label = ctk.CTkLabel(self, text="Enter IP Addresses (comma-separated):")
        self.label.pack(pady=10)
        self.ip_entry = ctk.CTkEntry(self, textvariable=self.ip_var, width=280)
        self.ip_entry.pack(pady=10)

        #range input
        self.start_ip_label = ctk.CTkLabel(self, text="Start IP:")
        self.start_ip_label.pack(pady=(10, 0))
        self.start_ip_entry = ctk.CTkEntry(self, textvariable=self.start_ip_var, width=280)
        self.start_ip_entry.pack(pady=10)
        self.end_ip_label = ctk.CTkLabel(self, text="End IP:")
        self.end_ip_label.pack(pady=(10, 0))

        self.end_ip_entry = ctk.CTkEntry(self, textvariable=self.end_ip_var, width=280)
        self.end_ip_entry.pack(pady=10)

        #Add IPs button
        button_color = "#07bbd0"
        self.add_button = ctk.CTkButton(self, text="Add IPs", text_color="black",
                                        command=self.add_ips,fg_color=button_color, hover_color="green")
        self.add_button.pack(pady=10)

        #Remove IP
        self.remove_button = ctk.CTkButton(self, text="Remove IP", text_color="black",
                                           command=self.remove_ip,fg_color=button_color, hover_color="red")
        self.remove_button.pack(pady=10)

        # Remove All Button
        self.remove_all_button = ctk.CTkButton(self, text="Remove All", text_color="white",
                                               command=self.remove_all_ips,fg_color="#c12e13", hover_color="red")
        self.remove_all_button.pack(pady=10)

        # Display Section (using Treeview for table-like view)
        self.tree = ttk.Treeview(self, columns=('IP', 'Hostname','Status', 'Pings Sent', 'Replies', '% of Replies'), show='headings')
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('Hostname', text='Hostname')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Pings Sent', text='Pings Sent')
        self.tree.heading('Replies', text='Replies')
        self.tree.heading('% of Replies', text='% of Replies')

        #setting column width and centering text
        self.tree.column('IP', anchor='center')
        self.tree.column('Hostname', anchor='center')
        self.tree.column('Hostname', anchor='center')
        self.tree.column('Status', anchor='center')
        self.tree.column('Pings Sent', width=75, anchor='center')
        self.tree.column('Replies', width=75, anchor='center')
        self.tree.column('% of Replies', anchor='center')

        self.tree.pack(pady=20, expand=True, fill='both')

        # Add tags for color coding status
        self.tree.tag_configure('up', foreground='green')  # Green for UP
        self.tree.tag_configure('down', foreground='red')  # Red for DOWN
        self.tree.tag_configure('error', foreground='orange')  # Orange for ERROR

        # Start the ping loop in a separate thread
        self.stop_ping = False  # Flag to control the ping loop
        threading.Thread(target=run_event_loop, args=(self,), daemon=True).start()  # Start the ping loop in a new thread

        # Bind the close event
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # Function to add IP addresses from the entry fields
    def add_ips(self):
        ips = self.ip_var.get().split(',')
        for ip in ips:
            ip = ip.strip()
            if is_valid_ip(ip):
                if ip not in ping_targets:  # Check if the IP is already in the dictionary
                    ping_targets[ip] = {'pings_sent': 0, 'replies': 0}  # Initialize stats
                    self.tree.insert("", "end", values=(ip, "N/A", 0, 0, "0.00%", "Pending..."))
                    print(f"Added IP {ip} to ping targets")  # Debugging print
                else:
                    print(f"IP {ip} already in the list.")
            else:
                print(f"Invalid IP address: {ip}")

        # Add range of IPs from start and end input
        start_ip = self.start_ip_var.get().strip()
        end_ip = self.end_ip_var.get().strip()
        if is_valid_ip(start_ip) and is_valid_ip(end_ip):
            try:
                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)
                if start > end:
                    print("Start IP must be less than or equal to End IP.")  # Debugging print
                    return
                for ip in range(int(start), int(end) + 1):
                    ip_str = str(ipaddress.ip_address(ip))
                    if ip_str not in ping_targets:
                        ping_targets[ip_str] = {'pings_sent': 0, 'replies': 0}
                        self.tree.insert("", "end", values=(ip_str, "N/A", 0, 0, "0.00%", "Pending..."))
                        print(f"Added IP {ip_str} to ping targets")  # Debugging print
            except ValueError:
                print("Invalid range of IP addresses.")
        self.start_ip_var.set("")
        self.end_ip_var.set("")

    # Function to remove an IP address
    def remove_ip(self):
        selected_item = self.tree.selection()  # Get the selected item
        if selected_item:
            item = selected_item[0]  # Get the first selected item
            ip = self.tree.item(item, 'values')[0]  # Get IP from the selected row
            if ip in ping_targets:
                ping_targets.pop(ip)  # Remove from targets
                print(f"Removed IP {ip} from ping targets")  # Debugging print
            self.tree.delete(item)

    #function to remove all IP addresses
    def remove_all_ips(self):
        #clear the ping_targets dictionary
        global ping_targets
        ping_targets.clear()

        #clear the Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        print("All IPs removed and pinging stopped.")

    #function to update results in the Treeview
    def update_ping_results(self, results):
        for ip, hostname, response_time, pings_sent, replies, reply_percent, tag in results:
            self._update_gui(ip, hostname, response_time, pings_sent, replies, reply_percent, tag)

    def _update_gui(self, ip, hostname, response_time, pings_sent, replies, reply_percent, tag):
        for child in self.tree.get_children():
            if self.tree.item(child, 'values')[0] == ip:
                self.tree.item(child, values=(ip, hostname, response_time, pings_sent, replies, reply_percent),tags=(tag,))
                break

    def on_close(self):
        self.stop_ping = True
        self.quit()

# Start the GUI application
if __name__ == "__main__":
    app = PingApp()  # Create the GUI app
    app.mainloop()  # Start the GUI main loop