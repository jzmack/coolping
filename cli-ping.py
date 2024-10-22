import subprocess #for pinging and nslookup
import time
import ipaddress #for validating IPs
import threading #for multiple pings at once
import datetime #timestamping
from concurrent.futures import ThreadPoolExecutor #threading for multiple processes at once
from colorama import Fore, Style, init #cool colorful text
from texttable import Texttable #text table

#initialize colorama
init()
ping_targets = []  #global list for storing ping targets
lock = threading.Lock()  #lock to prevent race conditions when modifying the target list
display_results = True #flag for displaying the table of results

#function to ping a server and return status and response time
def ping_target(ip):
    try:
        output = subprocess.check_output(["ping", "-n", "1", ip], stderr=subprocess.STDOUT, universal_newlines=True)
        for line in output.splitlines(): #getting response time
            if "time=" in line:
                response_time = line.split("time=")[1].split("ms")[0].strip()
                return True, response_time + " ms"  #server is UP, with response time
        return True, "N/A"
    except subprocess.CalledProcessError:
        return False, "N/A"  #server is DOWN or unreachable

#function to validate IP addresses
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

#function and to get the hostnames and cache them using nslookup
hostname_cache = {} #dictionary to store hostnames
def get_hostname(ip):
    if ip in hostname_cache:
        return hostname_cache[ip]
    try:
        output = subprocess.check_output(["nslookup", ip], stderr=subprocess.STDOUT, universal_newlines=True)
        for line in output.splitlines():
            if "Name:" in line:
                hostname = line.split(":", 1)[1].strip()#extract hostname
                hostname_cache[ip] = hostname
                return hostname
        return "N/A"
    except subprocess.CalledProcessError:
        return "N/A"

#function to ping the list using multithreading
def ping_loop():
    global display_results
    while True:
        with lock:
            if not ping_targets:
                time.sleep(2)
                continue

            if display_results:#only display results if this is true

                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") #printing a timestamp
                print(f"\nTimestamp: {current_time}")

                table = Texttable() #creating a table from text
                table.add_row(["Device IP", "Hostname", "Status"]) #defining the headers for the table0

                #pinging ips concurrently
                with ThreadPoolExecutor(max_workers=15) as executor:#max workers can be adjusted
                    future_to_ip = {executor.submit(ping_target, ip): ip for ip in ping_targets}

                    for future in future_to_ip:
                        ip = future_to_ip[future]
                        hostname = get_hostname(ip)
                        try:
                            status, response_time = future.result()#get the result of the ping
                            if status:
                                status_text = f"{Fore.GREEN}UP - {response_time}{Style.RESET_ALL}"
                            else:
                                status_text = f"{Fore.RED}DOWN{Style.RESET_ALL}"
                        except Exception as e:
                            status_text = f"{Fore.RED}ERROR{Style.RESET_ALL}"
                            response_time = "N/A"

                        table.add_row([ip, hostname, status_text])

                print(table.draw())
        time.sleep(2) #time to wait between pinging (2 seconds)

#function to handle user commands
def command_loop():
    global ping_targets, display_results
    while True:
        user_input = input("\nEnter 'add' or 'remove' to adjust IP list, or 'exit' to quit: \n").strip().lower()

        if user_input == "add": #adding an IP
            display_results = False #to stop displaying results for an easier visual
            new_ips = input("Enter the new IP addresses to add, separated by commas: ")
            display_results = True #continue diplaying results after additional input
            with lock:
                for ip in new_ips.split(","):
                    ip = ip.strip()
                    if is_valid_ip(ip):
                        ping_targets.append(ip)
                        print(f"{Fore.GREEN}{ip} added successfully.{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}{ip} is not a valid IP address.{Style.RESET_ALL}")

        elif user_input == "remove":
            display_results = False
            ip_to_remove = input("Enter the IP address to remove: ").strip()
            with lock:
                if ip_to_remove in ping_targets:
                    ping_targets.remove(ip_to_remove)
                    print(f"{Fore.YELLOW}{ip_to_remove} removed successfully.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}{ip_to_remove} is not in the list.{Style.RESET_ALL}")
            display_results = True

        elif user_input == "exit":
            print("Exiting...")
            exit() #safely exit the program

#main function
def main():
    try:
        #initial IP input
        initial_input = input("Enter IP addresses to ping, separated by commas: ")
        global ping_targets
        for ip in initial_input.split(","):
            ip = ip.strip()
            if is_valid_ip(ip):
                ping_targets.append(ip)
            else:
                print(f"{Fore.RED}{ip} is not a valid IP address and will be skipped.{Style.RESET_ALL}")

        #start pinging in a separate thread
        ping_thread = threading.Thread(target=ping_loop)
        ping_thread.daemon = True  #daemon mode allows the program to exit even if this thread is still running
        ping_thread.start()

        #start command input loop in the main thread
        command_loop()
    except KeyboardInterrupt:
        print("Program interrupted. Exiting...")

if __name__ == "__main__":
    main()
