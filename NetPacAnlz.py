import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, get_if_list
import threading
import socket
import struct
import textwrap
from flask import Flask, render_template_string, request

# Initialize Flask app
app = Flask(__name__)

# Global variables
packets = []
capturing = False
interface = None

# Function to capture packets
def capture_packets(filter=None):
    global packets
    global capturing
    capturing = True
    packets.clear()

    try:
        if not interface:
            raise ValueError("No interface selected or available")

        print(f"Using interface: {interface}")
        if filter:
            sniff(iface=interface, filter=filter, prn=lambda x: packets.append(x), store=0, stop_filter=lambda x: not capturing)
        else:
            sniff(iface=interface, prn=lambda x: packets.append(x), store=0, stop_filter=lambda x: not capturing)
    except Exception as e:
        print(f"Error capturing packets: {e}")
        messagebox.showerror("Error", f"Error capturing packets: {e}")

# Function to update the packet list in the GUI
def update_packet_list(packet_list):
    packet_list.delete(0, tk.END)
    for pkt in packets:
        pkt_summary = pkt.summary()
        packet_list.insert(tk.END, pkt_summary)

# Function to start packet capturing in a new thread
def start_capture(filter_var, packet_list):
    filter_val = filter_var.get()
    thread = threading.Thread(target=capture_packets, args=(filter_val,))
    thread.daemon = True
    thread.start()
    root.after(1000, lambda: update_packet_list(packet_list))  # Schedule GUI update

# Function to stop packet capturing
def stop_capture():
    global capturing
    capturing = False

# Tkinter GUI setup
root = tk.Tk()
root.title("Network Packet Analyzer")

# Interface selection
interfaces = get_if_list()
if not interfaces:
    messagebox.showerror("Error", "No network interfaces found")
interface_var = tk.StringVar(value=interfaces[0] if interfaces else "")
interface_label = tk.Label(root, text="Select Interface:")
interface_label.grid(column=0, row=0)
interface_menu = tk.OptionMenu(root, interface_var, *interfaces)
interface_menu.grid(column=1, row=0)

# Function to set the interface
def set_interface():
    global interface
    interface = interface_var.get()
    if not interface:
        messagebox.showerror("Error", "No interface selected")
    else:
        messagebox.showinfo("Interface Selected", f"Capturing on: {interface}")

select_button = tk.Button(root, text="Set Interface", command=set_interface)
select_button.grid(column=2, row=0)

# Filter input
filter_label = tk.Label(root, text="Packet Filter:")
filter_label.grid(column=0, row=1)
filter_var = tk.StringVar()
filter_entry = tk.Entry(root, textvariable=filter_var)
filter_entry.grid(column=1, row=1, columnspan=2)

# Packet list
packet_list = tk.Listbox(root, height=15, width=100)
packet_list.grid(column=0, row=2, columnspan=3)

# Buttons
start_button = tk.Button(root, text="Start Capture", command=lambda: start_capture(filter_var, packet_list))
start_button.grid(column=0, row=3)
stop_button = tk.Button(root, text="Stop Capture", command=stop_capture)
stop_button.grid(column=1, row=3)

# ScrolledText for packet details
packet_details = scrolledtext.ScrolledText(root, width=100, height=10)
packet_details.grid(column=0, row=4, columnspan=3)

# Function to show packet details on selection
def show_packet_details(event):
    selected_packet_index = packet_list.curselection()
    if selected_packet_index:
        packet_details.delete(1.0, tk.END)
        packet_details.insert(tk.END, packets[selected_packet_index[0]].show(dump=True))

packet_list.bind('<<ListboxSelect>>', show_packet_details)

# Flask web interface
@app.route('/')
def index():
    packet_summary_list = [pkt.summary() for pkt in packets]
    return render_template_string("""
    <html>
    <head>
        <title>Network Packet Analyzer</title>
    </head>
    <body>
        <h1>Captured Packets</h1>
        <form method="post" action="/start">
            <label for="filter">Packet Filter:</label>
            <input type="text" id="filter" name="filter">
            <input type="submit" value="Start Capture">
        </form>
        <ul>
        {% for summary in packet_summary_list %}
            <li>{{ summary }}</li>
        {% endfor %}
        </ul>
    </body>
    </html>
    """, packet_summary_list=packet_summary_list)

@app.route('/start', methods=['POST'])
def start_capture_web():
    filter_val = request.form.get('filter')
    thread = threading.Thread(target=capture_packets, args=(filter_val,))
    thread.daemon = True
    thread.start()
    return index()

# Start Flask in a separate thread
def run_flask():
    app.run(debug=False, use_reloader=False)

flask_thread = threading.Thread(target=run_flask)
flask_thread.daemon = True
flask_thread.start()

# Run the Tkinter main loop
root.mainloop()