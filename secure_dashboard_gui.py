
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests
import os
from playsound import playsound
import threading

API_URL = "http://127.0.0.1:5000/analyze"
ALARM_PATH = "alarm/alarm.wav"

def play_alarm():
    while alarm_flag["active"]:
        playsound(ALARM_PATH)

def stop_alarm():
    alarm_flag["active"] = False

def analyze_file(filepath, output_box):
    try:
        with open(filepath, "rb") as f:
            files = {"file": f}
            response = requests.post(API_URL, files=files)
        if response.status_code == 200:
            result = response.json()
            msg = f"""
[RESULT]
Filename: {result['filename']}
Entropy: {result['entropy']}
Size (KB): {result['size_kb']}
Extension: {result['extension']}
Prediction: {result['prediction']}
VirusTotal: {result['virustotal']}
"""
            output_box.insert(tk.END, msg + "\n")
            output_box.see(tk.END)

            if result["prediction"] == "Ransomware":
                alarm_flag["active"] = True
                threading.Thread(target=play_alarm).start()
                messagebox.showwarning("Threat Detected", "Ransomware detected! Alarm triggered!")
        else:
            output_box.insert(tk.END, "[ERROR] Server Error\n")
    except Exception as e:
        output_box.insert(tk.END, f"[ERROR] {str(e)}\n")

def browse_file(output_box):
    filepath = filedialog.askopenfilename()
    if filepath:
        output_box.insert(tk.END, f"[INFO] Selected file: {filepath}\n")
        analyze_file(filepath, output_box)

def stop_alarm_gui():
    stop_alarm()
    messagebox.showinfo("Alarm", "Alarm stopped by admin.")

# Main GUI Window
app = tk.Tk()
app.title("Smart Ransomware Defender")
app.geometry("650x500")

alarm_flag = {"active": False}

frame = tk.Frame(app)
frame.pack(pady=10)

select_btn = tk.Button(frame, text="Select File for Analysis", command=lambda: browse_file(output_box))
select_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(frame, text="Stop Alarm", command=stop_alarm_gui)
stop_btn.pack(side=tk.LEFT, padx=10)

output_box = scrolledtext.ScrolledText(app, height=20, width=80)
output_box.pack(pady=10)

app.mainloop()
