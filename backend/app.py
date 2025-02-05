from flask import Flask
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import TCP
import threading
import time

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*")

sending = False
sniffing_active = False
stop_sniffing_flag = False

@app.route('/home')
def home():
    return "Welcome to the Home Page!"

# Function to capture network traffic
def capture_traffic(packet):
    if packet.haslayer(TCP):
        socketio.emit('traffic', {'traffic': packet.summary()})

# Sniffing function with stop_filter
def sniffing_loop():
    global stop_sniffing_flag
    sniff(prn=capture_traffic, store=0, stop_filter=lambda x: stop_sniffing_flag)

# Start Sniffing Event
@socketio.on('start_sniffing')
def start_sniffing():
    global sniffing_active, stop_sniffing_flag
    if not sniffing_active:
        sniffing_active = True
        stop_sniffing_flag = False
        threading.Thread(target=sniffing_loop).start()  # Run sniffing in a separate thread
        emit('complete', {'data': 'Started sniffing!'})

# Stop Sniffing Event
@socketio.on('stop_sniffing')
def stop_sniffing():
    global stop_sniffing_flag, sniffing_active
    stop_sniffing_flag = True
    sniffing_active = False
    emit('complete', {'data': 'Stopped sniffing!'})

# Start Sending Time
@socketio.on('request_time')
def send_time():
    global sending
    if sending:
        return
    sending = True
    while sending:
        current_time = datetime.now().strftime('%H:%M:%S')
        emit('time', {'time': current_time})
        time.sleep(1)
    emit('complete', {'data': 'Stopped sending time!'})

# Stop Sending Time
@socketio.on('stop_time')
def stop_time():
    global sending
    sending = False
    emit('complete', {'data': 'Stopped time updates!'})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
