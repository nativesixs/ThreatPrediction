from flask import Flask
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import time
from datetime import datetime
from scapy.all import sniff

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins
socketio = SocketIO(app, cors_allowed_origins="*")

# To keep track of whether we're currently sending time and traffic
sending = False

@app.route('/home')
def home():
    return "Welcome to the Home Page!"

@socketio.on('request_time')
def send_time_and_traffic():
    global sending
    if sending:
        return  # If already sending, do nothing

    sending = True

    def capture_traffic(packet):
        # This is a simplified example; you can modify the capture logic as needed
        traffic_info = f"Packet: {packet.summary()}"
        print(traffic_info)  # Print to console for debugging
        time.sleep(3) #safety
        socketio.emit('traffic', {'traffic': traffic_info})  # Send traffic data to the client

    # Start capturing packets
    sniff(prn=capture_traffic, store=0, count=0)  # Will run indefinitely

    while sending:
        current_time = datetime.now().strftime('%H:%M:%S')  # Get current time in HH:MM:SS format
        emit('time', {'time': current_time})  # Send current time to the client
        time.sleep(1)  # Send every second

    emit('complete', {'data': 'Finished sending time and traffic!'})  # Indicate completion (this won't actually be reached)

@socketio.on('stop_time')
def stop_time():
    global sending
    sending = False  # Allow stopping sending if needed

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
