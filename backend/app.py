from flask import Flask
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import time
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins
socketio = SocketIO(app, cors_allowed_origins="*")

# To keep track of whether we're currently sending time
sending = False

@app.route('/home')
def home():
    return "Welcome to the Home Page!"

@app.route('/help')
def help():
    return "Welcome to the Help Page!"

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('response', {'data': 'Connected to WebSocket!'})

@socketio.on('request_time')
def send_time():
    global sending
    if sending:
        return  # If already sending, do nothing

    sending = True
    while sending:
        current_time = datetime.now().strftime('%H:%M:%S')  # Get current time in HH:MM:SS format
        emit('time', {'time': current_time})  # Send current time to the client
        time.sleep(1)  # Send every second
    emit('complete', {'data': 'Finished sending time!'})  # Indicate completion (this won't actually be reached)

@socketio.on('stop_time')
def stop_time():
    global sending
    sending = False  # Allow stopping sending if needed

@socketio.on('message')
def handle_message(data):
    print('Received message: ' + str(data))
    emit('response', {'data': 'Message received!'})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000,allow_unsafe_werkzeug=True) #todo - remove unsafe werkzeug for prod
