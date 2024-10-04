from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/home', methods=['GET'])
def home():
    return jsonify('Welcome to the Home Page!')

@app.route('/help', methods=['GET'])
def help():
    return jsonify('Here is some help information.')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
