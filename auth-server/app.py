from flask import Flask, request, jsonify #creating web server and APIs & get incoming JSON data & return data as JSON responses
from flask_cors import CORS #Cross-Origin Resource Sharing so that frontends from other origins can access the API
#for generating/validating secure signatures
import hmac 
import hashlib
# for timestamps
import time 
import secrets #for securely generating tokens
import base64 # Used to encode/decode binary data
import os # for reading environment variables

# Initializes the Flask app and allows CORS so frontend clients can access the API.
app = Flask(__name__)
CORS(app)

# Secure Advertisement-Based Authentication System(Core Authentication Logic)
class SecureAdvertisementAuth:
    def __init__(self):
        self.registered_devices = {} #A list of all authorized devices (Stores registered device info)
        self.time_window = 30  # 30 seconds for time-based tokens validity
        self.proximity_threshold = 10  # meters(concept of the real world)
        self.replay_cache = {}  # Prevent replay attacks(attackers can't reuse them)->Stores used nonces
        self.challenge_cache = {}  # Active challenges ->Stores challenges for optional extra authentication
        
    def register_device(self, device_id, public_key, device_type, shared_secret):
        """Register device with public key and shared secret for HMAC"""
        # Create a unique device-specific key (SHA-256 of device id + shared secret)
        device_key = hashlib.sha256(f"{device_id}{shared_secret}".encode()).digest()

        if device_id in self.registered_devices:
            # A device that restarts may register again, but only with the same secret.
            # A different secret for an existing ID is rejected (possible impersonation).
            stored_key = base64.b64decode(self.registered_devices[device_id]['device_key'])
            if hmac.compare_digest(stored_key, device_key):
                return True, device_key
            return False, "Device already registered with different credentials"

        #Stores device info
        self.registered_devices[device_id] = {
            'public_key': public_key,
            'device_type': device_type,
            'device_key': base64.b64encode(device_key).decode(),
            'registered_at': time.time(),
            'access_level': self._determine_access_level(device_type),
            'last_advertisement': None,
            'failed_attempts': 0
        }
        
        return True, device_key # Returns success and the hashed key 

    """Determine access level based on device type"""
    def _determine_access_level(self, device_type):
        access_levels = {
            'smartphone': ['gates', 'lights'],
            'smartcar': ['gates', 'garage', 'lights'],
            'smartbike': ['gates', 'bike_storage']
        }
        return access_levels.get(device_type, [])
    
    """Main Function to Verify cryptographic advertisement from device if broadcasted """
    def verify_advertisement(self, advertisement_data):
        
        try:# analyze the data received from the device.
            device_id = advertisement_data.get('device_id')
            timestamp = advertisement_data.get('timestamp')
            nonce = advertisement_data.get('nonce')
            location = advertisement_data.get('location')
            signature = advertisement_data.get('signature')
            proximity_proof = advertisement_data.get('proximity_proof', {})
            
            # Check if device is registered (Rejects unknown devices)
            if device_id not in self.registered_devices:
                return False, "Unknown device"
            
            device = self.registered_devices[device_id]
            
            # Checks if this nonce was used before (to block replay attacks)
            if self._is_replay_attack(device_id, nonce, timestamp):
                device['failed_attempts'] += 1
                return False, "Replay attack detected"
            
            # Validates the timestamp is recent (prevent old advertisements)
            if not self._verify_timestamp(timestamp):
                return False, "Advertisement expired"
            
            # Verify HMAC signature (Recomputes what the HMAC signature should be)
            expected_signature = self._generate_signature(
                device_id, timestamp, nonce, location, 
                base64.b64decode(device['device_key'])
            )
            
            # Compares provided signature with expected one securely
            if not hmac.compare_digest(signature, expected_signature):
                device['failed_attempts'] += 1
                return False, "Invalid signature"
            
            # Verify proximity if provided(validates signal strength and timing)
            if proximity_proof:
                if not self._verify_proximity(proximity_proof):
                    return False, "Proximity verification failed"
            
            # Update device Info
            device['last_advertisement'] = time.time()
            device['failed_attempts'] = 0
            
            # Add to replay cache (prevents nonce from being used again)
            self._add_to_replay_cache(device_id, nonce, timestamp)
            
            #Returns verified device data.
            return True, {
                'device_id': device_id,
                'device_type': device['device_type'],
                'access_level': device['access_level'],
                'location': location
            }
            
        except Exception as e:
            return False, f"Advertisement verification failed: {str(e)}"
    # Creates HMAC by secret device key and the device’s advertisement fields
    def _generate_signature(self, device_id, timestamp, nonce, location, device_key):
        
        message = f"{device_id}:{timestamp}:{nonce}:{location}".encode()
        return hmac.new(device_key, message, hashlib.sha256).hexdigest()
    
    #Returns True if timestamp is within 30 secondsf current time
    def _verify_timestamp(self, timestamp):
        """Verify timestamp is within acceptable window"""
        current_time = time.time()
        return abs(current_time - timestamp) <= self.time_window
    
    #Returns True if same nonce used recently for the same device
    def _is_replay_attack(self, device_id, nonce, timestamp):
        """Check if this is a replay attack"""
        cache_key = f"{device_id}:{nonce}"
        
        # Clean old entries (if older than 2 * time_window -> 1 min)
        self._clean_replay_cache()
        
        # Check if nonce was already used
        if cache_key in self.replay_cache:
            return True
        
        return False
    
    def _add_to_replay_cache(self, device_id, nonce, timestamp):
        """Add advertisement to replay cache"""
        cache_key = f"{device_id}:{nonce}"
        self.replay_cache[cache_key] = timestamp
    
    def _clean_replay_cache(self):
        """Remove old entries from replay cache"""
        current_time = time.time()
        expired_keys = []
        
        for key, timestamp in self.replay_cache.items():
            if current_time - timestamp > self.time_window * 2:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.replay_cache[key]
    
    #Checks if signal strength is strong enough and response time is low 
    def _verify_proximity(self, proximity_proof):
        # Implement distance bounding protocol
        signal_strength = proximity_proof.get('rssi', -100)
        response_time = proximity_proof.get('response_time', float('inf'))
        
        # Simple proximity check (can be enhanced with UWB or distance bounding)
        if signal_strength > -70 and response_time < 0.001:  # 1ms
            return True
        
        return False
    
    #extra security layer (Stores it in challenge_cache)
    def generate_challenge(self, device_id):
        """Generate challenge for enhanced security (optional)"""
        if device_id not in self.registered_devices:
            return None
        
        challenge = secrets.token_hex(32)
        challenge_id = secrets.token_urlsafe(16)
        
        self.challenge_cache[challenge_id] = {
            'device_id': device_id,
            'challenge': challenge,
            'created_at': time.time(),
            'used': False
        }
        
        return {
            'challenge_id': challenge_id,
            'challenge': challenge
        }

# Initialize the authentication system
auth_system = SecureAdvertisementAuth()

#Registers a device using JSON input (Returns status and the generated key (encoded))
@app.route('/register', methods=['POST'])
def register_device():
    """Register a new device with secure advertisement capability"""
    data = request.json
    device_id = data.get('device_id')
    public_key = data.get('public_key')
    device_type = data.get('device_type')
    shared_secret = data.get('shared_secret')
    

    if not all([device_id, public_key, device_type, shared_secret]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    success, result = auth_system.register_device(
        device_id, public_key, device_type, shared_secret
    )
    
    if success:
        return jsonify({
            'message': 'Device registered successfully',
            'device_id': device_id,
            'device_key': base64.b64encode(result).decode()
        }), 201
    
    return jsonify({'error': result}), 400

#Accepts an “advertisement” from the device and verifies its authenticity.
@app.route('/verify_advertisement', methods=['POST'])
def verify_advertisement():
    """Verify cryptographic advertisement from device"""
    advertisement_data = request.json
    
    success, result = auth_system.verify_advertisement(advertisement_data)
    
    if success:
        return jsonify({
            'verified': True,
            'device_info': result
        }), 200
    
    return jsonify({
        'verified': False,
        'error': result
    }), 401

#Optional feature: returns a challenge for the device to solve (challenge-response extension)
@app.route('/challenge/<device_id>', methods=['GET'])
def get_challenge(device_id):
    """Get challenge for enhanced security """
    challenge_data = auth_system.generate_challenge(device_id)
    
    if challenge_data:
        return jsonify(challenge_data), 200
    
    return jsonify({'error': 'Device not registered'}), 404

#Lists all registered devices with basic info
@app.route('/devices', methods=['GET'])
def list_devices():
    """List all registered devices"""
    devices = {}
    for device_id, device_info in auth_system.registered_devices.items():
        devices[device_id] = {
            'device_type': device_info['device_type'],
            'access_level': device_info['access_level'],
            'last_advertisement': device_info['last_advertisement'],
            'failed_attempts': device_info['failed_attempts']
        }
    
    return jsonify(devices), 200

#Health check API: tells you if the server is running and how many devices are active.
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'active_devices': len(auth_system.registered_devices),
        'replay_cache_size': len(auth_system.replay_cache)
    }), 200

#Starts the Flask app on all available IPs, port 5000.
#Debug mode is off by default (the Werkzeug debugger must never be exposed on 0.0.0.0);
#set FLASK_DEBUG=1 only for local development.
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('FLASK_DEBUG') == '1')
