#core for building APIs
from flask import Flask, request, jsonify
from flask_cors import CORS
# enables real-time communication (WebSocket) between server and frontend.
from flask_socketio import SocketIO, emit
import requests #allows making HTTP requests
# or time tracking and background tasks
import time
import threading
# for reading environment variables
import os

app = Flask(__name__) #initializes the Flask app
CORS(app)# allows your API to be accessed from any frontend (e.g. HTML)
socketio = SocketIO(app, cors_allowed_origins="*")#sets up real-time WebSocket support

# Reads URL
AUTH_SERVER_URL = os.environ.get('AUTH_SERVER_URL', 'http://auth-server:5000')

# Simulated IoT devices state & a type 
iot_devices = {
    'gates': {'status': 'closed', 'type': 'actuator'},
    'lights': {'status': 'off', 'type': 'actuator'},
    'garage': {'status': 'closed', 'type': 'actuator'},
    'bike_storage': {'status': 'locked', 'type': 'actuator'},
    'alarm': {'status': 'armed', 'type': 'sensor'}
}

# Track active devices and their locations
active_devices = {}# track of currently authenticated/active device
proximity_zones = {}# maps device locations

# Security monitoring
security_events = []# logs security-related events
rate_limiter = {}# tracks request frequency to prevent abuse

class SecureGateway:
    def __init__(self):
        self.device_sessions = {}
        self.zone_controllers = {}
        self.security_policy = {
            'max_failed_attempts': 5,
            'rate_limit_window': 60,  # seconds
            'max_requests_per_window': 30,
            'auto_timeout': 300  # 5 minutes
        }
        
        # Start background thread to monitor inactivity
        self.start_security_monitor()
            
    """handle incoming advertisement from device"""
    def handle_advertisement(self, advertisement_data):
        
        # Rate limiting check(get divice ID)
        device_id = advertisement_data.get('device_id')
        if not self._check_rate_limit(device_id):#Prevent flooding by checking request rate
            self._log_security_event('rate_limit_exceeded', device_id)
            return False, "Rate limit exceeded"
        
        # Forward to auth server for verification
        try:
            response = requests.post(
                f'{AUTH_SERVER_URL}/verify_advertisement',
                json=advertisement_data,
                timeout=5
            )
            # if succeeded {1.log device in, 2. trigger action->open gate, 3. notify clients->Websockert }
            if response.status_code == 200:
                verified_data = response.json()
                if verified_data['verified']:
                    device_info = verified_data['device_info']
                    
                    # Update active devices
                    self._update_active_device(device_info)
                    
                    # Trigger zone-based actions
                    actions = self._trigger_zone_actions(device_info)
                    
                    # Log successful authentication
                    self._log_security_event('authentication_success', device_id)
                    
                    return True, {
                        'device_info': device_info,
                        'actions': actions
                    }
            
            # Log failed authentication
            self._log_security_event('authentication_failed', device_id)
            return False, "Advertisement verification failed"
            
        except Exception as e:
            self._log_security_event('system_error', device_id, str(e))
            return False, f"Gateway error: {str(e)}"
    
    def _check_rate_limit(self, device_id):
        """Check if device is within rate limits(no abuse from a single device)"""
        current_time = time.time()
        
        if device_id not in rate_limiter:
            rate_limiter[device_id] = {
                'requests': [],
                'blocked_until': 0
            }
        
        # Check if device is blocked
        if current_time < rate_limiter[device_id]['blocked_until']:
            return False
        
        # Clean old requests
        window_start = current_time - self.security_policy['rate_limit_window']
        rate_limiter[device_id]['requests'] = [
            t for t in rate_limiter[device_id]['requests'] 
            if t > window_start
        ]
        
        # Check rate limit
        if len(rate_limiter[device_id]['requests']) >= self.security_policy['max_requests_per_window']:
            rate_limiter[device_id]['blocked_until'] = current_time + 300  # 5 min block
            return False
        
        # Add current request
        rate_limiter[device_id]['requests'].append(current_time)
        return True
    
    def _update_active_device(self, device_info):
        """Update active device tracking(session and locatio )"""
        device_id = device_info['device_id']
        location = device_info['location']
        
        active_devices[device_id] = {
            'device_type': device_info['device_type'],
            'location': location,
            'last_seen': time.time(),
            'access_level': device_info['access_level'],
            'session_start': active_devices.get(device_id, {}).get('session_start', time.time())
        }
        
        # Update zone tracking
        if location not in proximity_zones:
            proximity_zones[location] = set()
        
        # Clear device from other zones
        for zone, devices in list(proximity_zones.items()):
            if zone != location and device_id in devices:
                devices.remove(device_id)
        
        proximity_zones[location].add(device_id)
    
    def _trigger_zone_actions(self, device_info):
        """Trigger actions based on device location and permissions"""
        location = device_info['location']
        access_level = device_info['access_level']
        actions = []
        
        # Zone-based automation rules
        if location == 'entrance':
            if 'gates' in access_level:
                self._actuate_device('gates', 'open')
                actions.append({'device': 'gates', 'action': 'open'})
            
            if 'lights' in access_level:
                self._actuate_device('lights', 'on')
                actions.append({'device': 'lights', 'action': 'on'})
                
        elif location == 'garage':
            if 'garage' in access_level:
                self._actuate_device('garage', 'open')
                actions.append({'device': 'garage', 'action': 'open'})
                
        elif location == 'bike_area':
            if 'bike_storage' in access_level:
                self._actuate_device('bike_storage', 'unlocked')
                actions.append({'device': 'bike_storage', 'action': 'unlock'})
        
        # Disarm alarm if any authorized device is present
        if len(actions) > 0:
            self._actuate_device('alarm', 'disarmed')
            actions.append({'device': 'alarm', 'action': 'disarm'})
        
        # Emit real-time updates
        socketio.emit('zone_activity', {
            'location': location,
            'device_info': device_info,
            'actions': actions,
            'timestamp': time.time()
        })
        
        return actions
    
    def _actuate_device(self, device_name, new_status):
        """Actuate IoT device(updates device state)"""
        if device_name in iot_devices:
            iot_devices[device_name]['status'] = new_status
            
            # Emit status update
            socketio.emit('iot_status_update', iot_devices)
    
    def _log_security_event(self, event_type, device_id, details=None):
        """Log security events"""
        event = {
            'timestamp': time.time(),
            'event_type': event_type,
            'device_id': device_id,
            'details': details
        }
        
        security_events.append(event)
        
        # Keep only recent events
        if len(security_events) > 1000:
            security_events.pop(0)
        
        # Emit security event
        socketio.emit('security_event', event)
    
    def start_security_monitor(self):
        """Start background security monitoring(thread removes inactive devices)"""
        def monitor():
            while True:
                current_time = time.time()
                
                # Check for inactive devices
                inactive_devices = []
                # Iterate over a copy: request threads may change the dict at the same time
                for device_id, device_data in list(active_devices.items()):
                    if current_time - device_data['last_seen'] > self.security_policy['auto_timeout']:
                        inactive_devices.append(device_id)
                
                # Remove inactive devices
                for device_id in inactive_devices:
                    active_devices.pop(device_id, None)
                    for devices in proximity_zones.values():
                        devices.discard(device_id)
                    self._log_security_event('device_timeout', device_id)
                
                # Clean up empty zones
                empty_zones = [
                    zone for zone, devices in list(proximity_zones.items())
                    if len(devices) == 0
                ]
                for zone in empty_zones:
                    proximity_zones.pop(zone, None)
                
                # Check if premises should be secured
                if len(active_devices) == 0:
                    self._secure_premises()
                
                time.sleep(10)  # Check every 10 seconds
        
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
    
    def _secure_premises(self):
        """Secure all devices when no authorized devices present"""
        iot_devices['gates']['status'] = 'closed'
        iot_devices['lights']['status'] = 'off'
        iot_devices['garage']['status'] = 'closed'
        iot_devices['bike_storage']['status'] = 'locked'
        iot_devices['alarm']['status'] = 'armed'
        
        socketio.emit('iot_status_update', iot_devices)
        self._log_security_event('premises_secured', 'system')

# Initialize gateway
gateway = SecureGateway()

@app.route('/advertise', methods=['POST'])
def handle_advertisement():
    """Handle device advertisement"""
    advertisement_data = request.json
    
    success, result = gateway.handle_advertisement(advertisement_data)
    
    if success:
        return jsonify({
            'success': True,
            'device_info': result['device_info'],
            'actions': result['actions']
        }), 200
    
    return jsonify({
        'success': False,
        'error': result
    }), 401

@app.route('/status', methods=['GET'])
def get_status():
    """Get current system status"""
    return jsonify({
        'iot_devices': iot_devices,
        'active_devices': active_devices,
        'proximity_zones': {
            zone: list(devices) for zone, devices in proximity_zones.items()
        },
        'security_events': security_events[-50:]  # Last 50 events
    }), 200

@app.route('/control/<device>', methods=['POST'])
def control_device(device):
    """Manual control of IoT devices (requires admin auth)"""
    data = request.json
    action = data.get('action')
    
    # In production, add proper admin authentication here
    
    if device not in iot_devices:
        return jsonify({'error': 'Device not found'}), 404
    
    # Map actions to status
    status_map = {
        'open': 'open',
        'close': 'closed',
        'on': 'on',
        'off': 'off',
        'lock': 'locked',
        'unlock': 'unlocked',
        'arm': 'armed',
        'disarm': 'disarmed'
    }
    
    if action in status_map:
        gateway._actuate_device(device, status_map[action])
        gateway._log_security_event('manual_control', 'admin', f'{device}:{action}')
        
        return jsonify({'message': f'{device} {action} successful'}), 200
    
    return jsonify({'error': 'Invalid action'}), 400

@app.route('/security/events', methods=['GET'])
def get_security_events():
    """Get security event log"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(security_events[-limit:]), 200

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('iot_status_update', iot_devices)
    emit('active_devices', active_devices)

@socketio.on('request_status')
def handle_status_request():
    """Handle status request via WebSocket"""
    emit('full_status', {
        'iot_devices': iot_devices,
        'active_devices': active_devices,
        'proximity_zones': {
            zone: list(devices) for zone, devices in proximity_zones.items()
        }
    })

if __name__ == '__main__':
    # Debug mode is off by default; set FLASK_DEBUG=1 only for local development
    socketio.run(app, host='0.0.0.0', port=5001,
                 debug=os.environ.get('FLASK_DEBUG') == '1', allow_unsafe_werkzeug=True)
