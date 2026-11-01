import requests #HTTP communication
import time
#Security & cryptography
import hmac
import hashlib
import secrets
#Parallel execution
import threading
import os #Environment variables
import base64
import random #Simulating real-world randomness

#contact the gateway and auth server
GATEWAY_URL = os.environ.get('GATEWAY_URL', 'http://gateway:5001')
AUTH_SERVER_URL = os.environ.get('AUTH_SERVER_URL', 'http://auth-server:5000')

# Initialize a new simulated smart device with ID, type  and a shared secret
class SecureAdvertisingDevice:
    def __init__(self, device_id, device_type, shared_secret):
        # Store parameters 
        self.device_id = device_id
        self.device_type = device_type
        self.shared_secret = shared_secret
        self.device_key = None # it will be received after registration
        # Create a fake public key using a hash 
        self.public_key = self._generate_public_key()
        # Control loop running
        self.running = True
        self.advertisement_interval = 5  # seconds
        self.signal_strength = -50  # RSSI simulation
        
        # Proximity simulation -> where the device is
        self.current_location = 'away'
        # Base values stay below the auth server's 1 ms response-time limit even with
        # +/-20% random noise (0.0009 * 1.2 = 1.08 ms used to fail ~20% of bike checks)
        self.proximity_data = {# how close each location
            'entrance': {'rssi': -45, 'response_time': 0.0005},
            'garage': {'rssi': -50, 'response_time': 0.0007},
            'bike_area': {'rssi': -55, 'response_time': 0.0008},
            'away': {'rssi': -90, 'response_time': 0.1}
        }
    
    def _generate_public_key(self):
        """Generate a simulated public key"""
        # In production, use proper cryptographic key generation(Encoded to base64)
        return base64.b64encode(
            hashlib.sha256(f"{self.device_id}:{self.shared_secret}:public".encode()).digest()
        ).decode()
    
    #Sends device data to the auth server to get a device key
    def register(self):
        """Register device with authentication server"""
        #(POSTs registration data to /register)
        try:
            response = requests.post(f'{AUTH_SERVER_URL}/register', json={
                'device_id': self.device_id,
                'public_key': self.public_key,
                'device_type': self.device_type,
                'shared_secret': self.shared_secret
            })
            #decodes and stores the secret key
            if response.status_code == 201:
                data = response.json()
                self.device_key = base64.b64decode(data['device_key'])
                print(f"[{self.device_id}] Registration successful")
                return True
            else:
                print(f"[{self.device_id}] Registration failed: {response.json()}")
                return False
                
        except Exception as e:
            print(f"[{self.device_id}] Registration error: {str(e)}")
            return False
    
    """Creates secure advertisement packet to send to the gateway"""
    def generate_advertisement(self, location):
        #nonce
        timestamp = time.time()
        nonce = secrets.token_hex(16)
        
        # Create advertisement data(e.g proximity proof-> RSSI + response_time)
        advertisement = {
            'device_id': self.device_id,
            'timestamp': timestamp,
            'nonce': nonce,
            'location': location,
            'proximity_proof': self._generate_proximity_proof(location)
        }
        
        # Generate HMAC signature & adds the signature
        message = f"{self.device_id}:{timestamp}:{nonce}:{location}".encode()
        signature = hmac.new(self.device_key, message, hashlib.sha256).hexdigest()
        advertisement['signature'] = signature
        
        return advertisement
    
    #Returns slightly randomized RSSI and response_time for the location
    def _generate_proximity_proof(self, location):
        """Generate proximity proof data"""
        if location in self.proximity_data:
            proximity = self.proximity_data[location]
            # Add some randomness to simulate real-world conditions
            return {
                'rssi': proximity['rssi'] + random.randint(-5, 5),
                'response_time': proximity['response_time'] * random.uniform(0.8, 1.2)
            }
        return {}
    #Sends the generated advertisement to the gateway
    def advertise(self):
        """Broadcast secure advertisement"""
        if self.current_location == 'away':
            print(f"[{self.device_id}] Not in range, skipping advertisement")
            return
        #Skips if the device is “away”
        advertisement = self.generate_advertisement(self.current_location)
        
        try:#POSTs to the gateway’s /advertise
            response = requests.post(
                f'{GATEWAY_URL}/advertise',
                json=advertisement,
                timeout=5
            )
            #Prints if accepted and shows actions triggered
            if response.status_code == 200:
                data = response.json()
                actions = data.get('actions', [])
                print(f"[{self.device_id}] Advertisement accepted at {self.current_location}")
                if actions:
                    print(f"[{self.device_id}] Triggered actions: {actions}")
            else:
                print(f"[{self.device_id}] Advertisement rejected: {response.json()}")
                
        except Exception as e:
            print(f"[{self.device_id}] Advertisement error: {str(e)}")
    
    """Simulate device movement between locations"""
    def simulate_movement(self):
        #Each device type has a different movement pattern
        locations = ['entrance', 'garage', 'bike_area', 'away']
        location_probabilities = {
            'smartphone': [0.4, 0.1, 0.1, 0.4],
            'smartcar': [0.2, 0.5, 0.0, 0.3],
            'smartbike': [0.2, 0.0, 0.6, 0.2]
        }
        
        # Get probabilities for this device type
        probs = location_probabilities.get(self.device_type, [0.25, 0.25, 0.25, 0.25])
        
        # Choose next location based on device type
        while self.running:
            self.current_location = random.choices(locations, weights=probs)[0]
            
            print(f"[{self.device_id}] Moved to {self.current_location}")
            
            # Advertise at new location
            self.advertise()
            
            # Stay at location for random duration
            stay_duration = random.uniform(10, 30)
            time.sleep(stay_duration)
    
    def start_advertising(self):
        """Start periodic advertisement broadcasting(Thread & movement...) """
        def advertise_loop():
            while self.running:
                if self.current_location != 'away':
                    self.advertise()
                time.sleep(self.advertisement_interval)
        
        # Start advertisement thread
        adv_thread = threading.Thread(target=advertise_loop, daemon=True)
        adv_thread.start()
        
        # Start movement simulation
        self.simulate_movement()
    
    def stop(self):
        """Stop the device simulation"""
        self.running = False
    
"""Manage multiple simulated devices(Manages a list of devices.)"""
class DeviceFleet:
    def __init__(self):
        self.devices = []
    def add_device(self, device_id, device_type, shared_secret):
        """Add a device to the fleet"""
        device = SecureAdvertisingDevice(device_id, device_type, shared_secret)
        self.devices.append(device)
        return device
    
    #Registers all devices with the auth server
    def register_all(self):
        """Register all devices"""
        for device in self.devices:
            if not device.register():
                print(f"Failed to register {device.device_id}")
                return False
        return True
    
    #Starts all devices in their own thread and waits for them to run
    def start_all(self):
        """Start all device simulations"""
        threads = []
        
        for i, device in enumerate(self.devices):
            # Stagger device starts
            time.sleep(2)
            
            thread = threading.Thread(
                target=device.start_advertising,
                daemon=True
            )
            thread.start()
            threads.append(thread)
            
            print(f"Started device {device.device_id}")
        
        # Wait for all threads
        try:
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            print("\nStopping all devices...")
            for device in self.devices:
                device.stop()
                
#The main driver of the program
def simulate_secure_advertising_system():
    """Main simulation function"""
    print("Starting Secure Advertisement System Simulation")
    print("=" * 50)
    
    # Create device fleet
    fleet = DeviceFleet()
    
    # Add devices with different types and secrets
    devices_config = [
        ('phone-001', 'smartphone', 'secret-phone-001'),
        ('phone-002', 'smartphone', 'secret-phone-002'),
        ('car-001', 'smartcar', 'secret-car-001'),
        ('bike-001', 'smartbike', 'secret-bike-001')
    ]
    
    for device_id, device_type, secret in devices_config:
        fleet.add_device(device_id, device_type, secret)
    
    # Wait for services to be ready
    print("Waiting for services to start...")
    time.sleep(5)
    
    # Register all devices
    print("\nRegistering devices...")
    if not fleet.register_all():
        print("Device registration failed!")
        return
    
    print("\nStarting device advertisements...")
    print("Devices will move between locations and broadcast secure advertisements")
    print("Press Ctrl+C to stop simulation\n")
    
    # Start all devices
    fleet.start_all()

if __name__ == '__main__':
    simulate_secure_advertising_system()
