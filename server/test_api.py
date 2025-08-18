#!/usr/bin/env python3
"""
Test script to interact with your WireGuard API
"""
import requests
import json
import sys

# Your API settings
API_BASE = "http://localhost:8080/api"

# First, let's find the actual API secret
print("🔍 Finding API secret...")
try:
    import config
    api_secret = config.get_config().API_SECRET
    print(f"✅ Found API secret: {api_secret[:10]}...")
except Exception as e:
    print(f"❌ Could not get API secret: {e}")
    api_secret = input("Enter your API secret (check server logs): ")

headers = {
    "Authorization": f"Bearer {api_secret}",
    "Content-Type": "application/json"
}

def test_api():
    print("🧪 Testing WireGuard API...\n")
    
    # Test 1: Get Status
    print("1. Getting server status...")
    try:
        response = requests.get(f"{API_BASE}/status", headers=headers)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Server is running: {data.get('is_running')}")
            print(f"   Peers count: {data.get('peers_count')}")
        elif response.status_code == 401:
            print("❌ Authentication failed - check your API secret")
            return
        else:
            print(f"❌ Error: {response.text}")
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - is your server running?")
        return
    
    print("\n" + "-"*50 + "\n")
    
    # Test 2: Add a peer
    print("2. Adding a test peer...")
    test_peer_data = {
        "public_key": "dGVzdF9wdWJsaWNfa2V5XzEyMzQ1Njc4OTA=",  # Base64 encoded test key
        "user_id": 12345,
        "device_id": 1
    }
    
    try:
        response = requests.post(f"{API_BASE}/peer/add", headers=headers, json=test_peer_data)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Peer added successfully!")
            print(f"   Peer ID: {data.get('peer_id')}")
            print(f"   Assigned IP: {data.get('assigned_ip')}")
            
            # Show the client config
            config = data.get('config')
            if config:
                print(f"\n📋 Client Configuration:")
                print("-" * 30)
                print(config)
                print("-" * 30)
        else:
            data = response.json()
            print(f"❌ Error: {data.get('message')}")
    except Exception as e:
        print(f"❌ Error adding peer: {e}")
    
    print("\n" + "-"*50 + "\n")
    
    # Test 3: Get updated status
    print("3. Getting updated server status...")
    try:
        response = requests.get(f"{API_BASE}/status", headers=headers)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Updated peers count: {data.get('peers_count')}")
            peers = data.get('peers', [])
            if peers:
                print("   Active peers:")
                for peer in peers:
                    print(f"   - Peer ID: {peer[0]}, IP: {peer[2]}, User: {peer[3]}")
        else:
            print(f"❌ Error: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")

    print("\n" + "-"*50 + "\n")
    
    # Test 4: Generate config for the peer we just added
    print("4. Getting client config...")
    try:
        response = requests.get(f"{API_BASE}/peer/config/{test_peer_data['public_key']}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            print("✅ Retrieved client config:")
            print("-" * 40)
            print(data.get('config'))
            print("-" * 40)
        else:
            print(f"❌ Error: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    # Check if server is running first
    try:
        response = requests.get("http://localhost:8080/api/status", timeout=2)
    except requests.exceptions.ConnectionError:
        print("❌ Server not running! Start it first with: python start_dev.py")
        sys.exit(1)
    
    test_api()