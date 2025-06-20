#!/usr/bin/env python3
"""
Password Vault Startup Script
Professional startup script with automatic port management and clean interface.
"""

import os
import sys
import socket
import subprocess
import signal
import time
from pathlib import Path

def find_free_port(start_port=5000, max_attempts=50):
    """Find a free port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"Could not find a free port in range {start_port}-{start_port + max_attempts}")

def kill_existing_processes():
    """Kill any existing Password Vault processes"""
    try:
        # Kill processes using common ports
        for port in [5000, 5001, 5002, 5003]:
            try:
                result = subprocess.run(['lsof', '-ti', f':{port}'], 
                                      capture_output=True, text=True)
                if result.stdout.strip():
                    pids = result.stdout.strip().split('\n')
                    for pid in pids:
                        try:
                            os.kill(int(pid), signal.SIGTERM)
                            print(f"🔄 Stopped process on port {port} (PID: {pid})")
                        except (ProcessLookupError, ValueError):
                            pass
            except FileNotFoundError:
                # lsof not available, try alternative
                pass
        
        # Kill Python processes running app.py
        try:
            result = subprocess.run(['pkill', '-f', 'python.*app.py'], 
                                  capture_output=True)
            if result.returncode == 0:
                print("🔄 Stopped existing Password Vault processes")
        except FileNotFoundError:
            pass
            
        time.sleep(1)  # Give processes time to stop
    except Exception as e:
        print(f"⚠️  Warning: Could not clean up existing processes: {e}")

def main():
    """Main startup function"""
    print("🔐 Password Vault - Professional Startup")
    print("=" * 50)
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Check if app.py exists
    if not Path("app.py").exists():
        print("❌ Error: app.py not found in current directory")
        sys.exit(1)
    
    # Clean up any existing processes
    print("🧹 Cleaning up existing processes...")
    kill_existing_processes()
    
    # Find a free port
    try:
        port = find_free_port()
        print(f"🔍 Found free port: {port}")
    except RuntimeError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    
    # Start the application
    print(f"🚀 Starting Password Vault on port {port}...")
    print(f"🌐 Access your vault at: http://localhost:{port}")
    print("=" * 50)
    print("💡 Tips:")
    print("   • Press Ctrl+C to stop the server")
    print("   • Use --debug flag for development mode")
    print("   • Use --port <number> to specify a custom port")
    print("=" * 50)
    
    try:
        # Start the Flask application
        cmd = [sys.executable, "app.py", "--port", str(port)]
        
        # Add debug flag if requested
        if "--debug" in sys.argv:
            cmd.append("--debug")
            
        # Add custom port if specified
        if "--port" in sys.argv:
            try:
                port_idx = sys.argv.index("--port")
                custom_port = int(sys.argv[port_idx + 1])
                cmd = [sys.executable, "app.py", "--port", str(custom_port)]
                if "--debug" in sys.argv:
                    cmd.append("--debug")
            except (IndexError, ValueError):
                print("❌ Error: Invalid port number specified")
                sys.exit(1)
        
        # Start the process
        process = subprocess.Popen(cmd)
        
        # Wait for the process to complete
        process.wait()
        
    except KeyboardInterrupt:
        print("\n🛑 Shutting down Password Vault...")
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            process.kill()
        print("👋 Password Vault stopped successfully")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 