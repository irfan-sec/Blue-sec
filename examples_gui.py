#!/usr/bin/env python3
"""
Blue-sec GUI Examples
Demonstrates how to use the GUI programmatically
"""

import sys
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules import BlueSecConfig, run_gui
from modules.scanner import BluetoothDevice


def example_basic_gui():
    """
    Example 1: Launch basic GUI with default configuration
    """
    print("Example 1: Launching basic GUI...")
    print("This will open the GUI with default settings")
    
    config = BlueSecConfig()
    run_gui(config)


def example_custom_config_gui():
    """
    Example 2: Launch GUI with custom configuration
    """
    print("Example 2: Launching GUI with custom config...")
    
    # Create custom configuration
    config = BlueSecConfig()
    config.scanner.active_scan_timeout = 15
    config.debug_mode = True
    
    print(f"Scanner timeout: {config.scanner.active_scan_timeout}s")
    print(f"Debug mode: {config.debug_mode}")
    
    run_gui(config)


def example_gui_with_logging():
    """
    Example 3: Launch GUI with custom logging
    """
    print("Example 3: Launching GUI with custom logging...")
    
    from modules import setup_logging
    
    # Setup custom logging
    setup_logging("DEBUG", "/tmp/blue-sec-gui.log")
    
    config = BlueSecConfig()
    run_gui(config)


def example_programmatic_gui_control():
    """
    Example 4: Programmatically control GUI
    This shows how to create and manipulate the GUI programmatically
    """
    print("Example 4: Programmatic GUI control...")
    
    import tkinter as tk
    from modules.gui import BlueSecGUI
    
    # Create root window
    root = tk.Tk()
    
    # Create GUI instance
    config = BlueSecConfig()
    gui = BlueSecGUI(root, config)
    
    # Simulate some discovered devices
    fake_devices = [
        BluetoothDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Example Device 1",
            device_type="ble",
            rssi=-45
        ),
        BluetoothDevice(
            address="11:22:33:44:55:66",
            name="Example Device 2",
            device_type="classic",
            rssi=-60
        ),
    ]
    
    # Update GUI with fake devices
    gui.discovered_devices = fake_devices
    gui.update_device_list()
    gui.log_message("Programmatically added example devices")
    gui.update_status(f"Ready - {len(fake_devices)} devices loaded")
    
    # Run the GUI
    root.mainloop()


def show_menu():
    """Show example menu"""
    print("\nBlue-sec GUI Examples\n")
    print("1. Basic GUI (default configuration)")
    print("2. GUI with custom configuration")
    print("3. GUI with custom logging")
    print("4. Programmatic GUI control")
    print("0. Exit")
    print()


def main():
    """Main function"""
    if len(sys.argv) > 1:
        example_num = sys.argv[1]
    else:
        show_menu()
        example_num = input("Select example (0-4): ").strip()
    
    if example_num == "1":
        example_basic_gui()
    elif example_num == "2":
        example_custom_config_gui()
    elif example_num == "3":
        example_gui_with_logging()
    elif example_num == "4":
        example_programmatic_gui_control()
    elif example_num == "0":
        print("Goodbye!")
    else:
        print(f"Invalid selection: {example_num}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(0)
    except ImportError as e:
        print(f"\nError: {e}")
        print("\nGUI requires tkinter. Install with:")
        print("  - Linux: sudo apt-get install python3-tk")
        print("  - macOS: tkinter is included with Python")
        print("  - Windows: tkinter is included with Python")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
