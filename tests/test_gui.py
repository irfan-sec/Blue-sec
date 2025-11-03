"""
Blue-sec GUI Tests
Tests for the GUI module
"""

import pytest
import sys
import os
from pathlib import Path

# Try to import tkinter and check for display - skip tests if not available
GUI_AVAILABLE = False
DISPLAY_AVAILABLE = False

try:
    import tkinter as tk
    from modules.gui import BlueSecGUI
    from modules.config import BlueSecConfig
    GUI_AVAILABLE = True
    
    # Check if we have a display available
    try:
        test_root = tk.Tk()
        test_root.withdraw()
        test_root.destroy()
        DISPLAY_AVAILABLE = True
    except Exception:
        DISPLAY_AVAILABLE = False
        
except ImportError:
    GUI_AVAILABLE = False


@pytest.mark.skipif(not GUI_AVAILABLE or not DISPLAY_AVAILABLE, 
                    reason="GUI not available (tkinter not installed or no display)")
class TestGUI:
    """Test GUI module"""
    
    def test_gui_import(self):
        """Test that GUI module can be imported"""
        from modules.gui import BlueSecGUI, run_gui
        assert BlueSecGUI is not None
        assert run_gui is not None
    
    def test_gui_initialization(self):
        """Test GUI initialization without displaying"""
        # Create a root window but don't show it
        root = tk.Tk()
        root.withdraw()  # Hide the window
        
        try:
            config = BlueSecConfig()
            gui = BlueSecGUI(root, config)
            
            # Verify basic attributes
            assert gui.config is not None
            assert gui.discovered_devices == []
            assert gui.selected_device is None
            assert gui.scanning is False
            
            # Verify components are initialized
            assert gui.scanner is not None
            assert gui.cve_db is not None
            assert gui.vuln_scanner is not None
            assert gui.attack_manager is not None
            assert gui.report_gen is not None
            
        finally:
            # Clean up
            root.destroy()
    
    def test_gui_components_exist(self):
        """Test that GUI components are created"""
        root = tk.Tk()
        root.withdraw()
        
        try:
            config = BlueSecConfig()
            gui = BlueSecGUI(root, config)
            
            # Check notebook exists
            assert gui.notebook is not None
            
            # Check tabs exist (we can't easily test the content without displaying)
            # Just verify the notebook has tabs
            assert len(gui.notebook.tabs()) > 0
            
            # Check status bar exists
            assert gui.status_bar is not None
            
        finally:
            root.destroy()
    
    def test_update_status(self):
        """Test status bar update"""
        root = tk.Tk()
        root.withdraw()
        
        try:
            config = BlueSecConfig()
            gui = BlueSecGUI(root, config)
            
            # Update status
            test_message = "Test status message"
            gui.update_status(test_message)
            
            # Verify status was updated
            assert gui.status_bar.cget("text") == test_message
            
        finally:
            root.destroy()
    
    def test_log_message(self):
        """Test logging functionality"""
        root = tk.Tk()
        root.withdraw()
        
        try:
            config = BlueSecConfig()
            gui = BlueSecGUI(root, config)
            
            # Log a message
            test_message = "Test log message"
            gui.log_message(test_message)
            
            # Verify message appears in log
            log_content = gui.log_text.get(1.0, tk.END)
            assert test_message in log_content
            
        finally:
            root.destroy()
    
    def test_clear_devices(self):
        """Test clearing device list"""
        root = tk.Tk()
        root.withdraw()
        
        try:
            config = BlueSecConfig()
            gui = BlueSecGUI(root, config)
            
            # Add some fake devices
            from modules.scanner import BluetoothDevice
            device = BluetoothDevice(
                address="AA:BB:CC:DD:EE:FF",
                name="Test Device",
                device_type="ble"
            )
            gui.discovered_devices = [device]
            gui.update_device_list()
            
            # Clear devices
            gui.clear_devices()
            
            # Verify devices are cleared
            assert len(gui.discovered_devices) == 0
            assert gui.selected_device is None
            
        finally:
            root.destroy()
    
    def test_update_device_list(self):
        """Test updating device list display"""
        root = tk.Tk()
        root.withdraw()
        
        try:
            config = BlueSecConfig()
            gui = BlueSecGUI(root, config)
            
            # Add some devices
            from modules.scanner import BluetoothDevice
            devices = [
                BluetoothDevice(
                    address="AA:BB:CC:DD:EE:FF",
                    name="Device 1",
                    device_type="ble"
                ),
                BluetoothDevice(
                    address="11:22:33:44:55:66",
                    name="Device 2",
                    device_type="classic"
                )
            ]
            gui.discovered_devices = devices
            gui.update_device_list()
            
            # Verify devices are in treeview
            items = gui.device_tree.get_children()
            assert len(items) == 2
            
        finally:
            root.destroy()


@pytest.mark.skipif(GUI_AVAILABLE, reason="Test for when GUI is not available")
class TestGUINotAvailable:
    """Test behavior when GUI is not available"""
    
    def test_gui_graceful_import_failure(self):
        """Test that import failure is handled gracefully"""
        # This test only runs when tkinter is not available
        # The modules/__init__.py should handle this gracefully
        from modules import BlueSecGUI, run_gui
        assert BlueSecGUI is None
        assert run_gui is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
