"""
Blue-sec Scanner Module
Device discovery and enumeration functionality
"""

import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger

try:
    from bleak import BleakScanner, BleakClient
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False
    logger.warning("Bleak not available - BLE scanning will be limited")

try:
    import bluetooth
    PYBLUEZ_AVAILABLE = True
except ImportError:
    PYBLUEZ_AVAILABLE = False
    logger.warning("PyBluez not available - Classic Bluetooth scanning will be limited")

from modules.utils import format_mac_address, timestamp, console
from modules.config import ScannerConfig


@dataclass
class BluetoothDevice:
    """Represents a discovered Bluetooth device"""
    address: str
    name: Optional[str] = None
    rssi: Optional[int] = None
    device_type: str = "unknown"  # 'ble', 'classic', 'dual'
    manufacturer: Optional[str] = None
    services: List[str] = field(default_factory=list)
    characteristics: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: str = field(default_factory=timestamp)
    last_seen: str = field(default_factory=timestamp)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert device to dictionary"""
        return {
            'address': self.address,
            'name': self.name,
            'rssi': self.rssi,
            'device_type': self.device_type,
            'manufacturer': self.manufacturer,
            'services': self.services,
            'characteristics': self.characteristics,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BluetoothDevice':
        """Create device from dictionary"""
        return cls(**data)


class DeviceScanner:
    """Bluetooth device scanner"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.discovered_devices: Dict[str, BluetoothDevice] = {}
        self._scan_active = False
    
    async def scan_ble_devices(self, duration: float = None) -> List[BluetoothDevice]:
        """Scan for BLE devices"""
        if not BLEAK_AVAILABLE:
            logger.error("BLE scanning requires bleak library")
            return []
        
        duration = duration or self.config.passive_scan_duration
        devices = []
        
        try:
            logger.info(f"Starting BLE scan for {duration} seconds...")
            
            scanner = BleakScanner()
            await scanner.start()
            await asyncio.sleep(duration)
            await scanner.stop()
            
            discovered = await scanner.get_discovered_devices()
            
            for device in discovered:
                # Filter by RSSI threshold
                if device.rssi and device.rssi < self.config.rssi_threshold:
                    continue
                
                bt_device = BluetoothDevice(
                    address=format_mac_address(device.address),
                    name=device.name or "Unknown",
                    rssi=device.rssi,
                    device_type='ble',
                    metadata={'details': str(device.details)}
                )
                
                # Update or add device
                if bt_device.address in self.discovered_devices:
                    self.discovered_devices[bt_device.address].last_seen = timestamp()
                    self.discovered_devices[bt_device.address].rssi = bt_device.rssi
                else:
                    self.discovered_devices[bt_device.address] = bt_device
                
                devices.append(bt_device)
                logger.debug(f"Discovered BLE device: {bt_device.name} ({bt_device.address})")
            
            logger.info(f"BLE scan complete. Found {len(devices)} devices")
            
        except Exception as e:
            logger.error(f"Error during BLE scan: {e}")
        
        return devices
    
    def scan_classic_devices(self, duration: int = 8) -> List[BluetoothDevice]:
        """Scan for Classic Bluetooth devices"""
        if not PYBLUEZ_AVAILABLE:
            logger.warning("Classic Bluetooth scanning requires PyBluez")
            return []
        
        devices = []
        
        try:
            logger.info(f"Starting Classic Bluetooth scan for {duration} seconds...")
            nearby_devices = bluetooth.discover_devices(
                duration=duration,
                lookup_names=True,
                flush_cache=True,
                lookup_class=True
            )
            
            for addr, name, device_class in nearby_devices:
                bt_device = BluetoothDevice(
                    address=format_mac_address(addr),
                    name=name or "Unknown",
                    device_type='classic',
                    metadata={'device_class': device_class}
                )
                
                # Update or add device
                if bt_device.address in self.discovered_devices:
                    self.discovered_devices[bt_device.address].last_seen = timestamp()
                else:
                    self.discovered_devices[bt_device.address] = bt_device
                
                devices.append(bt_device)
                logger.debug(f"Discovered Classic device: {bt_device.name} ({bt_device.address})")
            
            logger.info(f"Classic scan complete. Found {len(devices)} devices")
            
        except Exception as e:
            logger.error(f"Error during Classic Bluetooth scan: {e}")
        
        return devices
    
    async def enumerate_services(self, device_address: str) -> List[str]:
        """Enumerate services for a BLE device"""
        if not BLEAK_AVAILABLE:
            logger.error("Service enumeration requires bleak library")
            return []
        
        services = []
        
        try:
            logger.info(f"Enumerating services for {device_address}...")
            
            async with BleakClient(device_address, timeout=self.config.active_scan_timeout) as client:
                if client.is_connected:
                    for service in client.services:
                        services.append(str(service.uuid))
                        logger.debug(f"Found service: {service.uuid}")
            
            # Update device services
            if device_address in self.discovered_devices:
                self.discovered_devices[device_address].services = services
            
            logger.info(f"Found {len(services)} services")
            
        except Exception as e:
            logger.error(f"Error enumerating services: {e}")
        
        return services
    
    async def enumerate_characteristics(self, device_address: str) -> List[Dict[str, Any]]:
        """Enumerate characteristics for a BLE device"""
        if not BLEAK_AVAILABLE:
            logger.error("Characteristic enumeration requires bleak library")
            return []
        
        characteristics = []
        
        try:
            logger.info(f"Enumerating characteristics for {device_address}...")
            
            async with BleakClient(device_address, timeout=self.config.active_scan_timeout) as client:
                if client.is_connected:
                    for service in client.services:
                        for char in service.characteristics:
                            char_info = {
                                'service_uuid': str(service.uuid),
                                'uuid': str(char.uuid),
                                'properties': char.properties,
                                'handle': char.handle
                            }
                            characteristics.append(char_info)
                            logger.debug(f"Found characteristic: {char.uuid}")
            
            # Update device characteristics
            if device_address in self.discovered_devices:
                self.discovered_devices[device_address].characteristics = characteristics
            
            logger.info(f"Found {len(characteristics)} characteristics")
            
        except Exception as e:
            logger.error(f"Error enumerating characteristics: {e}")
        
        return characteristics
    
    async def get_device_info(self, device_address: str) -> Optional[BluetoothDevice]:
        """Get comprehensive device information"""
        try:
            logger.info(f"Gathering information for {device_address}...")
            
            # Check if device is already discovered
            if device_address not in self.discovered_devices:
                # Try to connect and get basic info
                if BLEAK_AVAILABLE:
                    try:
                        async with BleakClient(device_address, timeout=5) as client:
                            device = BluetoothDevice(
                                address=device_address,
                                name="Unknown",
                                device_type='ble'
                            )
                            self.discovered_devices[device_address] = device
                    except:
                        return None
                else:
                    return None
            
            # Enumerate services and characteristics
            await self.enumerate_services(device_address)
            await self.enumerate_characteristics(device_address)
            
            return self.discovered_devices.get(device_address)
            
        except Exception as e:
            logger.error(f"Error getting device info: {e}")
            return None
    
    def get_discovered_devices(self) -> List[BluetoothDevice]:
        """Get all discovered devices"""
        return list(self.discovered_devices.values())
    
    def get_device_by_address(self, address: str) -> Optional[BluetoothDevice]:
        """Get device by address"""
        return self.discovered_devices.get(format_mac_address(address))
    
    def clear_cache(self):
        """Clear discovered devices cache"""
        self.discovered_devices.clear()
        logger.info("Device cache cleared")
    
    async def continuous_scan(self, callback=None):
        """Continuous scanning mode"""
        self._scan_active = True
        logger.info("Starting continuous scan mode...")
        
        while self._scan_active:
            devices = await self.scan_ble_devices(duration=5)
            
            if callback and devices:
                callback(devices)
            
            await asyncio.sleep(1)
    
    def stop_scan(self):
        """Stop continuous scan"""
        self._scan_active = False
        logger.info("Stopping scan...")


async def scan_bluetooth_devices(config: ScannerConfig, scan_type: str = "all") -> List[BluetoothDevice]:
    """
    Scan for Bluetooth devices
    
    Args:
        config: Scanner configuration
        scan_type: Type of scan ('ble', 'classic', 'all')
    
    Returns:
        List of discovered devices
    """
    scanner = DeviceScanner(config)
    all_devices = []
    
    if scan_type in ['ble', 'all']:
        ble_devices = await scanner.scan_ble_devices()
        all_devices.extend(ble_devices)
    
    if scan_type in ['classic', 'all']:
        classic_devices = scanner.scan_classic_devices()
        all_devices.extend(classic_devices)
    
    return all_devices
