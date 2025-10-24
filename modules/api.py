"""
Blue-sec API Module
REST API for enterprise integration
"""

import asyncio
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from loguru import logger

from modules import (
    BlueSecConfig, DeviceScanner, scan_bluetooth_devices,
    CVEDatabase, VulnerabilityScanner, AttackManager,
    ReportGenerator, BluetoothDevice, validate_mac_address
)

# API Models
class ScanRequest(BaseModel):
    scan_type: str = "all"
    duration: Optional[int] = None

class VulnScanRequest(BaseModel):
    target: str

class AttackRequest(BaseModel):
    attack_type: str
    target: str
    target2: Optional[str] = None
    message: Optional[str] = None
    command: Optional[str] = None
    pin_length: int = 4

# Initialize API
app = FastAPI(
    title="Blue-sec API",
    description="Advanced Bluetooth Security Testing Framework API",
    version="1.0.0"
)

# API Key Security
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Global config (will be set on startup)
config: Optional[BlueSecConfig] = None

async def get_api_key(api_key: str = Security(api_key_header)):
    """Validate API key"""
    if not config or not config.enterprise.api_key:
        return True  # No API key configured
    
    if api_key == config.enterprise.api_key:
        return True
    
    raise HTTPException(status_code=403, detail="Invalid API key")

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    global config
    from modules import load_config
    config = load_config()
    logger.info("Blue-sec API started")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Blue-sec API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post("/scan")
async def scan_devices(request: ScanRequest, authorized: bool = Depends(get_api_key)):
    """Scan for Bluetooth devices"""
    try:
        devices = await scan_bluetooth_devices(config.scanner, request.scan_type)
        
        return {
            "success": True,
            "devices_found": len(devices),
            "devices": [device.to_dict() for device in devices]
        }
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/vuln-scan")
async def vulnerability_scan(request: VulnScanRequest, authorized: bool = Depends(get_api_key)):
    """Perform vulnerability scan on a device"""
    try:
        if not validate_mac_address(request.target):
            raise HTTPException(status_code=400, detail="Invalid MAC address")
        
        # Get device info
        scanner = DeviceScanner(config.scanner)
        device = await scanner.get_device_info(request.target)
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Scan for vulnerabilities
        cve_db = CVEDatabase()
        vuln_scanner = VulnerabilityScanner(cve_db)
        vulnerabilities = await vuln_scanner.scan_device(device)
        
        return {
            "success": True,
            "device": device.to_dict(),
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [vuln.to_dict() for vuln in vulnerabilities]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/attack")
async def execute_attack(request: AttackRequest, authorized: bool = Depends(get_api_key)):
    """Execute attack simulation (requires API key)"""
    try:
        if not validate_mac_address(request.target):
            raise HTTPException(status_code=400, detail="Invalid MAC address")
        
        # Initialize attack manager
        attack_mgr = AttackManager(config.attack, config.security)
        
        # Prepare parameters
        kwargs = {'target': request.target}
        
        if request.attack_type == 'mitm':
            if not request.target2:
                raise HTTPException(status_code=400, detail="MITM requires target2")
            kwargs = {'target1': request.target, 'target2': request.target2, 'duration': 30}
        elif request.attack_type == 'bluejacking':
            kwargs['message'] = request.message or "Test message"
        elif request.attack_type == 'bluebugging':
            kwargs['command'] = request.command or "test"
        elif request.attack_type == 'pin_bruteforce':
            kwargs['pin_length'] = request.pin_length
        
        # Execute attack
        result = await attack_mgr.execute_attack(request.attack_type, **kwargs)
        
        return {
            "success": result.success,
            "result": result.to_dict()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/cves")
async def list_cves(authorized: bool = Depends(get_api_key)):
    """List known CVEs"""
    try:
        cve_db = CVEDatabase()
        
        return {
            "success": True,
            "total_cves": len(cve_db.vulnerabilities),
            "cves": {cve_id: vuln.to_dict() for cve_id, vuln in cve_db.vulnerabilities.items()}
        }
    except Exception as e:
        logger.error(f"Error listing CVEs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/cves/{cve_id}")
async def get_cve(cve_id: str, authorized: bool = Depends(get_api_key)):
    """Get specific CVE details"""
    try:
        cve_db = CVEDatabase()
        vuln = cve_db.get_vulnerability(cve_id)
        
        if not vuln:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        return {
            "success": True,
            "cve": vuln.to_dict()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CVE: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def run_api(host: str = "127.0.0.1", port: int = 8000):
    """Run the API server"""
    import uvicorn
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_api()
