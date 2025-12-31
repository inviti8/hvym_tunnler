from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import logging

from .services.ziti_service import ZitiService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="OpenZiti Tunneling Service",
    description="API for managing secure tunnels using OpenZiti",
    version="0.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Ziti service
ziti_service = ZitiService(
    controller_url="http://ziti-controller:1280",
    admin_username="admin",
    admin_password="admin"
)

# Startup event
@app.on_event("startup")
async def startup_event():
    try:
        await ziti_service.initialize()
        logger.info("Ziti service initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Ziti service: {e}")
        raise

# Models
class TunnelCreate(BaseModel):
    user_id: str
    service_name: str
    local_port: int
    protocol: str = "tcp"

class TunnelResponse(BaseModel):
    service_id: str
    identity: str
    jwt: str
    local_port: int
    status: str

# API Endpoints
@app.post("/tunnels/", response_model=TunnelResponse, status_code=status.HTTP_201_CREATED)
async def create_tunnel(tunnel: TunnelCreate):
    """Create a new tunnel"""
    try:
        return await ziti_service.create_tunnel(
            user_id=tunnel.user_id,
            service_name=tunnel.service_name,
            local_port=tunnel.local_port,
            protocol=tunnel.protocol
        )
    except Exception as e:
        logger.error(f"Error creating tunnel: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create tunnel: {str(e)}"
        )

@app.get("/tunnels/", response_model=List[dict])
async def list_tunnels():
    """List all active tunnels"""
    try:
        return await ziti_service.list_tunnels()
    except Exception as e:
        logger.error(f"Error listing tunnels: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list tunnels"
        )

@app.get("/tunnels/{service_id}", response_model=dict)
async def get_tunnel(service_id: str):
    """Get details of a specific tunnel"""
    tunnel = await ziti_service.get_tunnel(service_id)
    if tunnel is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tunnel not found"
        )
    return tunnel

@app.delete("/tunnels/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tunnel(service_id: str):
    """Delete a tunnel"""
    success = await ziti_service.close_tunnel(service_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tunnel not found or error deleting"
        )
    return {"status": "deleted"}

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok"}
