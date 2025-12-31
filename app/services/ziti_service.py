from typing import Dict, Optional, List
import logging
from openziti import ZitiContext
from openziti.model import Service, Identity, ServicePolicy
from openziti.exceptions import ZitiException

logger = logging.getLogger(__name__)

class ZitiService:
    def __init__(self, controller_url: str, admin_username: str, admin_password: str):
        self.controller_url = controller_url
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.contexts: Dict[str, ZitiContext] = {}
        self.initialized = False

    async def initialize(self):
        """Initialize the Ziti service with admin credentials"""
        try:
            ctx = ZitiContext()
            await ctx.connect(self.controller_url)
            await ctx.authenticate(self.admin_username, self.admin_password)
            self.admin_context = ctx
            self.initialized = True
            logger.info("Successfully initialized Ziti service")
        except ZitiException as e:
            logger.error(f"Failed to initialize Ziti service: {e}")
            raise

    async def create_tunnel(
        self, 
        user_id: str, 
        service_name: str, 
        local_port: int, 
        protocol: str = "tcp"
    ) -> dict:
        """
        Create a new tunnel for a user
        
        Args:
            user_id: Unique identifier for the user
            service_name: Name for the tunnel service
            local_port: Local port to forward
            protocol: Protocol to use (tcp/udp)
            
        Returns:
            Dict containing tunnel configuration
        """
        if not self.initialized:
            await self.initialize()

        try:
            # Create a unique service ID
            service_id = f"{user_id}-{service_name}-{local_port}"
            
            # Create service
            service = await self.admin_context.create_service(
                name=service_id,
                protocol=protocol,
                addresses=[f"{service_id}"],
                port_ranges=[{"low": local_port, "high": local_port}]
            )
            
            # Create identity for the tunnel
            identity = await self.admin_context.create_identity(
                name=f"{service_id}-identity",
                type="Device",
                is_admin=False
            )
            
            # Create service policies
            await self.admin_context.create_service_policy(
                name=f"{service_id}-bind",
                type="Bind",
                service_roles=[f"@${service_id}"],
                identity_roles=[identity.id]
            )
            
            await self.admin_context.create_service_policy(
                name=f"{service_id}-dial",
                type="Dial",
                service_roles=[f"@${service_id}"],
                identity_roles=[identity.id]
            )
            
            # Create a new context for this tunnel
            tunnel_ctx = ZitiContext()
            await tunnel_ctx.connect(self.controller_url)
            await tunnel_ctx.authenticate(identity.id, identity.password)
            
            # Store the context
            self.contexts[service_id] = tunnel_ctx
            
            return {
                "service_id": service_id,
                "identity": identity.id,
                "jwt": identity.jwt,
                "local_port": local_port,
                "status": "active"
            }
            
        except ZitiException as e:
            logger.error(f"Failed to create tunnel: {e}")
            raise

    async def close_tunnel(self, service_id: str) -> bool:
        """Close and clean up a tunnel"""
        if service_id in self.contexts:
            try:
                await self.contexts[service_id].close()
                # Clean up resources in the controller
                await self.admin_context.delete_service(service_id)
                await self.admin_context.delete_identity(f"{service_id}-identity")
                del self.contexts[service_id]
                return True
            except ZitiException as e:
                logger.error(f"Error closing tunnel {service_id}: {e}")
                return False
        return False

    async def list_tunnels(self) -> List[dict]:
        """List all active tunnels"""
        return [
            {
                "service_id": service_id,
                "status": "active"
            }
            for service_id in self.contexts
        ]

    async def get_tunnel(self, service_id: str) -> Optional[dict]:
        """Get details of a specific tunnel"""
        if service_id in self.contexts:
            return {
                "service_id": service_id,
                "status": "active"
            }
        return None
