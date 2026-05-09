import asyncio
import logging
from dataclasses import dataclass, field

from app.models.enums import AppState

logger = logging.getLogger(__name__)

# App LifeCycle Manager
@dataclass
class LifecycleManager:
    """
    This app cylce manager class monitors the applications state
    It manages tasks and background workers, daemons, on startup and shutdown events.
    """
    # Initial state
    state: AppState = AppState.BOOTING 
    db_ready: asyncio.Event = field(default=None) 
    shutdown_event: asyncio.Event = field(default=None) # Shutdown event
    tasks: list[asyncio.Task] = field(default_factory=list) # Tasks

    def __post_init__(self):
         self.db_ready = asyncio.Event()
         self.shutdown_event = asyncio.Event()
    
    # Set app state
    def set_state(self, new_state: AppState):
        """Set application status"""
        logger.info("[lifecycle] %s → %s", self.state.name, new_state.name)
        self.state = new_state

    def mark_db_ready(self):
        """ Marks database  as ready for other processes to start"""
        self.db_ready.set()
        self.set_state(AppState.DB_READY)

    def create_task(self, coro, name: str):
        """Create a task after confirming db is ready"""
        task = asyncio.create_task(coro, name=name)
        self.tasks.append(task)
        return task

    async def shutdown(self):
        """ Shutdown event -- cancel all ongoing tasks"""
        logger.info("[lifecycle] shutting down...")
        self.shutdown_event.set()
        
        # Cancel tasks
        for t in self.tasks:
            t.cancel()