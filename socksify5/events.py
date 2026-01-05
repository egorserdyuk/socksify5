"""
Event system for Socksify5.

Provides a simple event emitter for monitoring proxy server events.
"""

import asyncio
from typing import Any, Callable, Dict, List


class EventEmitter:
    """Simple event emitter for SOCKS5 server events."""

    def __init__(self):
        self._listeners: Dict[str, List[Callable]] = {}

    def on(self, event: str, callback: Callable) -> None:
        """Register an event listener."""
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)

    def off(self, event: str, callback: Callable) -> None:
        """Remove an event listener."""
        if event in self._listeners:
            self._listeners[event].remove(callback)
            if not self._listeners[event]:
                del self._listeners[event]

    def emit(self, event: str, *args: Any) -> None:
        """Emit an event to all listeners."""
        if event in self._listeners:
            for callback in self._listeners[event]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        asyncio.create_task(callback(*args))
                    else:
                        callback(*args)
                except Exception as e:
                    # Log error but don't crash
                    print(f"Error in event listener for {event}: {e}")

    def remove_all_listeners(self, event: str = None) -> None:
        """Remove all listeners for an event or all events."""
        if event:
            self._listeners.pop(event, None)
        else:
            self._listeners.clear()
