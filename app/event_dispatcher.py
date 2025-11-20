"""In-memory publish/subscribe dispatcher for streaming events to clients."""

import queue
import threading
from typing import Any, Dict, Optional, Set


class EventDispatcher:
    """Lightweight event bus used for WebSocket broadcasting."""

    def __init__(self, max_queue_size: int = 500) -> None:
        self._max_queue_size = max_queue_size
        self._subscribers: Set[queue.Queue] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        subscription = queue.Queue(maxsize=self._max_queue_size)
        with self._lock:
            self._subscribers.add(subscription)
        return subscription

    def unsubscribe(self, subscription: queue.Queue) -> None:
        with self._lock:
            self._subscribers.discard(subscription)

    def publish(self, event_type: str, payload: Dict[str, Any]) -> None:
        event = {
            "type": event_type,
            "payload": payload,
        }
        with self._lock:
            subscribers = list(self._subscribers)
        for subscription in subscribers:
            try:
                subscription.put_nowait(event)
            except queue.Full:
                # Drop the oldest event to make space
                try:
                    subscription.get_nowait()
                except queue.Empty:
                    pass
                try:
                    subscription.put_nowait(event)
                except queue.Full:
                    # Subscriber is not keeping up; drop the event
                    continue

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def clear(self) -> None:
        with self._lock:
            for subscription in self._subscribers:
                with subscription.mutex:
                    subscription.queue.clear()
