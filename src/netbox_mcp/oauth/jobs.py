"""Background jobs of OAuth mode (spec 6.2, 6.3, 6.4).

Two loops share one ``SessionManager``:

- hourly: end expired and orphaned sessions, recover interrupted token
  creations, drop stale login flows, work the cleanup queue; the queue is also
  worked whenever ``manager.cleanup_wanted`` is set (after every session end).
- daily: expire unused client registrations, check every session against
  NetBox.

Each loop runs once at startup. A failing step is logged and never stops a
loop. ``sleep`` is injectable so tests drive the schedule without waiting.
"""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable
from collections.abc import Callable

from netbox_mcp.oauth.sessions import SessionManager

logger = logging.getLogger(__name__)

HOURLY = 3600.0
DAILY = 86400.0


class Jobs:
    def __init__(
        self,
        manager: SessionManager,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.manager = manager
        self._sleep = sleep
        self._tasks: list[asyncio.Task[None]] = []

    def start(self) -> None:
        if self._tasks:
            return
        self._tasks = [
            asyncio.create_task(self._hourly(), name="oauth-hourly"),
            asyncio.create_task(self._daily(), name="oauth-daily"),
        ]

    async def stop(self) -> None:
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    async def _guard(step: Callable[[], Awaitable[None]]) -> None:
        try:
            await step()
        except Exception:
            logger.exception(
                "oauth: background job failed: %s", getattr(step, "__name__", step)
            )

    async def _hourly_run(self) -> None:
        m = self.manager
        m.cleanup_wanted.clear()
        # Cleanup last, so tokens of sessions ended just now go in the same run.
        for step in (
            m.end_expired,
            m.end_orphans,
            m.recover_pending,
            m.drop_stale_flows,
            m.run_cleanup,
        ):
            await self._guard(step)

    async def _hourly(self) -> None:
        m = self.manager
        await self._hourly_run()
        timer = asyncio.ensure_future(self._sleep(HOURLY))
        waiter: asyncio.Future[bool] | None = None
        try:
            while True:
                waiter = asyncio.ensure_future(m.cleanup_wanted.wait())
                await asyncio.wait({timer, waiter}, return_when=asyncio.FIRST_COMPLETED)
                if timer.done():
                    await timer
                    await self._hourly_run()
                    timer = asyncio.ensure_future(self._sleep(HOURLY))
                else:
                    m.cleanup_wanted.clear()
                    await self._guard(m.run_cleanup)
                waiter.cancel()
        finally:
            timer.cancel()
            if waiter is not None:
                waiter.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(timer, return_exceptions=True)

    async def _daily(self) -> None:
        m = self.manager
        while True:
            for step in (m.expire_clients, m.daily_netbox_check):
                await self._guard(step)
            await self._sleep(DAILY)
