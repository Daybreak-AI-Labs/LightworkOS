"""Synchronous tool workers are a shared, bounded pool: no tenant may take it all."""
from __future__ import annotations

import pytest


def test_one_tenants_hung_tools_cannot_refuse_another_tenants(monkeypatch):
    import asyncio
    import concurrent.futures
    import threading

    from maverick import tool_result_stream as trs
    from maverick.paths import tenant_scope
    gate = threading.Event()

    def hung(args):
        gate.wait(10)
        return "done"

    async def main():
        asyncio.get_running_loop().set_default_executor(
            concurrent.futures.ThreadPoolExecutor(64))
        with tenant_scope(tenant="acme"):
            for _ in range(trs.MAX_WORKERS_PER_TENANT):
                task = asyncio.create_task(trs.execute_tool(hung, {}))
                await asyncio.sleep(0.01)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            with pytest.raises(trs.ToolWorkerCapacity, match="tenant"):
                await trs.execute_tool(lambda a: "x", {})
        with tenant_scope(tenant="beta"):
            assert "fresh" in str(await trs.execute_tool(lambda a: "fresh", {}))
        gate.set()
        for _ in range(100):
            if trs.pending_tool_workers() == 0:
                break
            await asyncio.sleep(0.05)
    asyncio.run(main())
