from aiohttp import web
import asyncio
from vencloud import vencloud

async def handle_web_request(request: web.Request) -> web.Response:
    if request.path.startswith("/v1"):
        return await vencloud(request)

async def start_site():
    app = web.Application()
    dyn_route_path = ""
    for i in range(10):
        dyn_route_path = dyn_route_path + "/"
        app.router.add_route('*', '' + dyn_route_path, handle_web_request)
        dyn_route_path = dyn_route_path + "{path_seg_" + str(i) + "}"
        app.router.add_route('*', '' + dyn_route_path, handle_web_request)

    runner = web.AppRunner(app, handle_signals=True)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 80)

    await site.start()

async def main():
    await start_site()
    while True:
        await asyncio.sleep(60)


asyncio.run(main())
