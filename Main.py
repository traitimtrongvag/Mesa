import asyncio
import websockets
import sys
import aioconsole

URL = "wss://messageanonymous.onrender.com/ws"

async def chat_client():
    print(f"🔌 Connecting to {URL} ...")
    async with websockets.connect(URL) as ws:
        token = None

        async def receiver():
            nonlocal token
            async for message in ws:
                if message.startswith("[Token]:"):
                    token = message[8:]
                    print(f"\n✅ Connected as [{token}]\n")
                    print(f"[{token} (you)]: ", end="", flush=True)
                else:
                    print(f"\r{message}\n[{token or '...'} (you)]: ", end="", flush=True)

        async def sender():
            nonlocal token
            while True:
                msg = await aioconsole.ainput(f"[{token or '...'} (you)]: ")
                if msg.lower() in {"exit", "quit"}:
                    print("👋 Goodbye!")
                    await ws.close()
                    break
                await ws.send(msg)

        await asyncio.gather(receiver(), sender())

if __name__ == "__main__":
    try:
        asyncio.run(chat_client())
    except KeyboardInterrupt:
        print("\n👋 Exiting chat.")
    except Exception as e:
        print(f"❌ Error: {e}")
