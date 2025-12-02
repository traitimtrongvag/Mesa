import asyncio
import websockets
import aioconsole
from datetime import datetime

URL = "wss://messageanonymous.onrender.com/ws"  # Hoặc wss://messageanonymous.onrender.com/ws

# ANSI màu
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GRAY = "\033[90m"
MAGENTA = "\033[95m"

print_lock = asyncio.Lock()

async def safe_print(text="", end="\n", flush=True):
    async with print_lock:
        print(text, end=end, flush=flush)

async def chat_client():
    await safe_print(f"{CYAN}🔌 Connecting to {URL} ...{RESET}")
    try:
        async with websockets.connect(URL, close_timeout=1) as ws:
            token = None

            async def receiver():
                nonlocal token
                try:
                    async for message in ws:
                        # Nhận token
                        if message.startswith("[Token]:"):
                            token = message[8:].strip()
                            await safe_print(f"\n{GREEN}✅ Connected as [{token}]{RESET}\n")
                            await safe_print(f"[{token} (you)]: ", end="")
                        # Nhận thông tin số người online
                        elif message.startswith("Số người online:"):
                            await safe_print(f"\r{MAGENTA}{message}{RESET}\n")
                            await safe_print(f"[{token} (you)]: ", end="")
                        # Tin nhắn từ người khác
                        else:
                            now = datetime.now().strftime("%H:%M")
                            await safe_print(f"\r{GRAY}[{now}] {YELLOW}{message}{RESET}\n")
                            await safe_print(f"[{token} (you)]: ", end="")
                except websockets.ConnectionClosed:
                    await safe_print("\n❌ Connection closed by server.")

            async def sender():
                while True:
                    try:
                        msg = await aioconsole.ainput("")
                        msg = msg.strip()
                        if not msg:
                            continue
                        if msg.lower() in {"exit", "quit"}:
                            await safe_print("\n👋 Goodbye!\n")
                            await ws.close()
                            break
                        # Gửi text thô
                        await ws.send(msg)
                        await safe_print(f"[{token} (you)]: ", end="")
                    except websockets.ConnectionClosed:
                        await safe_print("\n❌ Connection closed during sending.")
                        break

            await asyncio.gather(receiver(), sender())

    except Exception as e:
        await safe_print(f"\n❌ Connection error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(chat_client())
    except KeyboardInterrupt:
        print("\n👋 Exiting chat.")
