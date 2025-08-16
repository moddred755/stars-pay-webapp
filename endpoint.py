# railway_app.py
import os
import time
import uuid
import json
import hmac
import hashlib
import asyncio
import logging
from aiohttp import web, ClientSession
from aiogram import Bot
from aiogram.types import LabeledPrice

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("railway")

BOT_TOKEN = "8293989859:AAHuzHqEUFoHshGt-4w89Ghjos33fEF1v9E"
#BOT_TOKEN = os.getenv("BOT_TOKEN")
SECRET_KEY = b"505dsdkmn5343dDs" 
#SECRET_KEY = os.getenv("SECRET_KEY", "defaultsecret").encode()
VAST_SAVE_INVOICE_URL = "http://185.12.23.105:8080/save_invoice"
#VAST_SAVE_INVOICE_URL = os.getenv("VAST_SAVE_INVOICE_URL", "http://185.12.23.105:8080/save_invoice")

PORT = int(os.getenv("PORT", "8080"))

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN required")
if not VAST_SAVE_INVOICE_URL:
    raise RuntimeError("VAST_SAVE_INVOICE_URL required")

bot = Bot(token=BOT_TOKEN)


def generate_token(id_plan: str, count: str, price: str) -> str:
    return hmac.new(SECRET_KEY, f"{id_plan}:{count}:{price}".encode(), hashlib.sha256).hexdigest()

def verify_token(id_plan: str, count: str, price: str, token: str) -> bool:
    return hmac.compare_digest(generate_token(id_plan, count, price), token)


def create_invoice_handler_factory(bot: Bot):
    async def handler(request: web.Request):
        """
        Ожидает JSON:
        { "user_id": 12345, "id_plan": "plan_a", "count": "10", "price": "500", "token": "hmac" }
        """
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "invalid json"}, status=400)

        user_id = data.get("user_id")
        id_plan = str(data.get("id_plan", ""))
        count = str(data.get("count", ""))
        price = str(data.get("price", ""))
        token = data.get("token")

        if not all([user_id, id_plan, count, price, token]):
            return web.json_response({"error": "missing params"}, status=400)

        if not verify_token(id_plan, count, price, token):
            return web.json_response({"error": "invalid token"}, status=403)

        # prepare invoice
        invoice_id = str(uuid.uuid4())
        title = f"Plan {id_plan}"
        description = f"{count} credits"
        amount_minor = int(price)
        credits_u = int(count)

        payload = f"invoice:{invoice_id}"  # compact payload for bot

        try:
            prices = [LabeledPrice(label=title, amount=amount_minor)]
            invoice_url = await bot.create_invoice_link(
                title=title,
                description=description,
                currency="XTR",
                prices=prices,
                payload=payload
            )
        except Exception as e:
            logger.exception("create_invoice_link failed")
            return web.json_response({"error": str(e)}, status=500)

        # save invoice on Vast.ai via server-to-server call (HMAC signed)
        save_payload = {
            "invoice_id": invoice_id,
            "user_id": int(user_id),
            "id_plan": id_plan,
            "credits": credits_u,
            "amount": amount_minor
        }
        body = json.dumps(save_payload).encode("utf-8")
        signature = hmac.new(SECRET_KEY, body, hashlib.sha256).hexdigest()

        async with ClientSession() as sess:
            try:
                resp = await sess.post(
                    VAST_SAVE_INVOICE_URL,
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Signature": signature
                    },
                    timeout=10
                )
                text = await resp.text()
                if resp.status != 200:
                    logger.error("save_invoice on VAST failed: %s %s", resp.status, text)
                    # Not fatal: we can still return invoice_url but it's better to notify/alert
            except Exception:
                logger.exception("Failed to call VAST save_invoice")

        return web.json_response({"invoice_url": invoice_url, "invoice_id": invoice_id})
    
    return handler

app = web.Application()
app.router.add_post("/create_invoice", create_invoice_handler_factory(bot))

if __name__ == "__main__":
    web.run_app(app, port=PORT)
