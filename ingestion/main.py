from fastapi import FastAPI, Request
from models import validateEvent
from writer import writeEvent

app = FastAPI()

@app.post("/event")
async def ingestEvent(request: Request):
    data = await request.json()
    event = validateEvent(data)
    writeEvent(event)
    return {"status": "ok"}