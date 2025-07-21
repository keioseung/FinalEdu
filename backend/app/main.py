from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import ai_info, quiz, prompt, base_content, term, auth

app = FastAPI()

origins = [
    "https://simple-production-6bc9.up.railway.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ai_info.router, prefix="/api/ai-info")
app.include_router(quiz.router, prefix="/api/quiz")
app.include_router(prompt.router, prefix="/api/prompt")
app.include_router(base_content.router, prefix="/api/base-content")
app.include_router(term.router, prefix="/api/term")
app.include_router(auth.router, prefix="/api/auth") 