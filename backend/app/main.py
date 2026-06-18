"""Точка входа FastAPI-приложения (сервер-проверяющий)."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .database import init_db
from .routers import admin, auth, public


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Создание таблиц и предварительная генерация модуля доверенного центра.
    init_db()
    from .services import trusted_center

    trusted_center.get_public_parameters()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Система аутентификации с нулевым разглашением (Fiat–Shamir)",
        description=(
            "Прототип беспарольной аутентификации на основе протокола "
            "Фиата–Шамира: сервер выступает проверяющим, клиент — доказывающим."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(public.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(admin.router, prefix="/api")

    @app.get("/api/health", tags=["public"])
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
