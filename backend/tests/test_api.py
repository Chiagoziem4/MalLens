"""
Tests for MalLens API endpoints.
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_root(client):
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "MalLens"


@pytest.mark.asyncio
async def test_health(client):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_queue_empty(client):
    response = await client.get("/api/queue")
    assert response.status_code == 200
    data = response.json()
    assert "analyses" in data


@pytest.mark.asyncio
async def test_dashboard(client):
    response = await client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "total_analyses" in data


@pytest.mark.asyncio
async def test_upload_no_file(client):
    response = await client.post("/api/upload")
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_status_not_found(client):
    response = await client.get("/api/status/nonexistent-id")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_report_not_found(client):
    response = await client.get("/api/report/nonexistent-id")
    assert response.status_code == 404
