def test_health_endpoint_success(client):
    """Verify that /api/v1/health returns 200 OK and reports database component status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "HEALTHY"
    assert "project" in data
    assert "environment" in data
    assert "timestamp" in data

    db_health = data["database"]
    assert db_health["status"] == "UP"
    assert isinstance(db_health["latency_ms"], (int, float))
    assert db_health["latency_ms"] >= 0
    assert db_health["details"]["connection"] == "active"


def test_root_endpoint(client):
    """Verify service information on root path."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert "health_endpoint" in data
