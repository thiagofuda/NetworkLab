from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_home_page_displays_networklab() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<h1>NetworkLab</h1>" in response.text
