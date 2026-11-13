from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_home_page_displays_landing_content_and_real_tool_links() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "InfraLab | Infrastructure Tools &amp; Diagnostics" in response.text
    assert "Infrastructure Tools &amp; Diagnostics" in response.text
    assert (
        "Simple, open-source tools for infrastructure troubleshooting" in response.text
    )
    assert "https://github.com/thiagofuda/NetworkLab" in response.text
    assert "https://github.com/thiagofuda/homeLab" in response.text
    assert 'class="brand-name" href="/">InfraLab</a>' in response.text
    assert "InfraLab GitHub" in response.text
    assert 'class="author-link" href="/about">Thiago Fuda</a>' in response.text
    assert 'class="tool-item" href="/tools/ip"' in response.text
    assert 'class="tool-item" href="/tools/cidr"' in response.text
    assert 'class="tool-item" href="/tools/dns"' in response.text
    assert "SSL/TLS Checker" in response.text
    assert "Coming soon" in response.text
    assert "Built with" not in response.text
    assert "<footer" not in response.text
    assert "/tools/ssl" not in response.text
    assert '<link rel="canonical" href="https://xdb.com.br/">' in response.text


def test_home_page_serves_landing_stylesheet() -> None:
    response = client.get("/static/css/home.css")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ".landing-page" in response.text


def test_robots_txt_allows_crawling() -> None:
    response = client.get("/robots.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text == "User-agent: *\nAllow: /\n"


def test_about_page_shows_profile_and_links() -> None:
    response = client.get("/about")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Cloud &amp; Infrastructure Engineer" in response.text
    assert "More than 20 years of experience in IT." in response.text
    assert "Linux, cloud, automation, and infrastructure." in response.text
    assert "personal, open-source project" in response.text
    assert 'href="https://github.com/thiagofuda"' in response.text
    assert "LinkedIn - coming soon" in response.text
    assert 'class="back-link" href="/">Back to home</a>' in response.text
    assert "About | InfraLab" in response.text
    assert "NetworkLab is a personal" not in response.text
    assert '<link rel="canonical" href="https://xdb.com.br/about">' in response.text
