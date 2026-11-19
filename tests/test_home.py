from xml.etree import ElementTree

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
    assert "curl https://infralab.fuda.com.br/api/ip" in response.text
    assert (
        "curl 'https://infralab.fuda.com.br/api/cidr?cidr=192.168.10.25/24'"
        in response.text
    )
    assert (
        "curl 'https://infralab.fuda.com.br/api/dns?domain=example.com&amp;record_type=A'"
        in response.text
    )
    assert 'class="brand-name" href="/">InfraLab</a>' in response.text
    assert "InfraLab GitHub" in response.text
    assert 'class="author-link" href="/about">Thiago Fuda</a>' in response.text
    assert 'class="tool-item" href="/tools/ip"' in response.text
    assert 'class="tool-item" href="/tools/cidr"' in response.text
    assert 'class="tool-item" href="/tools/dns"' in response.text
    assert "curl https://infralab.fuda.com.br/api/ip" in response.text
    assert (
        "curl 'https://infralab.fuda.com.br/api/cidr?cidr=192.168.10.25/24'"
        in response.text
    )
    assert (
        "curl 'https://infralab.fuda.com.br/api/dns?domain=example.com&amp;record_type=A'"
        in response.text
    )
    assert "AWS IAM Policy Validator" in response.text
    assert "https://infralab.fuda.com.br/api/aws/iam-validate" in response.text
    assert "--data-binary @policy.json" in response.text
    assert "AWS Terraform Plan Inspector" in response.text
    assert "OCI Terraform Plan Inspector" in response.text
    assert (
        "https://infralab.fuda.com.br/api/aws/terraform-plan-analyze" in response.text
    )
    assert (
        "https://infralab.fuda.com.br/api/oci/terraform-plan-analyze" in response.text
    )
    assert "--data-binary @plan.json" in response.text
    assert "OCI IAM Policy Analyzer" in response.text
    assert "https://infralab.fuda.com.br/api/oci/iam-policy-analyze" in response.text
    assert "--data-binary @oci-policy.json" in response.text
    assert "SSL/TLS Checker" in response.text
    assert '<span class="coming-soon">Em breve</span>' in response.text
    assert "Built with" not in response.text
    assert "<footer" not in response.text
    assert "/tools/ssl" not in response.text
    assert (
        '<link rel="canonical" href="https://infralab.fuda.com.br/">' in response.text
    )


def test_home_page_serves_landing_stylesheet() -> None:
    response = client.get("/static/css/home.css")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ".landing-page" in response.text


def test_robots_txt_allows_crawling() -> None:
    response = client.get("/robots.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text == (
        "User-agent: *\nAllow: /\nSitemap: https://infralab.fuda.com.br/sitemap.xml\n"
    )


def test_sitemap_lists_public_html_pages() -> None:
    response = client.get("/sitemap.xml")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/xml"
    root = ElementTree.fromstring(response.content)
    namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    assert root.tag == f"{namespace}urlset"
    assert [
        element.text for element in root.findall(f"{namespace}url/{namespace}loc")
    ] == [
        "https://infralab.fuda.com.br/",
        "https://infralab.fuda.com.br/about",
        "https://infralab.fuda.com.br/tools/ip",
        "https://infralab.fuda.com.br/tools/cidr",
        "https://infralab.fuda.com.br/tools/dns",
    ]


def test_about_page_shows_profile_and_links() -> None:
    response = client.get("/about")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Cloud &amp; Infrastructure Engineer" in response.text
    assert "More than 20 years of experience in IT." in response.text
    assert "Linux, cloud, automation, and infrastructure." in response.text
    assert "personal, open-source project" in response.text
    assert 'href="https://github.com/thiagofuda"' in response.text
    assert 'href="https://br.linkedin.com/in/thiago-fuda"' in response.text
    assert "LinkedIn" in response.text
    assert "About | InfraLab" in response.text
    assert "NetworkLab is a personal" not in response.text
    assert (
        '<link rel="canonical" href="https://infralab.fuda.com.br/about">'
        in response.text
    )
