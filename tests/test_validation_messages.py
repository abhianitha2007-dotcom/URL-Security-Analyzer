import analyzer.url_validator as url_validator

from app import app


def test_invalid_domain_validation():
    valid = url_validator.is_valid_url(
        "https://bad domain.com"
    )

    result = (
        url_validator.get_last_validation_result()
    )

    assert valid is False
    assert result["code"] == "invalid_domain"

    assert result["message"] == (
        "Please enter a valid HTTP or HTTPS URL."
    )


def test_private_target_validation():
    valid = url_validator.is_valid_url(
        "http://127.0.0.1"
    )

    result = (
        url_validator.get_last_validation_result()
    )

    assert valid is False
    assert result["code"] == "private_target"

    assert (
        "Private or local network addresses "
        "cannot be scanned."
        in result["message"]
    )


def test_dns_failure_validation(
    monkeypatch
):
    monkeypatch.setattr(
        url_validator,
        "_resolve_hostname",
        lambda hostname, port: None
    )

    valid = url_validator.is_valid_url(
        "https://unavailable-example.com"
    )

    result = (
        url_validator.get_last_validation_result()
    )

    assert valid is False
    assert result["code"] == "dns_failed"

    assert result["message"] == (
        "The domain could not be resolved. "
        "It may be offline or unavailable."
    )


def test_embedded_credentials_validation():
    valid = url_validator.is_valid_url(
        "https://user:password@example.com"
    )

    result = (
        url_validator.get_last_validation_result()
    )

    assert valid is False

    assert (
        result["code"]
        == "embedded_credentials"
    )

    assert result["message"] == (
        "URLs containing embedded usernames "
        "or passwords cannot be scanned."
    )


def test_valid_public_url_validation(
    monkeypatch
):
    monkeypatch.setattr(
        url_validator,
        "_resolve_hostname",
        lambda hostname, port: {
            "8.8.8.8"
        }
    )

    valid = url_validator.is_valid_url(
        "https://example.com"
    )

    result = (
        url_validator.get_last_validation_result()
    )

    assert valid is True
    assert result["code"] == "valid"
    assert result["message"] == "URL is valid."


def test_input_validation_does_not_require_dns(
    monkeypatch
):
    monkeypatch.setattr(
        url_validator,
        "_resolve_hostname",
        lambda hostname, port: None
    )

    valid = url_validator.validate_url_input(
        "https://unavailable-example.com"
    )

    result = (
        url_validator.get_last_validation_result()
    )

    assert valid is True
    assert result["code"] == "valid_input"


def test_network_status_reports_dns_unavailable(
    monkeypatch
):
    monkeypatch.setattr(
        url_validator,
        "_resolve_hostname",
        lambda hostname, port: None
    )

    result = (
        url_validator.get_network_target_status(
            "https://unavailable-example.com"
        )
    )

    assert result["safe"] is False
    assert result["available"] is False
    assert result["code"] == "dns_unavailable"


def test_flask_displays_invalid_domain_message():
    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.post(
            "/analyze",
            data={
                "url":
                    "https://bad domain.com"
            }
        )

    page = response.get_data(
        as_text=True
    )

    assert response.status_code == 200

    assert (
        "Please enter a valid HTTP or HTTPS URL."
        in page
    )


def test_flask_displays_private_target_message():
    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.post(
            "/analyze",
            data={
                "url":
                    "http://127.0.0.1"
            }
        )

    page = response.get_data(
        as_text=True
    )

    assert response.status_code == 200

    assert (
        "Private or local network addresses "
        "cannot be scanned."
        in page
    )


def test_flask_allows_dns_unavailable_url(
    monkeypatch
):
    monkeypatch.setattr(
        url_validator,
        "_resolve_hostname",
        lambda hostname, port: None
    )

    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.post(
            "/analyze",
            data={
                "url":
                    "https://unavailable-example.com"
            }
        )

    page = response.get_data(
        as_text=True
    )

    assert response.status_code == 200

    assert (
        "Security Report | URL Security Analyzer"
        in page
    )

    assert (
        "The domain could not be resolved. "
        "It may be offline or unavailable."
        not in page
    )


def test_flask_displays_embedded_credentials_message():
    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.post(
            "/analyze",
            data={
                "url":
                    "https://user:password@example.com"
            }
        )

    page = response.get_data(
        as_text=True
    )

    assert response.status_code == 200

    assert (
        "URLs containing embedded usernames "
        "or passwords cannot be scanned."
        in page
    )