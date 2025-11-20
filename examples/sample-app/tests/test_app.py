from app import Settings, build_connection_uri, public_bucket_policy


def test_settings_defaults():
    settings = Settings()
    assert settings.environment == "development"
    assert settings.payment_token.endswith("cure")


def test_build_connection_uri_contains_password():
    uri = build_connection_uri()
    assert "postgresql://app:" in uri
    assert uri.endswith("@localhost:5432/demo")


def test_public_bucket_policy_insecure():
    policy = public_bucket_policy()
    assert policy["acl"] == "public-read"
