"""Tests for CLI options using Click's testing utilities."""

import os

import pytest
from click.testing import CliRunner

from nextcloud_mcp_server.cli import run


@pytest.fixture
def runner():
    """Create a Click CLI runner."""
    return CliRunner()


@pytest.fixture
def clean_env(monkeypatch):
    """Clean environment variables before each test."""
    env_vars = [
        "NEXTCLOUD_HOST",
        "NEXTCLOUD_USERNAME",
        "NEXTCLOUD_PASSWORD",
        "NEXTCLOUD_OIDC_CLIENT_ID",
        "NEXTCLOUD_OIDC_CLIENT_SECRET",
        "NEXTCLOUD_OIDC_SCOPES",
        "NEXTCLOUD_OIDC_TOKEN_TYPE",
        "NEXTCLOUD_MCP_SERVER_URL",
        "NEXTCLOUD_PUBLIC_ISSUER_URL",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)


def test_help_message_displays_all_options(runner):
    """Test that help message includes all new CLI options."""
    result = runner.invoke(run, ["--help"])
    assert result.exit_code == 0

    # Check for new options
    assert "--nextcloud-host" in result.output
    assert "--nextcloud-username" in result.output
    assert "--nextcloud-password" in result.output
    assert "--oauth-scopes" in result.output
    assert "--oauth-token-type" in result.output
    assert "--public-issuer-url" in result.output

    # Check for existing options
    assert "--oauth-client-id" in result.output
    assert "--oauth-client-secret" in result.output
    assert "--mcp-server-url" in result.output


def test_token_type_accepts_valid_values(runner, clean_env):
    """Test that --oauth-token-type accepts bearer and jwt (case insensitive)."""
    # Test lowercase bearer
    result = runner.invoke(run, ["--oauth-token-type", "bearer", "--help"])
    assert result.exit_code == 0

    # Test lowercase jwt
    result = runner.invoke(run, ["--oauth-token-type", "jwt", "--help"])
    assert result.exit_code == 0

    # Test uppercase (should work with case_sensitive=False)
    result = runner.invoke(run, ["--oauth-token-type", "Bearer", "--help"])
    assert result.exit_code == 0

    result = runner.invoke(run, ["--oauth-token-type", "JWT", "--help"])
    assert result.exit_code == 0


def test_token_type_rejects_invalid_values(runner, clean_env):
    """Test that --oauth-token-type rejects invalid values."""
    result = runner.invoke(run, ["--oauth-token-type", "invalid"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output


def test_cli_options_set_environment_variables(runner, clean_env, monkeypatch):
    """Test that CLI options set environment variables correctly."""
    # We need to mock the actual server startup to avoid connection errors
    # Store the env vars that get set
    captured_env = {}

    def mock_get_app(*args, **kwargs):
        # Capture environment variables after they're set by CLI
        captured_env.update(
            {
                "NEXTCLOUD_HOST": os.environ.get("NEXTCLOUD_HOST"),
                "NEXTCLOUD_USERNAME": os.environ.get("NEXTCLOUD_USERNAME"),
                "NEXTCLOUD_PASSWORD": os.environ.get("NEXTCLOUD_PASSWORD"),
                "NEXTCLOUD_OIDC_SCOPES": os.environ.get("NEXTCLOUD_OIDC_SCOPES"),
                "NEXTCLOUD_OIDC_TOKEN_TYPE": os.environ.get(
                    "NEXTCLOUD_OIDC_TOKEN_TYPE"
                ),
                "NEXTCLOUD_PUBLIC_ISSUER_URL": os.environ.get(
                    "NEXTCLOUD_PUBLIC_ISSUER_URL"
                ),
                "NEXTCLOUD_MCP_SERVER_URL": os.environ.get("NEXTCLOUD_MCP_SERVER_URL"),
            }
        )
        # Raise an exception to stop execution before uvicorn.run
        raise SystemExit(0)

    # Patch get_app to capture env vars
    monkeypatch.setattr("nextcloud_mcp_server.cli.get_app", mock_get_app)

    _ = runner.invoke(
        run,
        [
            "--nextcloud-host",
            "https://test.example.com",
            "--nextcloud-username",
            "testuser",
            "--nextcloud-password",
            "testpass",
            "--oauth-scopes",
            "openid nc:read",
            "--oauth-token-type",
            "jwt",
            "--public-issuer-url",
            "https://public.example.com",
            "--mcp-server-url",
            "http://test:8000",
        ],
    )

    # Verify environment variables were set
    assert captured_env["NEXTCLOUD_HOST"] == "https://test.example.com"
    assert captured_env["NEXTCLOUD_USERNAME"] == "testuser"
    assert captured_env["NEXTCLOUD_PASSWORD"] == "testpass"
    assert captured_env["NEXTCLOUD_OIDC_SCOPES"] == "openid nc:read"
    assert captured_env["NEXTCLOUD_OIDC_TOKEN_TYPE"] == "jwt"
    assert captured_env["NEXTCLOUD_PUBLIC_ISSUER_URL"] == "https://public.example.com"
    assert captured_env["NEXTCLOUD_MCP_SERVER_URL"] == "http://test:8000"


def test_cli_options_override_environment_variables(runner, monkeypatch):
    """Test that CLI options override environment variables."""
    # Set environment variables
    monkeypatch.setenv("NEXTCLOUD_HOST", "https://from-env.example.com")
    monkeypatch.setenv("NEXTCLOUD_USERNAME", "envuser")
    monkeypatch.setenv("NEXTCLOUD_OIDC_SCOPES", "openid")
    monkeypatch.setenv("NEXTCLOUD_OIDC_TOKEN_TYPE", "bearer")

    captured_env = {}

    def mock_get_app(*args, **kwargs):
        captured_env.update(
            {
                "NEXTCLOUD_HOST": os.environ.get("NEXTCLOUD_HOST"),
                "NEXTCLOUD_USERNAME": os.environ.get("NEXTCLOUD_USERNAME"),
                "NEXTCLOUD_OIDC_SCOPES": os.environ.get("NEXTCLOUD_OIDC_SCOPES"),
                "NEXTCLOUD_OIDC_TOKEN_TYPE": os.environ.get(
                    "NEXTCLOUD_OIDC_TOKEN_TYPE"
                ),
            }
        )
        raise SystemExit(0)

    monkeypatch.setattr("nextcloud_mcp_server.cli.get_app", mock_get_app)

    # Provide CLI options that should override env vars
    _ = runner.invoke(
        run,
        [
            "--nextcloud-host",
            "https://from-cli.example.com",
            "--nextcloud-username",
            "cliuser",
            "--oauth-scopes",
            "openid nc:write",
            "--oauth-token-type",
            "jwt",
        ],
    )

    # Verify CLI options overrode env vars
    assert captured_env["NEXTCLOUD_HOST"] == "https://from-cli.example.com"
    assert captured_env["NEXTCLOUD_USERNAME"] == "cliuser"
    assert captured_env["NEXTCLOUD_OIDC_SCOPES"] == "openid nc:write"
    assert captured_env["NEXTCLOUD_OIDC_TOKEN_TYPE"] == "jwt"


def test_environment_variables_used_when_cli_not_provided(runner, monkeypatch):
    """Test that environment variables are used when CLI options not provided."""
    # Set environment variables
    monkeypatch.setenv("NEXTCLOUD_HOST", "https://from-env.example.com")
    monkeypatch.setenv("NEXTCLOUD_USERNAME", "envuser")
    monkeypatch.setenv("NEXTCLOUD_PASSWORD", "envpass")
    monkeypatch.setenv("NEXTCLOUD_OIDC_SCOPES", "openid email")
    monkeypatch.setenv("NEXTCLOUD_OIDC_TOKEN_TYPE", "jwt")
    monkeypatch.setenv("NEXTCLOUD_PUBLIC_ISSUER_URL", "https://public-env.example.com")

    captured_env = {}

    def mock_get_app(*args, **kwargs):
        captured_env.update(
            {
                "NEXTCLOUD_HOST": os.environ.get("NEXTCLOUD_HOST"),
                "NEXTCLOUD_USERNAME": os.environ.get("NEXTCLOUD_USERNAME"),
                "NEXTCLOUD_PASSWORD": os.environ.get("NEXTCLOUD_PASSWORD"),
                "NEXTCLOUD_OIDC_SCOPES": os.environ.get("NEXTCLOUD_OIDC_SCOPES"),
                "NEXTCLOUD_OIDC_TOKEN_TYPE": os.environ.get(
                    "NEXTCLOUD_OIDC_TOKEN_TYPE"
                ),
                "NEXTCLOUD_PUBLIC_ISSUER_URL": os.environ.get(
                    "NEXTCLOUD_PUBLIC_ISSUER_URL"
                ),
            }
        )
        raise SystemExit(0)

    monkeypatch.setattr("nextcloud_mcp_server.cli.get_app", mock_get_app)

    # Don't provide any CLI options - should use env vars
    _ = runner.invoke(run, [])

    # Verify env vars were used
    assert captured_env["NEXTCLOUD_HOST"] == "https://from-env.example.com"
    assert captured_env["NEXTCLOUD_USERNAME"] == "envuser"
    assert captured_env["NEXTCLOUD_PASSWORD"] == "envpass"
    assert captured_env["NEXTCLOUD_OIDC_SCOPES"] == "openid email"
    assert captured_env["NEXTCLOUD_OIDC_TOKEN_TYPE"] == "jwt"
    assert (
        captured_env["NEXTCLOUD_PUBLIC_ISSUER_URL"] == "https://public-env.example.com"
    )


def test_default_values(runner, clean_env, monkeypatch):
    """Test that default values are used when neither CLI nor env vars provided."""
    captured_env = {}

    def mock_get_app(*args, **kwargs):
        captured_env.update(
            {
                "NEXTCLOUD_OIDC_SCOPES": os.environ.get("NEXTCLOUD_OIDC_SCOPES"),
                "NEXTCLOUD_OIDC_TOKEN_TYPE": os.environ.get(
                    "NEXTCLOUD_OIDC_TOKEN_TYPE"
                ),
                "NEXTCLOUD_MCP_SERVER_URL": os.environ.get("NEXTCLOUD_MCP_SERVER_URL"),
            }
        )
        raise SystemExit(0)

    monkeypatch.setattr("nextcloud_mcp_server.cli.get_app", mock_get_app)

    # Don't provide CLI options or env vars - should use defaults
    _ = runner.invoke(run, [])

    # Verify default values
    assert captured_env["NEXTCLOUD_OIDC_SCOPES"] == (
        "openid profile email "
        "notes:read notes:write "
        "calendar:read calendar:write "
        "todo:read todo:write "
        "contacts:read contacts:write "
        "cookbook:read cookbook:write "
        "deck:read deck:write "
        "tables:read tables:write "
        "files:read files:write "
        "sharing:read sharing:write"
    )
    assert captured_env["NEXTCLOUD_OIDC_TOKEN_TYPE"] == "bearer"
    assert captured_env["NEXTCLOUD_MCP_SERVER_URL"] == "http://localhost:8000"


def test_oauth_token_type_case_normalization(runner, clean_env, monkeypatch):
    """Test that token type is normalized correctly regardless of input case."""
    captured_env = {}

    def mock_get_app(*args, **kwargs):
        captured_env["NEXTCLOUD_OIDC_TOKEN_TYPE"] = os.environ.get(
            "NEXTCLOUD_OIDC_TOKEN_TYPE"
        )
        raise SystemExit(0)

    monkeypatch.setattr("nextcloud_mcp_server.cli.get_app", mock_get_app)

    # Test uppercase JWT
    runner.invoke(run, ["--oauth-token-type", "JWT"])
    assert captured_env["NEXTCLOUD_OIDC_TOKEN_TYPE"] in ["JWT", "jwt"]

    # Test mixed case Bearer
    captured_env.clear()
    runner.invoke(run, ["--oauth-token-type", "Bearer"])
    assert captured_env["NEXTCLOUD_OIDC_TOKEN_TYPE"] in ["Bearer", "bearer"]


def test_stdio_transport_option(runner):
    """Test that stdio transport is available as a CLI option."""
    result = runner.invoke(run, ["--help"])
    assert result.exit_code == 0
    assert "stdio" in result.output
    assert "--transport" in result.output


def test_transport_accepts_valid_values(runner, clean_env):
    """Test that --transport accepts valid values: streamable-http, http, stdio."""
    # Test streamable-http (default)
    result = runner.invoke(run, ["--transport", "streamable-http", "--help"])
    assert result.exit_code == 0

    # Test http
    result = runner.invoke(run, ["--transport", "http", "--help"])
    assert result.exit_code == 0

    # Test stdio
    result = runner.invoke(run, ["--transport", "stdio", "--help"])
    assert result.exit_code == 0


def test_transport_rejects_invalid_values(runner, clean_env):
    """Test that --transport rejects invalid values."""
    result = runner.invoke(run, ["--transport", "invalid"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output


def test_stdio_transport_skips_uvicorn(runner, clean_env, monkeypatch):
    """Test that stdio transport doesn't call uvicorn but calls mcp.run() instead."""
    monkeypatch.setenv("NEXTCLOUD_HOST", "https://test.example.com")
    monkeypatch.setenv("NEXTCLOUD_USERNAME", "testuser")
    monkeypatch.setenv("NEXTCLOUD_PASSWORD", "testpass")

    uvicorn_called = {"called": False}
    mcp_run_called = {"called": False, "transport": None}

    def mock_get_app(transport, enabled_apps):
        class MockMCP:
            def run(self, transport):
                mcp_run_called["called"] = True
                mcp_run_called["transport"] = transport
                # Exit early to prevent actual server startup
                raise SystemExit(0)

        return (None if transport == "stdio" else object(), MockMCP())

    def mock_uvicorn_run(*args, **kwargs):
        uvicorn_called["called"] = True
        raise SystemExit(0)

    monkeypatch.setattr("nextcloud_mcp_server.cli.get_app", mock_get_app)
    monkeypatch.setattr("nextcloud_mcp_server.cli.uvicorn.run", mock_uvicorn_run)

    # Run with stdio transport
    _ = runner.invoke(run, ["--transport", "stdio"])

    # Should call mcp.run() with stdio, not uvicorn
    assert mcp_run_called["called"]
    assert mcp_run_called["transport"] == "stdio"
    assert not uvicorn_called["called"]


def test_http_transport_uses_uvicorn(runner, clean_env, monkeypatch):
    """Test that HTTP transports use uvicorn."""
    monkeypatch.setenv("NEXTCLOUD_HOST", "https://test.example.com")
    monkeypatch.setenv("NEXTCLOUD_USERNAME", "testuser")
    monkeypatch.setenv("NEXTCLOUD_PASSWORD", "testpass")

    uvicorn_called = {"called": False}
    mcp_run_called = {"called": False}

    def mock_get_app(transport, enabled_apps):
        class MockMCP:
            def run(self, transport):
                mcp_run_called["called"] = True

        return (object(), MockMCP())

    def mock_uvicorn_run(*args, **kwargs):
        uvicorn_called["called"] = True
        raise SystemExit(0)

    monkeypatch.setattr("nextcloud_mcp_server.cli.get_app", mock_get_app)
    monkeypatch.setattr("nextcloud_mcp_server.cli.uvicorn.run", mock_uvicorn_run)

    # Run with streamable-http transport
    _ = runner.invoke(run, ["--transport", "streamable-http"])

    # Should call uvicorn, not mcp.run()
    assert uvicorn_called["called"]
    assert not mcp_run_called["called"]
