import asyncio
import json
import logging
import os
from urllib.parse import parse_qs

import aio_cooker_client
import pytest
from aiohttp import web
from aiohttp.client_exceptions import ClientPayloadError
from aiohttp.web_request import Request
from aiohttp.web_response import StreamResponse


# This handler mocks cognito server for our usage
async def token_handler(request: Request) -> StreamResponse:
    form = parse_qs((await request.read()).decode("utf-8"))
    client_id = form.get("client_id", [""])[0]
    client_secret = form.get("client_secret", [""])[0]
    grant_type = form.get("grant_type", [""])[0]

    if client_id != "a_valid_client" or client_secret != "a_valid_secret":
        return web.Response(status=400, body=json.dumps({"error": "invalid_client"}))

    if grant_type != "client_credentials":
        return web.Response(status=400, body=json.dumps({"error": "invalid_request"}))

    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps(
            {
                "access_token": "a_valid_token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        ),
    )


# This handler mocks the api gateway and the cooker
async def credentials_handler(request: Request) -> StreamResponse:
    if request.headers.get("Authorization", "") != "a_valid_token":
        return web.Response(body=json.dumps({"message": "Unauthorized"}), status=401)

    return web.Response(
        status=201,
        content_type="application/json",
        body=json.dumps(
            {
                "policy": "a_policy",
                "signature": "a_policy_signature",
                "key_pair_id": "a_key_pair_id",
            }
        ),
    )


# This handler mocks a route timeouting
async def timeout_handler(request: Request) -> StreamResponse:
    await asyncio.sleep(30)
    return web.Response()


@pytest.fixture
async def mock_server():
    # Prepare mocked routes
    app = web.Application()
    logging.basicConfig(level=logging.DEBUG)
    app.router.add_post("/oauth2/token", token_handler)
    app.router.add_post("/v1/credentials", credentials_handler)
    app.router.add_post("/timeout", timeout_handler)

    # Run server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8080)
    print("Serving mockserver ...")
    await site.start()

    # Yield to execute fixtured tests
    yield

    # Stop server after test execution
    await site.stop()
    await runner.cleanup()


@pytest.mark.asyncio
async def test_get_credential(mock_server):
    client = aio_cooker_client.CookerClient(
        credential_endpoint_override=f"http://localhost:8080/v1/credentials",
        token_endpoint_override=f"http://localhost:8080/oauth2/token",
        client_id="a_valid_client",
        client_secret="a_valid_secret",
        cache_ttl=10,
    )

    cred = await client.get_credential()
    assert cred.policy == "a_policy"
    assert cred.signature == "a_policy_signature"
    assert cred.key_pair_id == "a_key_pair_id"


@pytest.mark.asyncio
async def test_wrong_credentials(mock_server):
    client = aio_cooker_client.CookerClient(
        credential_endpoint_override=f"http://localhost:8080/v1/credential",
        token_endpoint_override=f"http://localhost:8080/oauth2/token",
        client_id="not_a_valid_id",
        client_secret="not_a_valid_secret",
        cache_ttl=10,
    )

    with pytest.raises(aio_cooker_client.CookerTokenError):
        _ = await client.get_credential()


@pytest.mark.asyncio
async def test_server_404(mock_server):
    client = aio_cooker_client.CookerClient(
        credential_endpoint_override=f"http://localhost:8080/this-should-not-exist",
        token_endpoint_override=f"http://localhost:8080/oauth2/token",
        client_id="a_valid_client",
        client_secret="a_valid_secret",
        cache_ttl=10,
    )

    with pytest.raises(aio_cooker_client.CookerResponseError):
        _ = await client.get_credential()


@pytest.mark.asyncio
async def test_bad_domain(mock_server):
    client = aio_cooker_client.CookerClient(
        cooker_domain_name="this-should-not-resolve.example.org",
        client_id="a_valid_client",
        client_secret="a_valid_secret",
        cache_ttl=10,
    )

    with pytest.raises(aio_cooker_client.CookerConnectionError):
        _ = await client.get_credential()


@pytest.mark.asyncio
async def test_timeout(mock_server):
    client = aio_cooker_client.CookerClient(
        credential_endpoint_override=f"http://localhost:8080/timeout",
        token_endpoint_override=f"http://localhost:8080/oauth2/token",
        client_id="a_valid_client",
        client_secret="a_valid_secret",
        cache_ttl=10,
        client_timeout=1,
    )

    with pytest.raises(aio_cooker_client.CookerConnectionError):
        _ = await client.get_credential()
