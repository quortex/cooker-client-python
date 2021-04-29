import asyncio
import json
import time
from functools import partial

import aiohttp
import pytest
from aiohttp.client import ClientTimeout


class Credential:
    """Object containing informations needed to build a cloudfront cookie.

    Attributes:
        policy -- cloudfront policy, encoded in cloudfront base64
        signature -- signature of this policy, encoded in cloudfront base64
        key_pair_id -- identifier of the public key registered in cloudfront
    """

    policy: str
    signature: str
    key_pair_id: str

    def __init__(self, policy: str, signature: str, key_pair_id: str):
        self.policy = policy
        self.signature = signature
        self.key_pair_id = key_pair_id

    def __str__(self) -> str:
        return str(self.__dict__)


class CookerError(Exception):
    """Base class for all cooker exceptions."""


class CookerConnectionError(CookerError):
    """Raised when client could not connect to auth or api backends.

    Attributes:
        message -- explanation of the error
    """

    message: str

    def __init__(self, message: str) -> None:
        self.message = message

    def __str__(self) -> str:
        return f"connection error : {self.message} "


class CookerTokenError(CookerError):
    """Raised when client could not get a token.

    Attributes:
        message -- explanation of the error
    """

    message: str

    def __init__(self, message: str) -> None:
        self.message = message

    def __str__(self) -> str:
        return f"token error : {self.message} "


class CookerResponseError(CookerError):
    """Raised when server responded a 40x or 50x response.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message) -> None:
        self.message = message

    def __str__(self) -> str:
        return f"bad response error : {self.message} "


class CookerClient:
    credential_endpoint: str
    token_endpoint: str

    client_id: str
    client_secret: str
    client_timeout: int
    cache_ttl: int

    _cache_expiration: float
    _cached_credential: Credential

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        cache_ttl: int,
        client_timeout: int = 10,
        cooker_domain_name: str = "",
        credential_endpoint_override: str = "",
        token_endpoint_override: str = "",
    ) -> None:
        # API endpoints configuration
        self.credential_endpoint = f"https://{cooker_domain_name}/v1/credentials"
        if credential_endpoint_override:
            self.credential_endpoint = credential_endpoint_override

        self.token_endpoint = f"https://auth.{cooker_domain_name}/oauth2/token"
        if token_endpoint_override:
            self.token_endpoint = token_endpoint_override

        # Client parameters
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_timeout = client_timeout
        self.cache_ttl = cache_ttl

        # Setup cache
        self._timer = time.monotonic
        self._cache_expiration = 0.0

    async def get_credential(self) -> Credential:
        """Function returning asynchronously a credential, either from local cache or from cooker.

        Raises:
            CookerConnectionError: error thrown if the client could not connect to auth or credential endpoints.
            CookerTokenError: error thrown if the client fails to retrieve a token from the auth endpoint.
            CookerResponseError: error thrown if the client received an invalid response from the credential endpoint (40x or 50x).

        Returns:
            Credential: credential retrieved from from local cache or from cooker
        """
        if self._timer() > self._cache_expiration:
            # NOTE : this code is not protected with a lock, thus several requests could cache-miss at the same tim.
            # This is not cpu-costly at time of writting, and the last to enter will overwrite the cache which is ok

            # Warning : this does not decode the policy, thus does not check for bad cached value
            async with aiohttp.ClientSession(
                timeout=ClientTimeout(self.client_timeout)
            ) as session:
                token = await self._retrieve_token(
                    session, self.client_id, self.client_secret
                )
                self._cached_credential = await self._retrieve_credential(
                    session, token
                )
                self._cache_expiration = self._timer() + self.cache_ttl

        return self._cached_credential

    async def _retrieve_token(
        self, session: aiohttp.ClientSession, client_id: str, client_secret: str
    ) -> str:
        try:
            response = await session.post(
                url=self.token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
            )
        except aiohttp.ClientError as exc:
            raise CookerConnectionError("failed to connect to token endpoint") from exc

        try:
            content = await response.json()
        except Exception as exc:
            raise CookerTokenError(
                "received bad mimetype or badly formatted token : {}".format(
                    await response.text()
                )
            ) from exc

        content = await response.json()
        if response.status != 200:
            raise CookerTokenError(
                "client failed to retrieve a token : {}".format(
                    content["error"] if "error" in content else await response.text()
                )
            )

        if "access_token" not in content:
            raise CookerTokenError(
                "client received a badly formatted token : {}".format(content)
            )

        return content["access_token"]

    async def _retrieve_credential(
        self, session: aiohttp.ClientSession, token: str
    ) -> Credential:
        try:
            response = await session.post(
                url=self.credential_endpoint,
                headers={"Accept": "application/json", "Authorization": token},
            )
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise CookerConnectionError(
                "failed to connect to credential endpoint"
            ) from exc

        if response.status != 201:
            try:
                error = (await response.json())["error"]
            except Exception as exc:
                error = await response.text()
            raise CookerResponseError(
                f"client got {response.status} while retrieving credential : {error}"
            )

        try:
            return json.loads(
                await response.text(), object_hook=lambda d: Credential(**d)
            )
        except Exception as exc:
            raise CookerResponseError(
                "client failed to parse credential : {}".format(await response.text())
            ) from exc
