# Cooker Client Python
Python (asyncio) client library for Quortex Cooker API.

## Installation

This client can be installed by running `pip install aio_cooker_client`. It requires Python 3.7+ to run.

## Usage

```python
    import aio_cooker_client

    client = aio_cooker_client.CookerClient(
        cooker_domain_name=DOMAIN_NAME,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        cache_ttl=120,
    )

    cred = client.get_credential()
```
