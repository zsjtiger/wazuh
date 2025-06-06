from copy import deepcopy
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from freezegun import freeze_time
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.base import ValidateFilePathMixin

from comms_api.authentication.test.conftest import get_default_configuration

with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
    default_config = get_default_configuration()
    CentralizedConfig._config = default_config

    from server_management_api.authentication import JWT_ISSUER
    from wazuh.core.exception import WazuhCommsAPIError

    from comms_api.authentication.authentication import (
        JWT_AUDIENCE,
        JWT_EXPIRATION,
        JWTBearer,
        decode_token,
        generate_token,
    )
    from comms_api.routers.exceptions import HTTPError

    payload = {
        'iss': JWT_ISSUER,
        'aud': JWT_AUDIENCE,
        'iat': 0,
        'exp': 0 + JWT_EXPIRATION,
        'uuid': '019113d7-d428-725e-a87a-a7661cf5f641',
    }


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1))
@patch('comms_api.authentication.authentication.decode_token', return_value=payload)
async def test_jwt_bearer(decode_token_mock):
    """Validate that the `JWTBearer` class works as expected."""
    token = 'token'
    mock_req = MagicMock()
    mock_req.headers = {'Authorization': f'Bearer {token}'}
    jwt = JWTBearer()
    credentials = await jwt(mock_req)

    decode_token_mock.assert_called_once()
    assert mock_req.state.agent_uuid == payload['uuid']
    assert credentials == token


@pytest.mark.asyncio
async def test_jwt_bearer_ko():
    """Validate that the `JWTBearer` class handles internal exceptions successfully."""
    mock_req = MagicMock()
    jwt = JWTBearer()

    message = 'not enough values to unpack \(expected 3\, got 0\)'
    with pytest.raises(HTTPError, match=rf'{status.HTTP_403_FORBIDDEN}: {message}'):
        _ = await jwt(mock_req)


@pytest.mark.asyncio
@patch('comms_api.authentication.authentication.decode_token', side_effect=WazuhCommsAPIError(2706))
async def test_jwt_bearer_decode_ko(decode_token_mock):
    """Validate that the `JWTBearer` class handles decode exceptions successfully."""
    mock_req = MagicMock()
    mock_req.headers = {'Authorization': 'Bearer token'}
    jwt = JWTBearer()

    with pytest.raises(HTTPError, match='2706: Invalid authentication token'):
        _ = await jwt(mock_req)


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1))
@patch('comms_api.authentication.authentication.encode', return_value='test_token')
@patch(
    'comms_api.authentication.authentication.get_keypair',
    return_value=('-----BEGIN PRIVATE KEY-----', '-----BEGIN PUBLIC KEY-----'),
)
async def test_generate_token(mock_get_keypair, mock_encode):
    """Verify that the `generate_token` function works as expected."""
    result = generate_token(uuid=payload['uuid'])
    assert result == 'test_token'

    # Check all functions are called with expected params
    mock_get_keypair.assert_called_once()
    mock_encode.assert_called_once_with(payload, '-----BEGIN PRIVATE KEY-----', algorithm='RS256')


@freeze_time(datetime(1970, 1, 1))
@patch('comms_api.authentication.authentication.decode')
@patch(
    'comms_api.authentication.authentication.get_keypair',
    return_value=('-----BEGIN PRIVATE KEY-----', '-----BEGIN PUBLIC KEY-----'),
)
def test_decode_token(mock_get_keypair, mock_decode):
    """Verify that the `decode_token` function works as expected."""
    mock_decode.return_value = deepcopy(payload)

    decoded_token = decode_token(token='test_token')

    assert decoded_token == decoded_token
    mock_get_keypair.assert_called_once()


@patch(
    'comms_api.authentication.authentication.get_keypair',
    return_value=('-----BEGIN PRIVATE KEY-----', '-----BEGIN PUBLIC KEY-----'),
)
def test_decode_token_ko(mock_get_keypair):
    """Assert exceptions are handled as expected inside the `decode_token` function."""
    with pytest.raises(WazuhCommsAPIError, match='Error 2706 - Invalid authentication token'):
        _ = decode_token(token='test_token')

    mock_get_keypair.assert_called_once()
