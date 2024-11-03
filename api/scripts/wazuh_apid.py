#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import signal
import sys
import warnings
from functools import partial

SSL_DEPRECATED_MESSAGE = 'The `{ssl_protocol}` SSL protocol is deprecated.'
CACHE_DELETED_MESSAGE = 'The `cache` API configuration option no longer takes effect since {release} and will ' \
                        'be completely removed in the next major release.'

API_MAIN_PROCESS = 'wazuh-apid'
API_LOCAL_REQUEST_PROCESS = 'wazuh-apid_exec'
API_AUTHENTICATION_PROCESS = 'wazuh-apid_auth'
API_SECURITY_EVENTS_PROCESS = 'wazuh-apid_events'

logger = None


def spawn_process_pool():
    """Spawn general process pool child."""

    exec_pid = os.getpid()
    pyDaemonModule.create_pid(API_LOCAL_REQUEST_PROCESS, exec_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def spawn_events_pool():
    """Spawn events process pool child."""

    events_pid = os.getpid()
    pyDaemonModule.create_pid(API_SECURITY_EVENTS_PROCESS, events_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def spawn_authentication_pool():
    """Spawn authentication process pool child."""

    auth_pid = os.getpid()
    pyDaemonModule.create_pid(API_AUTHENTICATION_PROCESS, auth_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def configure_ssl(params: dict, config):
    """Configure https files and permission, and set the uvicorn dictionary configuration keys.

    Parameters
    ----------
    params : dict
        uvicorn parameter configuration dictionary.
    config: APISSLConfig
        Configuration for SSL
    """

    from wazuh.core.common import WAZUH_SERVER_YML

    try:
        # Generate SSL if it does not exist and HTTPS is enabled
        if not os.path.exists(config.key) or not os.path.exists(config.cert):
            logger.info('HTTPS is enabled but cannot find the private key and/or certificate. '
                        'Attempting to generate them')
            private_key = generate_private_key(config.key)
            logger.info(
                f"Generated private key file in WAZUH_PATH/{to_relative_path(config.key)}")
            generate_self_signed_certificate(private_key, config.cert)
            logger.info(
                f"Generated certificate file in WAZUH_PATH/{to_relative_path(config.cert)}")

        # Load SSL context
        allowed_ssl_protocols = {
            'tls': ssl.PROTOCOL_TLS,
            'tlsv1': ssl.PROTOCOL_TLSv1,
            'tlsv1.1': ssl.PROTOCOL_TLSv1_1,
            'tlsv1.2': ssl.PROTOCOL_TLSv1_2,
            'auto': ssl.PROTOCOL_TLS_SERVER
        }

        config_ssl_protocol = config.ssl_protocol
        ssl_protocol = allowed_ssl_protocols[config_ssl_protocol.lower()]

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            if ssl_protocol in (ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1):
                logger.warning(SSL_DEPRECATED_MESSAGE.format(ssl_protocol=config_ssl_protocol))

        # Check and assign ownership to wazuh user for server.key and server.crt files
        utils.assign_wazuh_ownership(config.key)
        utils.assign_wazuh_ownership(config.cert)

        params['ssl_version'] = ssl.PROTOCOL_TLS_SERVER

        if config.use_ca:
            params['ssl_cert_reqs'] = ssl.CERT_REQUIRED
            params['ssl_ca_certs'] = config.ca

        params['ssl_certfile'] = config.cert
        params['ssl_keyfile'] = config.key

        # Load SSL ciphers if any has been specified
        if config.ssl_ciphers != "":
            params['ssl_ciphers'] = config.ssl_ciphers.upper()

    except ssl.SSLError as exc:
        error = APIError(
            2003, details='Private key does not match with the certificate')
        logger.error(error)
        raise error from exc
    except IOError as exc:
        if exc.errno == 22:
            error = APIError(2003, details='PEM phrase is not correct')
            logger.error(error)
            raise error from exc
        elif exc.errno == 13:
            error = APIError(2003,
                                details='Ensure the certificates have the correct permissions')
            logger.error(error)
            raise error from exc
        else:
            msg = f'Wazuh API SSL ERROR. Please, ensure ' \
                    f'if path to certificates is correct in the configuration ' \
                    f'file {WAZUH_SERVER_YML}'
            print(msg)
            logger.error(msg)
            raise exc from exc


from wazuh.core.config.models.central_config import ManagementAPIConfig


def start(params: dict, config: ManagementAPIConfig):
    """Run the Wazuh API.

    If another Wazuh API is running, this function will fail because uvicorn server will
    not be able to create server processes in the same port.
    The function creates the pool processes, the AsyncApp instance, setups the API spec.yaml,
    the middleware classes, the error_handlers, the lifespan, and runs the uvicorn ASGI server.

    Parameters
    ----------
    params : dict
        uvicorn parameter configuration dictionary.
    config: ManagementAPIConfig
        API Configuration
    """
    try:
        check_database_integrity()
    except Exception as db_integrity_exc:
        raise APIError(2012, details=str(db_integrity_exc)) from db_integrity_exc

    # Spawn child processes with their own needed imports
    if 'thread_pool' not in common.mp_pools.get():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            asyncio.wait([loop.run_in_executor(pool,
                                               getattr(sys.modules[__name__], f'spawn_{name}'))
                          for name, pool in common.mp_pools.get().items()]))

    # Set up API
    app = AsyncApp(
        __name__,
        specification_dir=os.path.join(api_path[0], 'spec'),
        swagger_ui_options=SwaggerUIOptions(swagger_ui=False),
        pythonic_params=True,
        lifespan=lifespan_handler,
        uri_parser_class=APIUriParser
    )
    app.add_api('spec.yaml',
                arguments={
                    'title': 'Wazuh API',
                    'protocol': 'https',
                    'host': params['host'],
                    'port': params['port']},
                strict_validation=True,
                validate_responses=False
                )

    # Maximum body size that the API can accept (bytes)
    if config.access.max_request_per_minute > 0:
        app.add_middleware(CheckRateLimitsMiddleware, MiddlewarePosition.BEFORE_SECURITY)
    app.add_middleware(CheckExpectHeaderMiddleware)
    app.add_middleware(CheckBlockedIP, MiddlewarePosition.BEFORE_SECURITY)
    app.add_middleware(WazuhAccessLoggerMiddleware, MiddlewarePosition.BEFORE_EXCEPTION)
    app.add_middleware(SecureHeadersMiddleware)

    app.add_middleware(ContentSizeLimitMiddleware, max_content_size=config.max_upload_size)
    app.add_error_handler(ContentSizeExceeded, error_handler.content_size_handler)

    # Enable CORS
    if config.cors.enabled:
        app.add_middleware(
            CORSMiddleware,
            position=MiddlewarePosition.BEFORE_EXCEPTION,
            allow_origins=config.cors.source_route,
            expose_headers=config.cors.expose_headers,
            allow_headers=config.cors.allow_headers,
            allow_credentials=config.cors.allow_credentials,
        )


    # Add error handlers to format exceptions
    app.add_error_handler(ExpectFailedException, error_handler.expect_failed_error_handler)
    app.add_error_handler(Unauthorized, error_handler.unauthorized_error_handler)
    app.add_error_handler(HTTPException, error_handler.http_error_handler)
    app.add_error_handler(ProblemException, error_handler.problem_error_handler)
    app.add_error_handler(403, error_handler.problem_error_handler)


    # Start uvicorn server
    try:
        uvicorn.run(app, **params)

    except OSError as exc:
        if exc.errno == 98:
            error = APIError(2010)
            logger.error(error)
            raise error
        else:
            logger.error(exc)
            raise exc


def print_version():
    from wazuh.core.cluster import __author__, __licence__, __version__, __wazuh_name__
    print('\n{} {} - {}\n\n{}'.format(__wazuh_name__, __version__, __author__, __licence__))



def version():
    """Print API version and exits with 0 code. """
    print_version()
    sys.exit(0)


def add_debug2_log_level_and_error():
    """Add a new debug level used by wazuh api and framework."""

    logging.DEBUG2 = 6

    def debug2(self, message, *args, **kws):
        if self.isEnabledFor(logging.DEBUG2):
            self._log(logging.DEBUG2, message, args, **kws)

    def error(self, msg, *args, **kws):
        if self.isEnabledFor(logging.ERROR):
            if 'exc_info' not in kws:
                kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
            self._log(logging.ERROR, msg, args, **kws)

    logging.addLevelName(logging.DEBUG2, "DEBUG2")

    logging.Logger.debug2 = debug2
    logging.Logger.error = error


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    #########################################################################################
    parser.add_argument('-f', help="Run in foreground",
                        action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version",
                        action='store_true', dest="version")
    #TODO(26356) - Delete this parameter that isn't used
    parser.add_argument('-t', help="Test configuration",
                        action='store_true', dest='test_config')
    parser.add_argument('-r', help="Run as root",
                        action='store_true', dest='root')
    parser.add_argument('-c', help="Configuration file to use",
                        type=str, metavar='config', dest='config_file')
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.",
                        action='count',
                        dest='debug_level')
    args = parser.parse_args()

    if args.version:
        version()
        sys.exit(0)

    import asyncio
    import logging
    import logging.config
    import ssl

    import uvicorn
    from connexion import AsyncApp
    from connexion.exceptions import HTTPException, ProblemException, Unauthorized
    from connexion.middleware import MiddlewarePosition
    from connexion.options import SwaggerUIOptions
    from content_size_limit_asgi import ContentSizeLimitMiddleware
    from content_size_limit_asgi.errors import ContentSizeExceeded
    from starlette.middleware.cors import CORSMiddleware
    from wazuh.core import common, pyDaemonModule, utils
    from wazuh.rbac.orm import check_database_integrity
    from wazuh.core.config.client import CentralizedConfig
    from wazuh.core.config.models.management_api import ManagementAPIConfig

    from api import __path__ as api_path
    from api import error_handler
    from api.alogging import set_logging
    from api.api_exception import APIError, ExpectFailedException
    from api.configuration import generate_private_key, generate_self_signed_certificate
    from api.constants import API_LOG_PATH
    from api.middlewares import (
        CheckBlockedIP,
        CheckRateLimitsMiddleware,
        SecureHeadersMiddleware,
        WazuhAccessLoggerMiddleware,
        CheckExpectHeaderMiddleware,
    )
    from api.signals import lifespan_handler
    from api.uri_parser import APIUriParser
    from api.util import to_relative_path

    try:
        CentralizedConfig.load()
    except Exception as e:
        print(f"Error when trying to start the Management Wazuh API. {e}")
        sys.exit(1)
    management_config = CentralizedConfig.get_management_api_config()

    # Configure uvicorn parameters dictionary
    uvicorn_params = {}
    uvicorn_params['host'] = management_config.host
    uvicorn_params['port'] = management_config.port
    uvicorn_params['loop'] = 'uvloop'
    uvicorn_params['server_header'] = False

    # Set up logger file
    try:
        uvicorn_params['log_config'] = set_logging(log_filepath=API_LOG_PATH,
                                                   logging_config=management_config.logging,
                                                   foreground_mode=args.foreground)
    except APIError as api_log_error:
        print(f"Error when trying to start the Wazuh API. {api_log_error}")
        sys.exit(1)

    # set permission on log files
    for handler in uvicorn_params['log_config']['handlers'].values():
        if 'filename' in handler:
            utils.assign_wazuh_ownership(handler['filename'])
            os.chmod(handler['filename'], 0o660)

    # Configure and create the wazuh-api logger
    add_debug2_log_level_and_error()
    logging.config.dictConfig(uvicorn_params['log_config'])
    logger = logging.getLogger('wazuh-api')

    configure_ssl(uvicorn_params, management_config.ssl)

    # Check for unused PID files
    utils.clean_pid_files(API_MAIN_PROCESS)

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()
    else:
        logger.info('Starting API in foreground')

    # Drop privileges to wazuh
    if not args.root:
        if management_config.drop_privileges:
            os.setgid(common.wazuh_gid())
            os.setuid(common.wazuh_uid())
    else:
        logger.info('Starting API as root')

    pid = os.getpid()
    pyDaemonModule.create_pid(API_MAIN_PROCESS, pid)

    signal.signal(signal.SIGTERM, partial(pyDaemonModule.exit_handler, process_name=API_MAIN_PROCESS, logger=logger))
    try:
        start(uvicorn_params, config=management_config)
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)
    except Exception as e:
        print(f'Internal error when trying to start the Wazuh API. {e}')
        sys.exit(1)
    finally:
        pyDaemonModule.delete_child_pids(API_MAIN_PROCESS, pid, logger)
        pyDaemonModule.delete_pid(API_MAIN_PROCESS, pid)
