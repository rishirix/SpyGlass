"""AWS connection layer for Spyglass.

Single place where boto3 sessions/clients are created.
- DEMO mode: talks to a local moto emulator (never real AWS).
- LIVE mode: talks to real AWS using credentials from memory, a named
  profile, or the standard AWS credential chain.

Credentials are never logged, persisted, or returned to callers.
"""
import re
import threading
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

import config


class AWSConnectionError(Exception):
    """Connection/auth problem with a machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# Short timeouts so a dead endpoint fails fast; standard retry mode
# handles throttling.
_BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=15,
    retries={"max_attempts": 3, "mode": "standard"},
)

_LOCAL_HOSTS = {"127.0.0.1", "localhost"}
_DEMO_REGION = "us-east-1"

_lock = threading.Lock()
_state = {"mode": config.MODE, "credentials": None}


# ---------------------------------------------------------------- state --

def get_mode() -> str:
    with _lock:
        return _state["mode"]


def set_mode(mode: str) -> None:
    mode = (mode or "").strip().lower()
    if mode not in ("demo", "live"):
        raise AWSConnectionError("INVALID_INPUT", "Mode must be 'demo' or 'live'.")
    with _lock:
        _state["mode"] = mode


def set_credentials(access_key_id, secret_access_key, region=None, session_token=None):
    """Hold credentials in server memory only (never written to disk)."""
    access_key_id = (access_key_id or "").strip()
    secret_access_key = (secret_access_key or "").strip()
    region = (region or config.REGION).strip()
    session_token = (session_token or "").strip() or None

    if not re.fullmatch(r"[A-Z0-9]{16,128}", access_key_id):
        raise AWSConnectionError("INVALID_INPUT", "Access Key ID format looks invalid.")
    if len(secret_access_key) < 20:
        raise AWSConnectionError("INVALID_INPUT", "Secret Access Key looks too short.")
    if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", region):
        raise AWSConnectionError("INVALID_INPUT", "Region format looks invalid (e.g. ap-south-1).")

    with _lock:
        _state["credentials"] = {
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "session_token": session_token,
            "region": region,
        }


def clear_credentials() -> None:
    with _lock:
        _state["credentials"] = None


def describe_state() -> dict:
    """Safe-to-display state. Never includes secrets."""
    with _lock:
        creds = _state["credentials"]
        return {
            "mode": _state["mode"],
            "using_form_credentials": creds is not None,
            "region": _current_region(creds),
        }


def _current_region(creds) -> str:
    if _state["mode"] == "demo":
        return _DEMO_REGION
    return creds["region"] if creds else config.REGION


def get_region() -> str:
    with _lock:
        return _current_region(_state["credentials"])


# ------------------------------------------------------ session/clients --

def _build_session() -> boto3.session.Session:
    with _lock:
        mode = _state["mode"]
        creds = _state["credentials"]
        region = _current_region(creds)

    try:
        if mode == "demo":
            host = urlparse(config.MOTO_ENDPOINT).hostname
            if host not in _LOCAL_HOSTS:
                raise AWSConnectionError(
                    "UNSAFE_ENDPOINT",
                    "Demo mode may only use a local endpoint (127.0.0.1/localhost).",
                )
            # Dummy values: moto accepts anything; these are not real secrets.
            return boto3.session.Session(
                aws_access_key_id="testing",
                aws_secret_access_key="testing",
                region_name=region,
            )

        if creds:
            return boto3.session.Session(
                aws_access_key_id=creds["access_key_id"],
                aws_secret_access_key=creds["secret_access_key"],
                aws_session_token=creds["session_token"],
                region_name=region,
            )
        if config.AWS_PROFILE:
            return boto3.session.Session(profile_name=config.AWS_PROFILE, region_name=region)
        return boto3.session.Session(region_name=region)
    except ProfileNotFound:
        raise AWSConnectionError("PROFILE_NOT_FOUND", "The configured AWS profile was not found.")


def get_client(service: str):
    """Return a boto3 client for the active mode."""
    session = _build_session()
    kwargs = {"config": _BOTO_CONFIG}
    if get_mode() == "demo":
        kwargs["endpoint_url"] = config.MOTO_ENDPOINT
    return session.client(service, **kwargs)


# ------------------------------------------------------------ verification --

def _result(connected: bool, **extra) -> dict:
    base = {
        "connected": connected,
        "mode": get_mode(),
        "region": get_region(),
        "account_id": None,
        "arn": None,
        "user_id": None,
        "error_code": None,
        "error": None,
    }
    base.update(extra)
    return base


def verify_connection() -> dict:
    """Check credentials with sts:GetCallerIdentity. Never raises."""
    try:
        identity = get_client("sts").get_caller_identity()
        return _result(
            True,
            account_id=identity["Account"],
            arn=identity["Arn"],
            user_id=identity["UserId"],
        )
    except AWSConnectionError as e:
        return _result(False, error_code=e.code, error=e.message)
    except (NoCredentialsError, PartialCredentialsError):
        return _result(False, error_code="NO_CREDENTIALS",
                       error="No AWS credentials found. Configure the AWS CLI, "
                             "set environment variables, or use the Connect form.")
    except (EndpointConnectionError, ConnectTimeoutError):
        return _result(False, error_code="ENDPOINT_UNREACHABLE",
                       error="Could not reach the AWS endpoint. In demo mode, is the "
                             "moto server running? In live mode, check your network.")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        msg = e.response.get("Error", {}).get("Message", "")
        if code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "AuthFailure"):
            return _result(False, error_code="INVALID_CREDENTIALS",
                           error="AWS rejected these credentials (invalid key or secret).")
        if code in ("ExpiredToken", "ExpiredTokenException", "RequestExpired"):
            return _result(False, error_code="EXPIRED_CREDENTIALS",
                           error="The credentials or session token have expired.")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return _result(False, error_code="ACCESS_DENIED",
                           error="Access denied while verifying identity.")
        return _result(False, error_code="AWS_ERROR", error=f"{code}: {msg}")
    except BotoCoreError as e:
        return _result(False, error_code="AWS_ERROR", error=f"AWS SDK error: {type(e).__name__}")


if __name__ == "__main__":
    import json
    print(json.dumps(verify_connection(), indent=2))
