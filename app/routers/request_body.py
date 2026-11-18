from collections.abc import Callable
from email.message import Message

from fastapi import HTTPException, Request
from starlette.requests import ClientDisconnect


async def read_limited_body(
    request: Request,
    max_bytes: int,
    error: Callable[[int, str], HTTPException],
) -> bytearray:
    """Le o corpo em partes e deixa o router montar os erros publicos."""
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1 or any(
        not length.isascii() or not length.isdecimal() for length in lengths
    ):
        raise error(400, "INVALID_CONTENT_LENGTH")
    # Limita o numero de digitos antes de converter o cabecalho em inteiro.
    if lengths and (len(lengths[0]) > 10 or int(lengths[0]) > max_bytes):
        raise error(413, "PAYLOAD_TOO_LARGE")

    # Content-Length pode faltar. O limite tambem vale para os bytes recebidos.
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > max_bytes:
                raise error(413, "PAYLOAD_TOO_LARGE")
            body.extend(chunk)
    except ClientDisconnect as disconnect:
        raise error(400, "INCOMPLETE_BODY") from disconnect

    if not body:
        raise error(400, "EMPTY_BODY")
    return body


def is_utf8_media_type(header: str, media_type: str) -> bool:
    # O parser trata parametros entre aspas, como charset="UTF-8".
    content_type = Message()
    content_type["Content-Type"] = header
    parameters = content_type.get_params() or []
    if not parameters or parameters[0][0].lower() != media_type:
        return False
    if len(parameters) == 1:
        return True
    if len(parameters) != 2:
        return False
    name, value = parameters[1]
    return (
        name.lower() == "charset"
        and isinstance(value, str)
        and value.lower() == "utf-8"
    )


def validate_json_headers(
    request: Request,
    error: Callable[[int, str], HTTPException],
) -> None:
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1 or not is_utf8_media_type(
        content_types[0], "application/json"
    ):
        raise error(415, "UNSUPPORTED_MEDIA_TYPE")

    encodings = request.headers.getlist("content-encoding")
    if len(encodings) > 1 or (encodings and encodings[0].lower() != "identity"):
        raise error(415, "UNSUPPORTED_CONTENT_ENCODING")


def decode_utf8(
    body: bytearray,
    error: Callable[[int, str], HTTPException],
) -> str:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as invalid_utf8:
        raise error(400, "INVALID_UTF8") from invalid_utf8
