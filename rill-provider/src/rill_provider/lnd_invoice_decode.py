"""Decode a client's BOLT11 invoice with the provider's own LND (RS-008).

LND verifies the invoice signature and refuses invoices for another network;
this adapter maps the result onto the RS-001 ``InvoiceBinding`` and refuses
invoices that rill-core's reader would read differently. Decoding is
read-only (``DecodePayReq`` needs only ``offchain:read``) and grants nothing:
unsupported routing features are rejected before returning a fundable binding,
and the caller still applies amount, expiry, and CLTV policy.
"""

from __future__ import annotations

import hashlib
import logging
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

import grpc
from rill_core.errors import ValidationError
from rill_core.networks import backend_names, invoice_matches_network
from rill_core.wire.bolt11 import require_wire_agreement
from rill_core.wire.messages import InvoiceBinding

from rill_provider._lnd_proto import lightning_pb2
from rill_provider.diagnostics import diagnostic
from rill_provider.lnd_payment_observation import (
    DEFAULT_DEADLINE_SECONDS,
    MAX_CERT_BYTES,
    MAX_MACAROON_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_PORT,
    LndAuthError,
    LndObservationError,
    LndProtocolError,
    LndUnavailableError,
    _read_file,
)

if TYPE_CHECKING:
    import os

    from rill_core.wire.types import NetworkIdentity

DECODE_METHOD = "/lnrpc.Lightning/DecodePayReq"
MAX_INVOICE_CHARS = 2048
HASH_HEX = 64
PAYMENT_SECRET_BYTES = 32
REJECTED = (grpc.StatusCode.UNKNOWN, grpc.StatusCode.INVALID_ARGUMENT)  # LND decode errors
# Classic, single-path payment-secret invoices. Optional route-blinding support
# is advertised by ordinary LND invoices too; actual blinded paths are refused.
PAYMENT_FEATURES = frozenset({8, 9, 14, 15, 17, 25})
TRANSIENT = (
    grpc.StatusCode.UNAVAILABLE,
    grpc.StatusCode.DEADLINE_EXCEEDED,
    grpc.StatusCode.RESOURCE_EXHAUSTED,
    grpc.StatusCode.CANCELLED,
)


class InvoiceRejectedError(LndObservationError):
    """LND refused to decode the invoice (malformed, bad signature, other network)."""


def binding_from_payreq(
    bolt11: str, payreq: lightning_pb2.PayReq, *, expected: InvoiceBinding | None = None
) -> InvoiceBinding:
    """Map a decoded ``PayReq`` onto an ``InvoiceBinding`` or refuse it.

    LND verified the signature, but readers disagree on repeated or malformed
    fields (LND keeps the first; older LND even a second payment hash), so the
    exact bytes must also read the same under rill-core's rules, which the
    browser and offline CLI use. A differing ``expected`` binding is LND's
    fault, not the invoice's, and is checked first.
    """
    binding = _mapped_binding(bolt11, payreq)
    if expected is not None and binding != expected:
        raise LndProtocolError("decoded invoice differs from signed binding")
    try:
        require_wire_agreement(
            bolt11,
            payment_hash=payreq.payment_hash,
            payment_secret=payreq.payment_addr.hex(),
            amount_msat=payreq.num_msat,
            payee=payreq.destination,
            timestamp=payreq.timestamp,
            expiry_seconds=payreq.expiry,
            min_final_cltv_delta=payreq.cltv_expiry,
            features=frozenset(payreq.features),
            blinded_paths=bool(payreq.blinded_paths),
        )
    except ValidationError:
        # Callers act on this module's rejection class (FAILED, "rejected"),
        # never on rill-core's, which would read as an outage and be retried.
        raise InvoiceRejectedError("invoice fields are ambiguous to BOLT11 readers") from None
    diagnostic(
        logging.getLogger(__name__),
        "invoice.decoded",
        "Invoice verified by LND",
        payment_hash=binding.payment_hash,
        invoice_hash=binding.bolt11_sha256,
        amount_msat=binding.amount_msat,
        memo=payreq.description,
    )
    return binding


def _mapped_binding(bolt11: str, payreq: lightning_pb2.PayReq) -> InvoiceBinding:
    if not isinstance(payreq, lightning_pb2.PayReq):
        raise LndProtocolError("LND decode returned an unexpected message")
    features = set(payreq.features)
    if not (
        features <= PAYMENT_FEATURES
        and len(features & {8, 9}) == 1
        and len(features & {14, 15}) == 1
        and len(payreq.payment_addr) == PAYMENT_SECRET_BYTES
        and not payreq.blinded_paths
    ):
        raise InvoiceRejectedError("invoice routing features unsupported")
    if payreq.num_msat <= 0 or payreq.num_msat % 1000 or payreq.expiry <= 0:
        raise InvoiceRejectedError("invoice must fix a whole-satoshi amount and an expiry")
    if len(payreq.payment_hash) != HASH_HEX or payreq.cltv_expiry <= 0:
        raise InvoiceRejectedError("invoice payment hash or final CLTV unsupported")
    try:
        return InvoiceBinding.model_validate(
            {
                "bolt11_sha256": hashlib.sha256(bolt11.encode("ascii")).hexdigest(),
                "payment_hash": payreq.payment_hash,
                "amount_msat": str(payreq.num_msat),
                "payee_compressed_pubkey": payreq.destination,
                "created_at": payreq.timestamp,
                "expires_at": payreq.timestamp + payreq.expiry,
                "min_final_cltv_delta": payreq.cltv_expiry,
            },
            strict=True,
        )
    except ValueError:
        raise InvoiceRejectedError("decoded invoice is not a valid binding") from None


class LndInvoiceDecoder:
    """Loopback ``DecodePayReq`` for one network with a dedicated read macaroon."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        tls_certificate_path: str | os.PathLike[str],
        macaroon_path: str | os.PathLike[str],
        network: NetworkIdentity,
    ) -> None:
        """Configure only; no credential read or network dial."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("LND endpoint must be a numeric loopback host and port")
        try:
            backend_names(network)  # refuses unsupported identities
        except ValidationError:
            raise ValueError("LND invoice decoding requires a supported network identity") from None
        self._network = network
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._certificate = Path(tls_certificate_path)
        self._macaroon = Path(macaroon_path)

    def decode(
        self, bolt11: str, *, deadline_seconds: float = DEFAULT_DEADLINE_SECONDS
    ) -> InvoiceBinding:
        """Return the verified binding, or raise ``InvoiceRejectedError``/unavailable."""
        if type(bolt11) is not str or not 0 < len(bolt11) <= MAX_INVOICE_CHARS:
            raise InvoiceRejectedError("invoice string unsupported")
        # The backend decodes for its own chain; bind the invoice to ours too.
        if not invoice_matches_network(bolt11, self._network):
            raise InvoiceRejectedError("invoice is not for the configured network")
        certificate = _read_file(self._certificate, MAX_CERT_BYTES, private=False)
        macaroon = _read_file(self._macaroon, MAX_MACAROON_BYTES, private=True)
        channel: grpc.Channel | None = None
        failure: LndObservationError | None = None
        try:
            channel = grpc.secure_channel(
                self._target,
                grpc.ssl_channel_credentials(root_certificates=certificate),
                options=(
                    ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
                    ("grpc.max_send_message_length", 4096),
                    ("grpc.enable_retries", 0),
                ),
            )
            rpc = channel.unary_unary(
                DECODE_METHOD,
                request_serializer=lightning_pb2.PayReqString.SerializeToString,
                response_deserializer=lightning_pb2.PayReq.FromString,
            )
            payreq = rpc(
                lightning_pb2.PayReqString(pay_req=bolt11),
                timeout=deadline_seconds,
                metadata=(("macaroon", macaroon.hex()),),
                wait_for_ready=False,
            )
            return binding_from_payreq(bolt11, payreq)
        except grpc.RpcError as error:
            try:
                code = error.code()
            except Exception:  # noqa: BLE001 - upstream error may be malformed
                code = grpc.StatusCode.UNAVAILABLE
            if code in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED):
                failure = LndAuthError("LND rejected invoice decoding credentials")
            elif code in REJECTED:
                failure = InvoiceRejectedError("LND refused to decode the invoice")
            elif code in TRANSIENT:
                failure = LndUnavailableError("LND invoice decoding unavailable")
            else:
                failure = LndProtocolError("LND invoice decoding failed unexpectedly")
        except LndObservationError:
            raise
        except Exception:  # noqa: BLE001 - never retain invoice or credential-bearing errors
            failure = LndUnavailableError("LND invoice decoding unavailable")
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()
        raise failure if failure is not None else LndUnavailableError("LND decoding failed")
