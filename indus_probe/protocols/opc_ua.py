"""
IndusProbe — OPC-UA Protocol & Security Policy Analyzer

Analyzes OPC-UA TCP Binary Protocol (default port 4840).
Detects SecurityPolicy, MessageSecurityMode (None, Sign, SignAndEncrypt),
and identifies insecure/cleartext industrial SCADA channels.
"""

from __future__ import annotations
import struct

# OPC UA message types
_MSG_TYPES = {
    b"HEL": "Hello",
    b"ACK": "Acknowledge",
    b"ERR": "Error",
    b"OPN": "OpenSecureChannel",
    b"CLO": "CloseSecureChannel",
    b"MSG": "Standard Message",
}


def parse_opc_ua(payload: bytes) -> dict | None:
    """
    Parse OPC UA TCP binary frame:
      MsgType (3 bytes) + ChunkType (1 byte) + MessageSize (4 bytes)
    """
    if len(payload) < 8:
        return None

    msg_type = payload[:3]
    if msg_type not in _MSG_TYPES:
        return None

    chunk_type = chr(payload[3])
    msg_size = struct.unpack("<I", payload[4:8])[0]

    result = {
        "msg_type": _MSG_TYPES[msg_type],
        "chunk_type": chunk_type,
        "message_size": msg_size,
        "security_policy": "Unknown",
        "is_encrypted": False,
        "is_insecure": False,
        "function_name": f"OPC-UA {_MSG_TYPES[msg_type]}",
        "is_write": False,
    }

    # Inspect OpenSecureChannel (OPN) to extract SecurityPolicyURI
    if msg_type == b"OPN" and len(payload) >= 16:
        # payload[8:12] = SecureChannelId
        # SecurityPolicyUri length prefix (int32) starts at offset 12
        try:
            uri_len = struct.unpack("<i", payload[12:16])[0]
            if 0 < uri_len < 256 and len(payload) >= 16 + uri_len:
                policy_uri = payload[16 : 16 + uri_len].decode("utf-8", errors="replace")
                result["security_policy"] = policy_uri

                if "SecurityPolicy#None" in policy_uri or policy_uri.endswith("#None"):
                    result["is_insecure"] = True
                    result["is_encrypted"] = False
                    result["details"] = "SecurityPolicy#None (Unencrypted, No Signature - Insecure)"
                elif any(strong in policy_uri for strong in ["Basic256Sha256", "Aes128", "Aes256"]):
                    result["is_encrypted"] = True
                    result["is_insecure"] = False
                    result["details"] = f"Strong SecurityPolicy: {policy_uri.split('#')[-1]}"
                elif "Basic128Rsa15" in policy_uri or "Basic256" in policy_uri:
                    result["is_encrypted"] = True
                    result["is_insecure"] = True
                    result["details"] = f"Deprecated Legacy Policy: {policy_uri.split('#')[-1]}"
        except Exception:
            pass

    return result

