IKEV2_ENCR = {
    3: "3DES",
    12: "AES-CBC",
    18: "AES-GCM-16",
    19: "AES-GCM-12",
    20: "AES-GCM-8",
}

IKEV2_PRF = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    5: "HMAC-SHA2-256",
    6: "HMAC-SHA2-384",
    7: "HMAC-SHA2-512",
}

IKEV2_INTEG = {
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    12: "SHA2-256-128",
    13: "SHA2-384-192",
    14: "SHA2-512-256",
}

IKEV2_DH = {
    2: "MODP-1024",
    14: "MODP-2048",
    19: "ECP-256",
    20: "ECP-384",
}

IKEV1_ENCR = {
    1: "DES",
    3: "3DES",
    7: "AES-CBC",
}

IKEV1_HASH = {
    1: "MD5",
    2: "SHA1",
    4: "SHA2-256",
}

RFC_CITATIONS = {
    "ikev2": "RFC 7296",
    "ikev1": "RFC 2409",
    "nist": "NIST SP 800-77 Rev. 1",
}
