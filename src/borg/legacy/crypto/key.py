from ...constants import *  # NOQA
from ...crypto.low_level import AES256_CTR_HMAC_SHA256, AES256_CTR_BLAKE2b
from ...crypto.key import ID_HMAC_SHA_256, ID_BLAKE2b_256, AESKeyBase, FlexiKey


class KeyfileKey(ID_HMAC_SHA_256, AESKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.KEYFILE, KeyType.REPO, KeyType.PASSPHRASE}
    TYPE = KeyType.KEYFILE
    NAME = "key file"
    ARG_NAME = "keyfile"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = AES256_CTR_HMAC_SHA256


class RepoKey(ID_HMAC_SHA_256, AESKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.KEYFILE, KeyType.REPO, KeyType.PASSPHRASE}
    TYPE = KeyType.REPO
    NAME = "repokey"
    ARG_NAME = "repokey"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = AES256_CTR_HMAC_SHA256


class Blake2KeyfileKey(ID_BLAKE2b_256, AESKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2KEYFILE, KeyType.BLAKE2REPO}
    TYPE = KeyType.BLAKE2KEYFILE
    NAME = "key file BLAKE2b"
    ARG_NAME = "keyfile-blake2"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = AES256_CTR_BLAKE2b


class Blake2RepoKey(ID_BLAKE2b_256, AESKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2KEYFILE, KeyType.BLAKE2REPO}
    TYPE = KeyType.BLAKE2REPO
    NAME = "repokey BLAKE2b"
    ARG_NAME = "repokey-blake2"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = AES256_CTR_BLAKE2b


LEGACY_KEY_TYPES = (KeyfileKey, RepoKey, Blake2KeyfileKey, Blake2RepoKey)
