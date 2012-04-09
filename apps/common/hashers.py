import base64
import bcrypt
import hmac
import hashlib
import logging

from django.conf import settings
from django.contrib.auth.hashers import BCryptPasswordHasher
from django.utils.encoding import smart_str

log = logging.getLogger('common.hashers')


class BcryptHMACPasswordHasher(BCryptPasswordHasher):
    algorithm = 'bcrypt'
    rounds = 12

    def encode(self, password, salt):
        if not settings.HMAC_KEYS:
            raise ImportError('settings.HMAC_KEYS must not be empty.')

        latest_key_id = max(settings.HMAC_KEYS.keys())
        shared_key = settings.HMAC_KEYS[latest_key_id]

        hmac_value = self._hmac_create(password, shared_key)
        bcrypt_value = bcrypt.hashpw(hmac_value, salt)
        return 'bcrypt{0}${1}'.format(bcrypt_value, latest_key_id)

    def verify(self, password, encoded):
        algo_and_hash, key_ver = encoded.rsplit('$', 1)
        try:
            shared_key = settings.HMAC_KEYS[key_ver]
        except KeyError:
            log.info('Invalid shared key version "{0}"'.format(key_ver))
            return False

        bc_value = algo_and_hash[6:]  # Yes, bcrypt <3s the leading $.
        hmac_value = self._hmac_create(password, shared_key)
        return bcrypt.hashpw(hmac_value, bc_value) == bc_value

    def _hmac_create(self, password, shared_key):
        """Create HMAC value based on pwd"""
        hmac_value = base64.b64encode(hmac.new(
                smart_str(shared_key),
                smart_str(password),
                hashlib.sha512).digest())
        return hmac_value


class BcryptHMACPasswordhasherNope(BcryptHMACPasswordHasher):
    """
    Force django to re-encode passwords.

    This shell password hasher forces us to re encode the password every time
    we get a valid check on a password so that incase the HMAC_KEYS have
    changed we can update the encoding. Because the algorithm is set to
    something that it can never be django will always try to "update" the
    password on a sucessful password check which allows us to ensure the right
    HMAC_KEY is being used.
    """
    algorithm = 'bcrypt-nope'
