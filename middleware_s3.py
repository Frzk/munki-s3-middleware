#!/usr/bin/env python
# coding: utf8

"""
Generates a pre-signed URL, allowing anyone to download the file from an S3
bucket.

This module is meant to plug into munki.
https://github.com/munki/munki/wiki

For explanations and a (useful) test case, see:
https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html

Some code shamelessly copied from https://github.com/waderobson/s3-auth
Thanks !
"""

import datetime
import hashlib
import hmac

try:  # Python3
    from urllib.parse import (urlencode, urlparse, urljoin)
except ImportError:  # Python2
    from urlparse import urlparse, urljoin
    from urllib import urlencode

from Foundation import CFPreferencesCopyAppValue


__version_info__ = (0, 1)
__version__ = '.'.join(map(str, __version_info__))

__author__ = 'François KUBLER <francois@kblr.fr>'
__copyright__ = 'Copyright KBLR SAS, 2020'
__licence__ = 'MIT'


class PreSignedUrlBuilder:
    """
    """
    ALGORITHM = 'AWS4-HMAC-SHA256'
    BUNDLE_ID = 'ManagedInstalls'
    SERVICE = 's3'
    SIGNED_HEADERS = 'host'
    PAYLOAD_HASH = 'UNSIGNED-PAYLOAD'

    def __init__(self, url):
        """
        """
        self.access_key = self.pref('S3AccessKey')
        self.secret_key = self.pref('S3SecretKey')
        self.region = self.pref('S3Region')
        self.endpoint = self.pref('S3Endpoint')

        parsed_url = urlparse(self.endpoint)
        self.host = parsed_url.hostname

        parsed_url = urlparse(url)
        self.resource = parsed_url.path

        # Build self.url from the S3 endpoint and path to resource:
        self.url = urljoin(self.endpoint, self.resource)

    def __str__(self):
        """
        """
        return self.build_url()

    def build_url(self, expires=300):
        """
        """
        # Get some datetime
        time_now = datetime.datetime.utcnow()
        timestamp = time_now.strftime('%Y%m%dT%H%M%SZ')
        datestamp = time_now.strftime('%Y%m%d')

        # Build Canonical Headers
        std_headers = "host:{}\n".format(self.host)

        # Build QueryString
        cred_scope = "{}/{}/{}/aws4_request".format(datestamp,
                                                    self.region,
                                                    self.SERVICE)

        cred = "{}/{}".format(self.access_key, cred_scope)

        qs_values = [
            ('X-Amz-Algorithm', self.ALGORITHM),
            ('X-Amz-Credential', cred),
            ('X-Amz-Date', timestamp),
            ('X-Amz-Expires', expires),
            ('X-Amz-SignedHeaders', self.SIGNED_HEADERS)
        ]

        std_qs = urlencode(qs_values)

        # Build Request
        std_request_values = (
            'GET',
            self.resource,
            std_qs,
            std_headers,
            self.SIGNED_HEADERS,
            self.PAYLOAD_HASH
        )

        std_request = "\n".join(std_request_values)

        # Build String-to-Sign
        sts_values = (
            self.ALGORITHM,
            timestamp,
            cred_scope,
            self.compute_hash(std_request)
        )

        sts = "\n".join(sts_values)

        # Build Signature
        signature_key = self.get_signature_key(self.secret_key,
                                               datestamp,
                                               self.region,
                                               self.SERVICE)

        signature = hmac.new(signature_key,
                             (sts).encode('utf-8'),
                             hashlib.sha256).hexdigest()

        # Build the final URL
        qs_values.append(('X-Amz-Signature', signature))
        full_qs = urlencode(qs_values)

        request_url = "{}?{}".format(self.url, full_qs)

        return request_url

    @classmethod
    def pref(cls, pref_name):
        """
        """
        value = CFPreferencesCopyAppValue(pref_name, cls.BUNDLE_ID)

        return value

    @classmethod
    def get_signature_key(cls, key, datestamp, region, service):
        """
        """
        keyDate = cls.sign(('AWS4' + key).encode('utf-8'), datestamp)
        keyRegion = cls.sign(keyDate, region)
        keyService = cls.sign(keyRegion, service)
        keySigning = cls.sign(keyService, 'aws4_request')

        return keySigning

    @staticmethod
    def sign(key, msg):
        """
        """
        hmac_dig = hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        return hmac_dig

    @staticmethod
    def compute_hash(msg):
        """
        """
        msg_hash = hashlib.sha256(msg.encode('utf-8')).hexdigest()

        return msg_hash


def process_request_options(options):
    """
    This is the entrypoint for Munki.

    We have to ignore requests to swscan.apple.com.
    """
    url = options.get('url')

    if 'swscan.apple.com' not in url:
        # print("\n*** Requesting: {}".format(url'))
        updated_url = str(PreSignedUrlBuilder(url))
        options['url'] = updated_url

    return options

