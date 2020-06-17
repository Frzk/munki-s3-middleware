#!/usr/bin/env python
#coding: utf8

"""
Generates a pre-signed URL, allowing anyone to download the file from an S3 bucket.

This module is meant to plug into munki.
https://github.com/munki/munki/wiki

For explanations and a (useful) test case, see:
See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html

Some code shamelessly copied from https://github.com/waderobson/s3-auth -- Thanks.
"""

import datetime
import hashlib
import hmac

# backwards compatibility for python2
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
    from urllib.parse import quote

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
        self.url = url

        self.access_key = self.pref('S3AccessKey')
        self.secret_key = self.pref('S3SecretKey')
        self.region = self.pref('S3Region')

        self.host = self.host_from_url(self.url)
        self.resource = self.uri_from_url(self.url)

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
        encoded_cred = quote(cred, safe="")

        std_qs = ("X-Amz-Algorithm={}"
                  "&X-Amz-Credential={}"
                  "&X-Amz-Date={}"
                  "&X-Amz-Expires={}"
                  "&X-Amz-SignedHeaders={}").format(self.ALGORITHM,
                                                    encoded_cred,
                                                    timestamp,
                                                    str(expires),
                                                    self.SIGNED_HEADERS)

        # Build Request
        std_request = "GET\n{}\n{}\n{}\n{}\n{}".format(self.resource,
                                                       std_qs,
                                                       std_headers,
                                                       self.SIGNED_HEADERS,
                                                       self.PAYLOAD_HASH)

        # Build String-to-Sign
        sts = "{}\n{}\n{}\n{}".format(self.ALGORITHM,
                                      timestamp,
                                      cred_scope,
                                      self.compute_hash(std_request))

        # Build Signature
        signature_key = self.get_signature_key(self.secret_key,
                                               datestamp,
                                               self.region,
                                               self.SERVICE)

        signature = hmac.new(signature_key,
                             (sts).encode('utf-8'),
                             hashlib.sha256).hexdigest()

        # Build the final URL
        request_url = "{}?{}&X-Amz-Signature={}".format(self.url,
                                                        std_qs,
                                                        signature)

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

    @staticmethod
    def uri_from_url(url):
        """
        """
        parse = urlparse(url)

        return parse.path

    @staticmethod
    def host_from_url(url):
        """
        """
        parse = urlparse(url)

        return parse.hostname


def process_request_options(options):
    """
    This is the entrypoint for Munki.
    """
    # print("\n*** Requesting: {}".format(options.get('url')))
    updated_url = str(PreSignedUrlBuilder(options['url']))

    options['url'] = updated_url

    return options
