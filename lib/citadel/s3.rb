#
# Copyright 2012-2016, Brandon Adams and other contributors.
# Copyright 2013-2016, Balanced, Inc.
# Copyright 2016, Noah Kantrowitz
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'time'
require 'openssl'
require 'base64'

require 'chef/http'

require 'citadel/error'


class Citadel
  # Simple read-only S3 client.
  #
  # @since 1.0.0
  # @api private
  module S3
    extend self

    # Get an object from S3.
    #
    # @param bucket [String] Name of the bucket to use.
    # @param path [String] Path to the object.
    # @param access_key_id [String] AWS access key ID.
    # @param secret_access_key [String] AWS secret access key.
    # @param token [String, nil] AWS IAM token.
    # @param region [String] S3 bucket region.
    # @return [Net::HTTPResponse]
    def get(bucket:, path:, access_key_id:, secret_access_key:, token: nil, region: nil)
      region ||= 'us-east-1' # Most buckets.
      path = path[1..-1] if path[0] == '/'

      verb = 'GET'
      uri_path = "/#{bucket}/#{path}"
      body = ''

      datetime = Time.now.utc.strftime('%Y%m%dT%H%M%SZ')
      date = datetime[0,8]

      c_scope = _credential_scope(date, region)
      credential = "#{access_key_id}/#{c_scope}"

      algorithm = 'AWS4-HMAC-SHA256'

      if region == 'us-east-1'
        hostname = 's3.amazonaws.com'
      else
        hostname = "s3-#{region}.amazonaws.com"
      end

      headers = {
        'host' => hostname,
        'x-amz-content-sha256' => hexdigest(body),
        'x-amz-date' => datetime,
        'x-amz-expires' => '900', # 15 minutes
      }
      headers['x-amz-security-token'] = token if token

      canonical_request = _canonical_request(verb: verb, path: uri_path,
                                             querystring: '', headers: headers,
                                             content_hash: hexdigest(body))
      signed_headers = headers.keys.sort.join(';')

      to_sign = _string_to_sign(datetime, c_scope, canonical_request)
      signed = _signature(secret_access_key, date, region, 's3', to_sign)

      headers['authorization'] = "#{algorithm} Credential=#{credential}, SignedHeaders=#{signed_headers}, Signature=#{signed}"

      # Debug information useful if the signature is wrong
      Chef::Log.debug { "CanonicalRequest: " + canonical_request.inspect }
      Chef::Log.debug { "StringToSign: " + to_sign.inspect }
      Chef::Log.debug { "headers: " + headers.inspect }

      client = Chef::HTTP.new("https://#{hostname}")
      begin
        content = client.get(uri_path[1..-1], headers)
      rescue Net::HTTPServerException => e
        raise CitadelError.new("Unable to download #{path}: #{e}")
      end

      response = client.last_response

      case response
      when Net::HTTPOK
        return content
      when Net::HTTPRedirection
        # When you request a bucket at the wrong region endpoint, S3 returns an
        # HTTP 301, but it doesn't set a Location header, so chef doesn't
        # follow it and returns a nil response.
        true_region = response.header['x-amz-bucket-region']
        raise CitadelError.new(
          "Bucket #{bucket} is actually in #{true_region}, not #{region}")
      else
        Chef::Log.warn("Unexpected HTTP response: #{response.inspect}")
        Chef::Log.warn("Response body: #{response.body.inspect}")
        raise CitadelError.new("Unexpected HTTP response: #{response.inspect}")
      end
    end

    def _canonical_request(verb:, path:, querystring:, headers:, content_hash:)
      # This isn't a super robust way to calculate the canonical request, since
      # we don't really deal properly with URIs that need escaping or quoted
      # header values.
      [
        verb,
        path,
        querystring,
        headers.sort_by(&:first).map {|k, v| "#{k}:#{v}" }.join("\n") + "\n", # sign all headers
        headers.keys.sort.join(';'),
        content_hash,
      ].join("\n")
    end

    def _string_to_sign(datetime_string, credential_scope, canonical_request)
      [
        'AWS4-HMAC-SHA256',
        datetime_string,
        credential_scope,
        hexdigest(canonical_request),
      ].join("\n")
    end

    def _credential_scope(date_string, region, service='s3')
      [date_string, region, 's3', 'aws4_request'].join('/')
    end

    def _signature(secret_access_key, date, region, service, string_to_sign)
      k_date = hmac('AWS4' + secret_access_key, date)
      k_region = hmac(k_date, region)
      k_service = hmac(k_region, service)
      k_credentials = hmac(k_service, 'aws4_request')
      hmac_hex(k_credentials, string_to_sign)
    end

    def hexdigest(data)
      OpenSSL::Digest::SHA256.hexdigest(data)
    end

    def hmac(key, value)
      OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, value)
    end

    def hmac_hex(key, value)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), key, value)
    end
  end
end
