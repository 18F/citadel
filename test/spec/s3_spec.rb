#
# Copyright 2016, Noah Kantrowitz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'spec_helper'

describe Citadel::S3 do
  let(:fake_http) { double('Chef::HTTP') }
  let(:fake_response) { double('Net::HTTPResponse') }
  let(:s3_hostname) { 's3.amazonaws.com' }
  let(:empty_sha256) { 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
  before do
    # Stub out the HTTP object.
    expect(Chef::HTTP).to receive(:new).with("https://#{s3_hostname}").and_return(fake_http)
    # Freeze time so our signing is predictable.
    allow(Time).to receive(:now).and_return(Time.at(0))
  end

  context 'with mybucket/mysecret' do
    subject { described_class.get(bucket: 'mybucket', path: 'mysecret', access_key_id: 'AKIAJMKSMHNNCQX4ILAH', secret_access_key: '0ljyHQrk1AGsc2bgx/8fbNghZNYSdckHADR4vNcL') }
    before do
      expect(fake_http).to receive(:get).with('mybucket/mysecret',
        'host' => 's3.amazonaws.com',
        'x-amz-content-sha256' => empty_sha256,
        'x-amz-date' => '19700101T000000Z',
        'x-amz-expires' => '900',
        'authorization' => 'AWS4-HMAC-SHA256 Credential=AKIAJMKSMHNNCQX4ILAH/19700101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-expires, Signature=fcfb9ddef446db9d31c9f08a4beb05116930b9861947cb49e0c8e8f46f176938'
      ).and_return(fake_response)
    end

    it { is_expected.to be fake_response }
  end # /context with mybucket/mysecret

  context 'with token' do
    subject { described_class.get(bucket: 'mybucket', path: 'mysecret', access_key_id: 'AKIAJMKSMHNNCQX4ILAH', secret_access_key: '0ljyHQrk1AGsc2bgx/8fbNghZNYSdckHADR4vNcL', token: 'EIZvol3NYAGhIYo3mxmF8Bw3GjRFQq6xmjrlXNQs') }
    before do
      expect(fake_http).to receive(:get).with('mybucket/mysecret',
        'host' => 's3.amazonaws.com',
        'x-amz-content-sha256' => empty_sha256,
        'x-amz-date' => '19700101T000000Z',
        'x-amz-expires' => '900',
        'x-amz-security-token' => 'EIZvol3NYAGhIYo3mxmF8Bw3GjRFQq6xmjrlXNQs',
        'authorization' => 'AWS4-HMAC-SHA256 Credential=AKIAJMKSMHNNCQX4ILAH/19700101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-expires;x-amz-security-token, Signature=e5ea717df9b8c93e15b30c86900c016a0d81b46c4b007644ffc80795ff8da15f'
      ).and_return(fake_response)
    end

    it { is_expected.to be fake_response }
  end # /context with token

  context 'with a region' do
    let(:s3_hostname) { 's3-us-west-2.amazonaws.com' }
    subject { described_class.get(bucket: 'mybucket', path: 'mysecret', access_key_id: 'AKIAJMKSMHNNCQX4ILAH', secret_access_key: '0ljyHQrk1AGsc2bgx/8fbNghZNYSdckHADR4vNcL', region: 'us-west-2') }
    before do
      expect(fake_http).to receive(:get).with('mybucket/mysecret',
        'host' => 's3-us-west-2.amazonaws.com',
        'x-amz-content-sha256' => empty_sha256,
        'x-amz-date' => '19700101T000000Z',
        'x-amz-expires' => '900',
        'authorization' => 'AWS4-HMAC-SHA256 Credential=AKIAJMKSMHNNCQX4ILAH/19700101/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-expires, Signature=be57f3bb860d84dae7e8637a75741efdad9796c281c5d3d34ec2c8a5d76663d5'
      ).and_return(fake_response)
    end

    it { is_expected.to be fake_response }
  end # /context with a region

  context 'with an exception' do
    subject { described_class.get(bucket: 'mybucket', path: 'mysecret', access_key_id: 'AKIAJMKSMHNNCQX4ILAH', secret_access_key: '0ljyHQrk1AGsc2bgx/8fbNghZNYSdckHADR4vNcL') }
    before do
      expect(fake_http).to receive(:get).with('mybucket/mysecret',
        'host' => 's3.amazonaws.com',
        'x-amz-content-sha256' => empty_sha256,
        'x-amz-date' => '19700101T000000Z',
        'x-amz-expires' => '900',
        'authorization' => 'AWS4-HMAC-SHA256 Credential=AKIAJMKSMHNNCQX4ILAH/19700101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-expires, Signature=fcfb9ddef446db9d31c9f08a4beb05116930b9861947cb49e0c8e8f46f176938'
      ).and_raise(Net::HTTPServerException.new(nil, nil))
    end

    it { expect { subject }.to raise_error {|error|
      expect(error).to be_a(Citadel::CitadelError)
      expect(error.wrapped_exception).to be_a(Net::HTTPServerException)
    } }
  end # /context with an exception
end




