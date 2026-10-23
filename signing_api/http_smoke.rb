# frozen_string_literal: true

require_relative 'app'
require 'tmpdir'
require 'net/http'

# Real entrypoint: verifies privilege drop and prevents accidental Rails/Puma config loading.
key = OpenSSL::PKey::RSA.new(2048)
cert = OpenSSL::X509::Certificate.new
cert.subject = OpenSSL::X509::Name.parse('/CN=Test Service')
cert.issuer = cert.subject
cert.public_key = key.public_key
cert.not_before = Time.now.utc - 60
cert.not_after = Time.now.utc + 600
cert.sign(key, OpenSSL::Digest.new('SHA256'))

Dir.mktmpdir do |dir|
  env = { 'SIGNING_DATA_DIR' => dir, 'SIGNING_KEY_PEM' => key.to_pem,
          'SIGNING_CERT_PEM' => cert.to_pem, 'SIGNING_API_TOKEN' => 'x' * 40,
          'SIGNING_IDENTITIES_JSON' => '{}' }
  pid = Process.spawn(env, '/bin/sh', '/app/signing_api/start.sh', pgroup: true,
                      out: '/tmp/http-smoke.log', err: '/tmp/http-smoke.log')
  begin
    ready = false
    30.times do
      begin
        response = Net::HTTP.get_response(URI('http://127.0.0.1:3000/healthz'))
        ready = response.code == '200'
        break if ready
      rescue Errno::ECONNREFUSED
        sleep 0.5
      end
    end
    raise "Server failed to start: #{File.read('/tmp/http-smoke.log')}" unless ready

    url = URI("http://127.0.0.1:3000/operations/#{SecureRandom.uuid}")
    raise 'Unauthenticated operation accepted' unless Net::HTTP.get_response(url).code == '401'

    puts 'PASS: production entrypoint, real HTTP health and authorization'
  ensure
    Process.kill('TERM', -pid)
    Process.wait(pid)
  end
end
