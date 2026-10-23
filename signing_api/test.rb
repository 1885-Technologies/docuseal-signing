# frozen_string_literal: true

require_relative 'app'
require 'tmpdir'

def assert(condition, message)
  raise message unless condition
end

key = OpenSSL::PKey::RSA.new(2048)
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 1
cert.subject = OpenSSL::X509::Name.parse('/CN=Test Automated Service')
cert.issuer = cert.subject
cert.public_key = key.public_key
cert.not_before = Time.now.utc - 60
cert.not_after = Time.now.utc + 3600
cert.sign(key, OpenSSL::Digest.new('SHA256'))
tenant, user, doc, operation = Array.new(4) { SecureRandom.uuid }
identity = { 'tenant_id' => tenant, 'name' => 'Test Leitung', 'email' => 'test@example.invalid',
             'authority_ref' => 'Automated test only' }
pdf = HexaPDF::Document.new
pdf.pages.add.canvas.font('Helvetica', size: 12).text('Dunning document TEST ONLY', at: [50, 700])
io = StringIO.new
pdf.write(io)
input = { 'pdf' => Base64.strict_encode64(io.string), 'original_sha256' => Digest::SHA256.hexdigest(io.string),
          'tenant_id' => tenant, 'document_id' => doc, 'signer_id' => user,
          'signer_name' => identity['name'], 'signer_email' => identity['email'],
          'assignment_sha256' => 'a' * 64, 'authority_ref' => identity['authority_ref'] }

def request(app, method, id, body = nil, auth = "Bearer #{'x' * 40}")
  app.call({ 'PATH_INFO' => "/operations/#{id}", 'REQUEST_METHOD' => method,
             'HTTP_AUTHORIZATION' => auth, 'rack.input' => StringIO.new(body ? JSON.generate(body) : '') })
end

# One end-to-end lifecycle deliberately shares one temporary durable store.
# rubocop:disable Metrics/BlockLength
Dir.mktmpdir do |dir|
  args = { directory: dir, token: 'x' * 40, key: key.to_pem, certificate: cert.to_pem,
           identities: { user => identity } }
  api = SigningApi.new(**args)
  assert(request(api, 'POST', operation, input, '')[0] == 401, 'Missing authentication accepted')
  assert(request(api, 'GET', '../escape')[0] == 404, 'Traversal accepted')
  assert(request(api, 'POST', operation, input.merge('signer_name' => 'Other'))[0] == 422, 'Wrong signer accepted')
  assert(request(api, 'POST', operation, input.merge('tenant_id' => SecureRandom.uuid))[0] == 422,
         'Wrong tenant accepted')
  assert(request(api, 'POST', operation, input.merge('original_sha256' => 'b' * 64))[0] == 422, 'Wrong digest accepted')
  status, _, body = request(api, 'POST', operation, input)
  assert(status == 200, "Signing failed #{status}: #{body}")
  data = JSON.parse(body.join)
  signed = Base64.strict_decode64(data['signed_pdf'])
  audit = Base64.strict_decode64(data['audit_pdf'])
  assert(api.verify!(signed), 'Signature verification failed')
  assert(api.verify!(audit), 'Audit signature verification failed')
  assert(HexaPDF::Document.new(io: StringIO.new(signed)).pages.one?, 'Extra page added')
  assert(data['signed_sha256'] == Digest::SHA256.hexdigest(signed), 'Signed hash mismatch')
  assert(data['certificate_sha256'] == Digest::SHA256.hexdigest(cert.to_der), 'Certificate mismatch')
  # Restart and retry: output MUST be byte-identical, not a new timestamp/signature.
  api = SigningApi.new(**args)
  assert(request(api, 'POST', operation, input)[2] == body, 'Duplicate signing after restart')
  assert(request(api, 'GET', operation)[2] == body, 'GET does not reconcile operation')
  assert(request(api, 'POST', operation, input.merge('document_id' => SecureRandom.uuid))[0] == 409,
         'Changed request reused operation')
  corrupted = signed.dup
  # Tampering outside the CMS contents must invalidate the cryptographic signature.
  position = corrupted.index('/ByteRange')
  corrupted[position - 10] = corrupted[position - 10] == '0' ? '1' : '0'
  rejected = false
  begin
    api.verify!(corrupted)
  rescue StandardError
    rejected = true
  end
  assert(rejected, 'Tampered PDF accepted')
  assert(
    request(api, 'POST', SecureRandom.uuid,
            input.merge('pdf' => Base64.strict_encode64(signed), 'original_sha256' => Digest::SHA256.hexdigest(signed)))[0] == 422, 'Already signed PDF accepted'
  )
  File.binwrite('/tmp/signed-test.pdf', signed)
  File.binwrite('/tmp/audit-test.pdf', audit)
  File.binwrite('/tmp/original-test.pdf', io.string)
  File.binwrite('/tmp/test-certificate.pem', cert.to_pem)
end
puts 'PASS: authentication, isolation, cryptography, audit, restart idempotency and tamper detection'

# rubocop:enable Metrics/BlockLength
