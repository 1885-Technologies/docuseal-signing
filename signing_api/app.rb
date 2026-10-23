# frozen_string_literal: true

# AGPL-3.0, including DocuSeal's additional attribution terms.
# A narrow service API using the public DocuSeal PDF signing implementation.
# It does not expose or reimplement the proprietary Pro submission endpoints.
require 'bundler/setup'
require 'active_support/all'
require 'i18n/backend/transliterator'
require 'hexapdf'
require 'openssl'
require 'json'
require 'base64'
require 'digest'
require 'fileutils'
require 'securerandom'
require 'stringio'
require_relative '../lib/text_utils'
require_relative '../lib/submissions/generate_result_attachments'
require_relative '../lib/verify_pdf_signature'
require_relative '../config/initializers/hexapdf'

class SigningApi
  SOURCE = 'https://github.com/1885-Technologies/docuseal-signing'
  MAX_BODY = 36_000_000
  UUID = /\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/

  def initialize(directory: ENV.fetch('SIGNING_DATA_DIR', '/data/docuseal/signing'),
                 token: ENV.fetch('SIGNING_API_TOKEN'),
                 key: ENV.fetch('SIGNING_KEY_PEM'), certificate: ENV.fetch('SIGNING_CERT_PEM'),
                 identities: JSON.parse(ENV.fetch('SIGNING_IDENTITIES_JSON')))
    raise 'API token must contain at least 32 bytes' if token.bytesize < 32

    @directory = directory
    @token = token
    @key = OpenSSL::PKey.read(key)
    @certificate = OpenSSL::X509::Certificate.new(certificate)
    raise 'Key and certificate do not match' unless @certificate.check_private_key(@key)

    @identities = identities
    FileUtils.mkdir_p(directory, mode: 0o700)
    @fingerprint = Digest::SHA256.hexdigest(@certificate.to_der)
  end

  def call(env)
    if env['PATH_INFO'] == '/healthz'
      return response(200,
                      { service: 'DocuSeal automated signing API', source: SOURCE })
    end
    if env['PATH_INFO'] == '/source'
      return response(200,
                      { attribution: 'Powered by DocuSeal', license: 'AGPL-3.0',
                        source: SOURCE })
    end

    return response(401, { error: 'Unauthorized' }) unless authorized?(env)

    match = %r{\A/operations/([^/]+)\z}.match(env['PATH_INFO'])
    return response(404, { error: 'Not found' }) unless match && UUID.match?(match[1])

    id = match[1]
    if env['REQUEST_METHOD'] == 'GET'
      path = File.join(@directory, "#{id}.json")
      return response(404, { error: 'Not found' }) unless File.file?(path)

      return [200, headers, [File.binread(path)]]
    end
    return response(405, { error: 'Method not allowed' }) unless env['REQUEST_METHOD'] == 'POST'
    return response(413, { error: 'Payload too large' }) if env['CONTENT_LENGTH'].to_i > MAX_BODY

    raw = env['rack.input'].read(MAX_BODY + 1)
    return response(413, { error: 'Payload too large' }) if raw.bytesize > MAX_BODY

    process(id, raw)
  rescue JSON::ParserError, ArgumentError, KeyError, HexaPDF::Error
    response(422, { error: 'Invalid signing request or PDF' })
  rescue StandardError => e
    warn "Signing operation failed (#{e.class})" # no documents, tokens, identities, URLs
    response(503, { error: 'Signing unavailable; reconcile the same operation ID' })
  end

  def process(id, raw)
    input = JSON.parse(raw)
    pdf = validate(input)
    execute(id, input, pdf)
  end

  def authorized?(env)
    auth = env['HTTP_AUTHORIZATION'].to_s
    expected = "Bearer #{@token}"
    auth.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(auth, expected)
  end

  def execute(id, input, pdf)
    request_hash = Digest::SHA256.hexdigest(JSON.generate(input.sort.to_h))
    File.open(File.join(@directory, "#{id}.lock"), File::RDWR | File::CREAT, 0o600) do |lock|
      unless lock.flock(File::LOCK_EX | File::LOCK_NB)
        return response(409, { error: 'Operation busy; reconcile with GET' })
      end

      path = File.join(@directory, "#{id}.json")
      return existing(path, request_hash) if File.file?(path)

      result = complete(id, input, pdf).merge('request_sha256' => request_hash)
      persist(path, result)
      response(200, result)
    end
  end

  def existing(path, request_hash)
    previous = JSON.parse(File.binread(path))
    unless previous['request_sha256'] == request_hash
      return response(409, { error: 'Operation ID already belongs to different input' })
    end

    response(200, previous)
  end

  def complete(id, input, pdf)
    evidence = input.except('pdf').merge('operation_id' => id, 'completed_at' => Time.now.utc.iso8601,
                                         'certificate_sha256' => @fingerprint,
                                         'signature_type' => 'automated_service_certificate',
                                         'attribution' => 'Powered by DocuSeal')
    reason = "Automated document service; responsible: #{input['signer_name']}; operation: #{id}"
    signed = sign(pdf, reason)
    evidence['signed_sha256'] = Digest::SHA256.hexdigest(signed)
    audit = sign(audit_pdf(evidence), "Automated signing audit; operation: #{id}")
    evidence.merge('status' => 'completed', 'signed_pdf' => Base64.strict_encode64(signed),
                   'audit_pdf' => Base64.strict_encode64(audit),
                   'audit_sha256' => Digest::SHA256.hexdigest(audit))
  end

  def persist(path, result)
    temp = "#{path}.#{SecureRandom.hex(8)}.tmp"
    begin
      File.open(temp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |f|
        f.write(JSON.generate(result))
        f.flush
        f.fsync
      end
      File.rename(temp, path)
      File.open(@directory, &:fsync)
    ensure
      FileUtils.rm_f(temp)
    end
  end

  def validate(input)
    keys = %w[pdf original_sha256 tenant_id document_id signer_id signer_name signer_email assignment_sha256
              authority_ref]
    raise ArgumentError unless input.is_a?(Hash) && input.keys.sort == keys.sort
    raise ArgumentError unless %w[tenant_id document_id signer_id].all? { |k| UUID.match?(input[k].to_s) }
    raise ArgumentError unless %w[original_sha256 assignment_sha256].all? do |k|
      /\A[0-9a-f]{64}\z/.match?(input[k].to_s)
    end

    identity = @identities.fetch(input['signer_id'])
    raise ArgumentError unless identity['tenant_id'] == input['tenant_id']
    raise ArgumentError unless identity['name'] == input['signer_name'] && identity['email'] == input['signer_email']
    raise ArgumentError unless input['authority_ref'] == identity['authority_ref']
    raise ArgumentError unless @certificate.not_before <= Time.now.utc && Time.now.utc < @certificate.not_after

    decode_pdf(input)
  end

  def decode_pdf(input)
    pdf = Base64.strict_decode64(input['pdf'])
    raise ArgumentError unless pdf.start_with?('%PDF-') && pdf.bytesize <= 25_000_000
    raise ArgumentError unless Digest::SHA256.hexdigest(pdf) == input['original_sha256']

    pdf
  end

  def sign(bytes, reason)
    pdf = HexaPDF::Document.new(io: StringIO.new(bytes))
    raise ArgumentError if pdf.pages.none? || pdf.pages.count > 100 || pdf.encrypted? || pdf.signatures.any?

    pkcs = Struct.new(:certificate, :key, :ca_certs).new(@certificate, @key, [])
    params = Submissions::GenerateResultAttachments.build_signing_params(nil, pkcs, nil)
    output = StringIO.new
    # Invisible signature widget. Content/layout and existing page count are preserved.
    pdf.sign(output, reason: reason, **params)
    signed = output.string
    verify!(signed)
    signed
  end

  def verify!(bytes)
    doc = HexaPDF::Document.new(io: StringIO.new(bytes))
    raise ArgumentError unless doc.signatures.one?

    signature = doc.signatures.first
    ranges = signature[:ByteRange]
    raise ArgumentError unless ranges[0].zero? && ranges[2] + ranges[3] == bytes.bytesize

    content = bytes.byteslice(ranges[0], ranges[1]) + bytes.byteslice(ranges[2], ranges[3])
    pkcs = OpenSSL::PKCS7.new(signature[:Contents])
    raise ArgumentError unless VerifyPdfSignature.trusted_certificate?(pkcs, [@certificate]) &&
                               VerifyPdfSignature.verify_contents(pkcs, content, [@certificate])

    true
  end

  def audit_pdf(evidence)
    # Audit is machine-readable and signed, separate from the untouched reminder pages.
    doc = HexaPDF::Document.new
    canvas = doc.pages.add.canvas
    font_path = Submissions::GenerateResultAttachments::FONT_PATH
    canvas.font(File.exist?(font_path) ? font_path : 'Helvetica', size: 10)
    lines = ['Automated document signature / DocuSeal',
             'Service certificate; no personal signing ceremony or qualified signature.',
             'Responsible person is recorded from the calling application assignment.', '']
    evidence.each { |k, v| lines << "#{k}: #{v}" }
    lines << '' << "Source: #{SOURCE}"
    lines.each_with_index { |line, i| canvas.text(line, at: [35, 800 - (20 * i)]) }
    output = StringIO.new
    doc.write(output)
    output.string
  end

  def headers
    { 'content-type' => 'application/json', 'cache-control' => 'no-store',
      'x-content-type-options' => 'nosniff', 'link' => "<#{SOURCE}>; rel=\"source\"" }
  end

  def response(status, data)
    [status, headers, [JSON.generate(data)]]
  end
end
