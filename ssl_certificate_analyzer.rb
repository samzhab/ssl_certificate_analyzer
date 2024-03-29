# frozen_string_literal: true

require 'openssl'
require 'socket'
require 'yaml'
require 'json'
require 'logger'
require 'byebug'
# Module for Error handling
module ErrorHandler
  def self.handle_error(error, context = 'General')
    error_message = "#{context}: #{error.message}"
    puts error_message # Output to the screen
    $logger.error(error_message) # Log to file
  end
end

# Helper class to allow Logger to write to multiple outputs
class MultiIO
  def initialize(*targets)
    @targets = targets
  end

  def write(*args)
    @targets.each { |target| target.write(*args) }
  end

  def close
    @targets.each(&:close)
  end
end

# Set up Logger to write to both STDOUT and a file
$logger = Logger.new(MultiIO.new($stdout, File.open(File.join('logs', 'ssl_certificate.log'), 'a')))
$logger.level = Logger::INFO

def ssl_scan(hostname, port)
  begin
    ssl_context = OpenSSL::SSL::SSLContext.new
    tcp_socket = TCPSocket.new(hostname, port)
    ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)

    ssl_socket.hostname = hostname
    ssl_socket.connect

    cert = ssl_socket.peer_cert

    # Log SSL scan results
    $logger.info("SSL/TLS Scan Results for #{hostname}:#{port}")
    $logger.info('-----------------------')
    $logger.info("IP Address: #{tcp_socket.peeraddr[3]}")
    $logger.info("Host: #{hostname}")
    $logger.info("Port: #{port}")
    $logger.info('-----------------------')
    $logger.info("Protocol: #{ssl_socket.ssl_version}")
    $logger.info("Cipher Suite: #{ssl_socket.cipher[0]}")
    $logger.info('Certificate Information:')
    $logger.info("  Subject: #{cert.subject}")
    $logger.info("  Issuer: #{cert.issuer}")
    $logger.info("  Valid from: #{cert.not_before}")
    $logger.info("  Valid until: #{cert.not_after}")

    # Extract specific fields from the certificate details
    cert_text = cert.to_text
    fields_to_extract = [
      'Serial Number',
      'Signature Algorithm',
      'Issuer',
      'Not Before',
      'Not After',
      'Subject',
      'Subject Public Key Info',
      'Public Key Algorithm',
      'RSA Public-Key',
      'Modulus',
      'Exponent',
      'Authority Information Access',
      'CA Issuers - URI',
      'X509v3 Subject Alternative Name',
      'Signed Certificate Timestamp',
      'Signature'
    ]
    certificate_details = {}
    fields_to_extract.each do |field|
      regex = /#{field}:\s*(.+)/
      match = cert_text.match(regex)
      certificate_details[field.downcase.gsub(' ', '_').to_sym] = match[1] if match
    end

    certificate_details[:hostname] = hostname
    certificate_details[:port] = port
    certificate_details[:ip_address] = tcp_socket.peeraddr[3]
    certificate_details[:protocol] = ssl_socket.ssl_version
    certificate_details[:cipher_suite] = ssl_socket.cipher[0]

    # Create directory if it doesn't exist
    Dir.mkdir('ssl_certificates') unless Dir.exist?('ssl_certificates')

    # Save details to a text file
    File.open(File.join('ssl_certificates', 'ssl_certificates.txt'), 'a') do |file|
      file.puts "SSL/TLS Scan Results for #{certificate_details[:hostname]}:#{certificate_details[:port]}"
      file.puts '-----------------------'
      file.puts "IP Address: #{certificate_details[:ip_address]}"
      file.puts "Host: #{certificate_details[:hostname]}"
      file.puts "Port: #{certificate_details[:port]}"
      file.puts "Subject: #{cert.subject}"
      file.puts "Issuer: #{cert.issuer}"
      file.puts "Valid from: #{cert.not_before}"
      file.puts "Valid until: #{cert.not_after}"
      file.puts '-----------------------'
      file.puts "Protocol: #{certificate_details[:protocol]}"
      file.puts "Cipher Suite: #{certificate_details[:cipher_suite]}"
      file.puts 'Certificate Information:'

      fields_to_extract.each do |field|
        file.puts "  #{field}: #{certificate_details[field.downcase.gsub(' ', '_').to_sym]}"
      end

      file.puts "\n" # Add a newline separator between certificate details
    end
  rescue StandardError => e
    ErrorHandler.handle_error(e, "Error occurred during SSL scan for #{hostname}:#{port}")
    return nil
  ensure
    ssl_socket&.close
    tcp_socket&.close
  end
  certificate_details
end

# Method to analyze websites from a YAML file and save SSL details to a JSON file
def analyze_websites(websites_file)
  return unless File.exist?(websites_file)

  websites = load_distinct_websites(websites_file)
  $logger.info("----- going to analyze #{websites.count} hostnames.")
  ssl_details = []
  error_websites = []
  processed_hostnames = 0
  websites.each do |website|
    begin
      details = ssl_scan(website, 443)
      if details.nil?
        processed_hostnames += 1
        error_websites << website
        $logger.info("----- #{websites.count - processed_hostnames} digital certificates remain.")
        next
      end
      ssl_details << details
    rescue StandardError => e
      ErrorHandler.handle_error(e, "SSL Scan Error for #{website}")
      error_websites << website
      next
    end
    processed_hostnames += 1
    $logger.info("----- finished processing #{website} digital certificate. #{websites.count - processed_hostnames} digital certificates remain.")
  end
  $logger.info("----- finished analyzing #{websites.count} hostnames.")
  # Save SSL details to JSON file
  $logger.info('----- creating ssl_serializations folder if no exist')
  Dir.mkdir('ssl_serializations') unless Dir.exist?('ssl_serializations')
  File.open(File.join('ssl_serializations', 'ssl_details.json'), 'w') do |file|
    file.puts JSON.pretty_generate(ssl_details)
  end
  # Log websites with certificate errors
  $logger.info("----- going to save #{error_websites.count} digital certificate error websites.")
  log_errors(error_websites)
end

# Method to log websites with certificate errors
def log_errors(error_websites)
  return if error_websites.empty?

  error_websites.each do |website|
    # Save details to a text file
    File.open(File.join('ssl_certificates', 'ssl_certificate_errors.txt'), 'a') do |file|
      file.puts website
      file.puts '-----------------------'
    end
  end
end

# Method to load YAML file and extract distinct hostnames
def load_distinct_websites(websites_file)
  return unless File.exist?(websites_file)

  websites = YAML.load_file(websites_file)
  distinct_hostnames = websites.map { |website| website }.uniq

  # Save distinct hostnames to YAML file
  File.open(websites_file, 'w') { |file| file.puts distinct_hostnames.to_yaml }
  distinct_hostnames
end

# Method to save SSL details to JSON file
def save_ssl_details_to_json(ssl_details)
  Dir.mkdir('ssl_serializations') unless Dir.exist?('ssl_serializations')
  File.open(File.join('ssl_serializations', 'ssl_details.json'), 'w') do |file|
    file.puts JSON.pretty_generate(ssl_details)
  end
end

# Example usage
analyze_websites('websites.yml')
