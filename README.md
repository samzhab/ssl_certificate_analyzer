# SSL Certificate Analyzer

## Overview

The SSL Certificate Analyzer is a Ruby application designed to analyze SSL/TLS certificates of websites listed in a YAML file. It scans each website's certificate, extracts relevant information, and saves the details to JSON files. Additionally, it logs events and updates using a Logger to provide visibility into the analysis process.

## Features

- Analyze SSL/TLS certificates of websites listed in a YAML file.
- Extract relevant certificate information such as subject, issuer, validity, etc.
- Log events and updates using a Logger.
- Save SSL details to JSON files.

## Installation

1. Clone this repository to your local machine:

    ```bash
    git clone <repository_url>
    ```

2. Install required dependencies:

    ```bash
    gem install bundler
    bundle install
    ```

## Folder Structure

- **ssl_certificates**: Directory to store SSL certificate details.
  - **ssl_certificate_errors.txt**: File to log websites with certificate errors.
- **ssl_serializations**: Directory to store serialized SSL details in JSON format.
  - **ssl_details.json**: JSON file containing SSL details of analyzed websites.
- **logs**: Directory to store log files.
  - **ssl_certificate.log**: Log file for SSL certificate analysis events and updates.

## Usage

1. Prepare a YAML file (`websites.yml`) containing a list of websites to analyze. Ensure each website is listed in the following format:

    ```yaml
    - example.com
    - example.com
    - example.com
    - example.com
    ```

2. Run the SSL certificate analysis:

    ```bash
    ruby ssl_certificate_analyzer.rb
    ```

3. View the analyzed SSL details in the `ssl_serializations/ssl_details.json` file.

## Logging

- SSL certificate analysis events and updates are logged to `logs/ssl_certificate.log` file.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or create a pull request.

## License
This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/).

![CC BY-SA 4.0](https://i.creativecommons.org/l/by-sa/4.0/88x31.png)

**Attribution**: This project is published by Samael (AI Powered), 2024.

You are free to:
- **Share** — copy and redistribute the material in any medium or format
- **Adapt** — remix, transform, and build upon the material for any purpose, even commercially.

Under the following terms:
- **Attribution** — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
- **ShareAlike** — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original.

No additional restrictions — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

Notices:
You do not have to comply with the license for elements of the material in the public domain or where your use is permitted by an applicable exception or limitation.

No warranties are given. The license may not give you all of the permissions necessary for your intended use. For example, other rights such as publicity, privacy, or moral rights may limit how you use the material.
