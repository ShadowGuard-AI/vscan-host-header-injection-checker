import argparse
import requests
import logging
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Detect Host header injection vulnerabilities.')
    parser.add_argument('url', type=str, help='The URL to check for Host header injection.')
    parser.add_argument('-H', '--host', type=str, help='The malicious Host header to inject. Defaults to example.com', default='example.com')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug logging).')
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates if the given URL is properly formatted.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def check_host_header_injection(url, malicious_host):
    """
    Checks for Host header injection vulnerability.

    Args:
        url (str): The URL to test.
        malicious_host (str): The malicious Host header to inject.

    Returns:
        bool or None: True if a vulnerability is likely, False when the
        baseline comparison shows no evidence, and None when a request
        failed, which is inconclusive and earns no verdict.
    """
    try:
        # Baseline request with no injected Host header: the server is
        # left to use the Host from the URL itself.
        baseline = requests.get(url, allow_redirects=False, timeout=10)
        logging.debug(f"Baseline response status code: {baseline.status_code}")
        logging.debug(f"Baseline response header names: {sorted(baseline.headers.keys())}")
        baseline_body = baseline.content.decode('utf-8', 'ignore')
        baseline_location = baseline.headers.get('Location', '')

        # Craft the malicious request
        # requests still builds the TLS handshake from the URL, SNI included, and only swaps the HTTP Host line. A site whose virtual hosting is selected during the handshake itself is therefore outside what I can reach: the certificate and the connection belong to the URL's host no matter what this header says.
        headers = {'Host': malicious_host}
        logging.debug(f"Sending request to {url} with a Host header naming the test host")
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=10)

        logging.debug(f"Received response with status code: {response.status_code}")
        logging.debug(f"Response header names: {sorted(response.headers.keys())}")

        # Evidence counts only when it differs from the baseline:
        # 1. The malicious host is reflected in the response body or the
        #    Location header, and the baseline does not reflect it.
        # 2. The status changed from the baseline to an error status.
        # The request URL itself is never evidence: with redirects
        # disabled, response.url is the URL that was requested.

        location = response.headers.get('Location', '')
        if malicious_host in location and malicious_host not in baseline_location:
            print("Possible Host Header Injection vulnerability found. Redirected to malicious host in Location header.")
            return True

        # Decoding with ignore drops the bytes that do not fit UTF-8. A reflection written in another encoding, or split by an invalid byte, can be present in the raw response and still never appear in the string I search.
        body = response.content.decode('utf-8', 'ignore')
        if malicious_host in body and malicious_host not in baseline_body:
            print(f"Possible Host Header Injection vulnerability found. Malicious host reflected in the response body.")
            return True

        # Only 400 and 500 count as status evidence. A 403 from a firewall that disliked the foreign Host, or a 404 from the default virtual host answering instead, are treated as no evidence, even though both are common shapes of a server reacting to the injected name.
        if response.status_code in [400, 500] and response.status_code != baseline.status_code:
            print(f"Possible Host Header Injection vulnerability found.  Status changed from baseline {baseline.status_code} to {response.status_code} with the injected Host header.")
            return True

        return False

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None



def main():
    """
    Main function to execute the Host header injection check.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url
    # The default test name is example.com, a real domain that real sites sometimes redirect to in documentation examples and parked configurations. The baseline comparison above is what keeps that from becoming a finding on its own, which is why the baseline request must never be dropped as an optimisation.
    malicious_host = args.host

    # Input validation
    if not is_valid_url(url):
        print("Error: Invalid URL provided.")
        sys.exit(1)

    print(f"Checking {url} for Host header injection with malicious host: {malicious_host}")

    result = check_host_header_injection(url, malicious_host)
    if result is None:
        print("Host Header Injection check inconclusive: the target could not be reached or a request failed.")
        sys.exit(1)
    if result:
        print("Possible Host Header Injection vulnerability detected.")
    else:
        print("No Host Header Injection vulnerability detected (or not easily detectable with this simple check).")


if __name__ == "__main__":
    """
    Entry point for the script.
    """
    main()