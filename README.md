# vscan-host-header-injection-checker
Detects potential Host header injection vulnerabilities by manipulating the Host header and observing server behavior. Focused on lightweight web application vulnerability scanning for common misconfigurations and publicly known vulnerabilities.

## Install
`git clone https://github.com/ShadowGuard-AI/vscan-host-header-injection-checker`

## Usage
`python3 main.py <url> [-H HOST] [-v]`

The check first sends a baseline request with no injected Host header, then a request with the test Host header. A finding requires evidence beyond the baseline: the test host reflected in the body or in a redirect Location header where the baseline does not reflect it, or a status change from the baseline to a 400 or 500 status. Reflection comparisons are case-insensitive, because host names are case-insensitive and servers commonly normalize them to lowercase. A bare error status that the baseline also returns is not a finding. The URL must use the http or https scheme; anything else is rejected as an invalid URL with exit 1. If a request fails, the check is inconclusive and the tool exits 1 with no verdict. A completed check exits 0 whether or not a finding was reported. Verbose mode logs status codes and response header names only; header values and response bodies are not logged.

## Parameters
- `-h`: Show help message and exit
- `-H HOST, --host HOST`: The malicious Host header to inject. Defaults to example.com
- `-v, --verbose`: Enable verbose output (debug logging)

## License
MIT. See LICENSE.
