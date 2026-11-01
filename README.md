# vscan-host-header-injection-checker
Detects potential Host header injection vulnerabilities by manipulating the Host header and observing server behavior. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-host-header-injection-checker`

## Usage
`./vscan-host-header-injection-checker [params]`

The check first sends a baseline request with no injected Host header, then a request with the test Host header. A finding requires evidence beyond the baseline: the test host reflected in the body or in a redirect Location header where the baseline does not reflect it, or a status change from the baseline to an error status. A bare error status that the baseline also returns is not a finding. If a request fails, the check is inconclusive and the tool exits 1 with no verdict. Verbose mode logs status codes and response header names only; header values and response bodies are not logged.

## Parameters
- `-h`: Show help message and exit
- `-H`: The malicious Host header to inject. Defaults to example.com
- `-v`: No description provided

## License
Copyright (c) ShadowGuardAI
