#!/usr/bin/env python

from typing import Union
from requests import Session
from jwcrypto.jwk import JWK
from jwcrypto.jwe import JWE
from Crypto.PublicKey import RSA
from datetime import datetime as Datetime, timedelta as Timedelta
from pyotp import HOTP, TOTP
from getpass import getpass

import uuid
import hashlib
import base64
import json
import sys
import argparse
import qrcode


# globals

otp_counter = 0

OTP_PERIOD = 120
OTP_DIGITS = 6


# http requests

def http_preregistration(s: Session) -> Union[str, JWK]:
    # preparation
    registration_code, registration_code_hashed = rand_hashed_uuid()
    url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v2/registerInit'
    content = {'appName': 'app-posteid-v3', 'initCodeChallenge': registration_code_hashed}

    r = s.post(url, json=content)
    assert r.status_code == 200, 'Preregistration failed ({} != 200)'.format(r.status_code)
    
    # parse content
    response_json = json.loads(r.text)
    pubkey_hex = response_json['pubServerKey']
    pubkey_pem = wrap_pem(pubkey_hex)
    pubkey = from_pem(pubkey_pem)
    return registration_code, pubkey

def http_registration(s: Session, registration_code: str, 
                      app_pubkey: str, app_privkey: JWK, server_key: JWK) -> Union[str, HOTP]:
    url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v2/register'

    # build jwe
    header = jwe_header(server_key=server_key)
    data = {
        'initCodeVerifier': registration_code,
        'xdevice': '{}::Android:10.0:SM-G960F:4.2.10:false'.format('A'*10), 
        'pubAppKey': b64enc_str(app_pubkey)
    }
    content = jwe_content('register', data)
    jwe = jwe_encode(header, content, server_key)

    # make http request
    r = s.post(url, data=jwe)
    assert r.status_code == 200, 'Registration failed ({} != 200)'.format(r.status_code)

    # parse response
    response = jwe_decode(r.text, app_privkey)

    app_id = response['data']['app-uuid']
    otp_secret_key = response['data']['otpSecretKey']
    otp_generator = new_auth_otp(otp_secret_key)

    return app_id, otp_generator

def http_app_activation(s: Session, app_id: str, app_id_hashed: str, 
                          otp_generator: HOTP, server_key: JWK):
    url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v2/activation'

    # build jwe
    header = jwe_header(app_id=app_id)
    otp_when, otp_code = next_otp(otp_generator)
    content = jwe_content('register', otp=jwe_otp(otp_when, otp_code), kid=app_id_hashed)
    jwe = jwe_encode(header, content, server_key)

    # make http request
    r = s.post(url, data=jwe)
    assert r.status_code == 200, 'App activation failed ({} != 200)'.format(r.status_code)

def http_get_config(s: Session, app_id: str, otp_generator: HOTP):
    # prepare request
    url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v1/appregistry/appconfig'
    otp_when, otp_code = next_otp(otp_generator)
    xkey = build_header_xkey(app_id, otp_when, otp_code)
    body = build_useless_header_app()

    # make http request
    r = s.post(url, headers=xkey, json=body)
    assert r.status_code == 200, 'Get config failed ({} != 200)'.format(r.status_code)

def http_appcheck_1(s: Session, app_id: str, otp_generator: HOTP):
    # prepare request
    url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v1/appregistry/appcheck'
    otp_when, otp_code = next_otp(otp_generator)
    xkey = build_header_xkey(app_id, otp_when, otp_code)
    body = build_useless_header_app()

    # make http request
    r = s.post(url, headers=xkey, json=body)
    assert r.status_code == 200, 'Check registration 1 failed ({} != 200)'.format(r.status_code)

def http_appcheck_2(s: Session, app_id: str, app_id_hashed: str, otp_generator: HOTP, 
                    server_key: JWK):
    url = 'https://sh2-web-posteid.poste.it/jod-secure-holder2-web/public/app/v1/checkRegisterApp'

    # build jwe
    header = jwe_header(app_id)
    otp_when, otp_code = next_otp(otp_generator)
    data = { 'appRegisterID': app_id }
    content = jwe_content('checkRegisterApp', data, 
                          otp=jwe_otp(otp_when, otp_code), kid=app_id_hashed)
    jwe = jwe_encode(header, content, server_key)

    # make http request
    r = s.post(url, data=jwe)
    assert r.status_code == 200, 'Check registration 2 ({} != 200)'.format(r.status_code)

def http_login(s: Session, app_id: str, app_id_hashed: str, otp_generator: HOTP, 
               username: str, password: str, server_key: JWK):
    url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

    # build jwe
    header = jwe_header(app_id)
    otp_when, otp_code = next_otp(otp_generator)
    data = {
        'authLevel': '0',
        'userid': username,
        'password': password
    }
    content = jwe_content('login', data=data, otp=jwe_otp(otp_when, otp_code), kid=app_id_hashed)
    jwe = jwe_encode(header, content, server_key)
    
    # make http request
    r = s.get(url, headers=jwe_bearer(jwe))
    assert r.status_code == 200, 'Login failed ({} != 200)'.format(r.status_code)

def http_send_sms(s: Session, app_id: str, app_id_hashed: str, otp_generator: HOTP, 
                  username: str, server_key: JWK):
    url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

    # build jwe
    header = jwe_header(app_id)
    otp_when, otp_code = next_otp(otp_generator)
    data = {
        'authLevel': '3',
        'userid': username, 
        'password': rand_uuid()
    }
    content = jwe_content('login', data=data, otp=jwe_otp(otp_when, otp_code), kid=app_id_hashed)
    jwe = jwe_encode(header, content, server_key)

    # make http request
    r = s.get(url, headers=jwe_bearer(jwe))
    assert r.status_code == 200, 'Send SMS failed ({} != 200)'.format(r.status_code)

def http_submit_sms(s: Session, app_id: str, app_id_hashed: str, otp_generator: HOTP,
                    sms_otp: str, server_key: JWK, app_privkey: JWK) -> str:
    url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

    # build jwe
    header = jwe_header(app_id)
    otp_when, otp_code = next_otp(otp_generator)
    data = {
        'authLevel': '2',
        'otp': sms_otp,
        'nonce': rand_uuid()
    }
    content = jwe_content('login', data=data, otp=jwe_otp(otp_when, otp_code), kid=app_id_hashed)
    jwe  = jwe_encode(header, content, server_key)

    # make http request
    r = s.get(url, headers=jwe_bearer(jwe))
    assert r.status_code == 200, 'Submit SMS failed ({} != 200)'.format(r.status_code)

    # parse response
    response = jwe_decode(r.headers['X-RESULT'], app_privkey)
    sms_alt_token = response['data']['token']

    return sms_alt_token

def http_register_app(s: Session, app_id: str, app_id_hashed: str, otp_generator: HOTP,
                      server_key: JWK, app_privkey: JWK, sms_alt_token: str, 
                      poste_pin: str={}) -> Union[str, str]:
    url = 'https://sh2-web-posteid.poste.it/jod-secure-holder2-web/public/app/v1/registerApp'

    # build jwe
    header = jwe_header(app_id)
    otp_when, otp_code = next_otp(otp_generator)
    data = {
        'idpAccessToken': '',
        'registerToken': sms_alt_token,
        'userPIN': poste_pin
    }
    content = jwe_content('registerApp', data=data, otp=jwe_otp(otp_when, otp_code), kid=app_id_hashed)
    jwe = jwe_encode(header, content, server_key)

    # make http request
    r = s.post(url, data=jwe)
    assert r.status_code == 200, 'Register app failed ({} != 200)'.format(r.status_code)

    # parse reponse
    response_encoded = json.loads(r.text)
    response = response_encoded['command-result']
    
    response_content = jwe_decode(response, app_privkey)

    app_register_id = response_content['data']['appRegisterID']
    secret_app = response_content['data']['secretAPP']

    return app_register_id, secret_app


# utils

def rand_uuid() -> str:
    # uuid version 4 generates a random uuid
    return str(uuid.uuid4())

def sha256b64enc(content: str) -> str:
    content_bytes = content.encode('utf-8')
    
    digest = hashlib.sha256()
    digest.update(content_bytes)
    hash_result = digest.digest()

    return b64enc_str(hash_result)

def b64enc_str(content: bytes) -> str:
    result_encoded = base64.b64encode(content)
    return result_encoded.decode('utf-8')

def rand_hashed_uuid() -> Union[str, str]:
    uuid = rand_uuid()
    result = sha256b64enc(uuid)
    return uuid, result

def wrap_pem(key: str) -> str:
    template = '-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----'
    pem_key = template.format(key).encode('utf-8')
    return pem_key

def from_pem(pem_key: str) -> JWK:
    return JWK.from_pem(pem_key)

def generate_pairs() -> Union[str, JWK]:
    keypair = RSA.generate(2048)

    public = keypair.publickey().exportKey(format='DER')
    private = from_pem(keypair.exportKey())

    return public, private

def times() -> Union[int, int]:
    now = Datetime.utcnow()
    minute = Timedelta(seconds=60)

    start = int(now.timestamp())
    end = int((now + minute).timestamp())

    return start, end

def jwe_header(app_id: str = None, server_key: JWK=None) -> dict:
    header = {
        "alg": "RSA-OAEP-256",
        "enc": "A256CBC-HS512",
        "typ": "JWT",
        "cty": "JWE",
        "kid": app_id if app_id != None else server_key.thumbprint(),
    }

    return header

def jwe_content(sub: str, data: dict={}, otp: dict=None, kid: dict=None):
    start, end = times()
    content = {
        'iss': 'app-posteid-v3',
        'sub': sub,
        'jti': rand_uuid(),
        'exp': end,
        'nbf': start,
        'iat': start,
        'data': data
    }

    if otp != None:
        content['otp-specs'] = otp

    if kid != None:
        content['kid-sha256'] = kid

    return content

def jwe_encode(header: dict, content: dict, key: JWK) -> str:
    # convert content
    content_json = json.dumps(content)
    content_bytes = content_json.encode('utf-8')

    # build_jwe
    jwe = JWE(protected=header, plaintext=content_bytes, recipient=key)
    serialized = jwe.serialize(True)
    return serialized

def jwe_bearer(content: str) -> dict:
    result = { 'Authorization': 'Bearer {}'.format(content) }
    return result

def new_auth_otp(otp_key: str) -> HOTP:
    return HOTP(otp_key, digits=8)

def jwe_otp(when: int, otp: str) -> dict:
    otp_dict = {
        'movingFactor': when,
        'otp': otp,
        'type': 'HMAC-SHA1'
    }
    return otp_dict

def next_otp(generator: HOTP) -> Union[int, str]:
    global otp_counter
    otp_counter += 1

    return otp_counter, generator.at(otp_counter)

def build_header_xkey(app_id: str, when: int, otp: str) -> dict:
    result = { 'X-KEY': '{}:{}:{}'.format(app_id, otp, when) }
    return result

def build_useless_header_app() -> dict:
    result = {'header': {'clientid': None, 'requestid': None}, 'body': {}}
    return result

def jwe_decode(content: str, jwe_key: JWK) -> dict:
    jwe_message = JWE()
    jwe_message.deserialize(content, jwe_key)
    result = json.loads(jwe_message.payload)
    return result

def read_secret() -> str:
    try:
        with open('secret.txt', 'r') as f:
            return f.readline()
    except:
        return None

def read_secret_or_fail(seed: str) -> str:
    if seed == None:
        seed = read_secret()
        if seed == None:
            print('No seed provided')
            exit()
    return seed

def parse_otp_seed(seed: str) -> str:
    key = base64.b32encode(seed.encode('utf-8'))
    return key.decode('utf-8')

def write_secret(secret: str):
    with open('secret.txt', 'w') as f:
        f.write(secret)


# functions

def extract_cmd(only_output: bool, show_string: bool):
    s = Session()

    registration_code, server_key = http_preregistration(s)
    app_pubkey, app_privkey = generate_pairs()
    app_id, otp_generator = http_registration(s, registration_code, app_pubkey, 
                                              app_privkey, server_key)
    app_id_hashed = sha256b64enc(app_id)
    http_app_activation(s, app_id, app_id_hashed, otp_generator, server_key)

    # useless calls
    http_get_config(s, app_id, otp_generator)
    http_appcheck_1(s, app_id, otp_generator)
    http_appcheck_2(s, app_id, app_id_hashed, otp_generator, server_key)

    # ask login info
    username = input('Type username: ')
    password = getpass('Type password: ')
    http_login(s, app_id, app_id_hashed, otp_generator, username, password, server_key)
    del password

    # handle sms
    http_send_sms(s, app_id, app_id_hashed, otp_generator, username, server_key)
    sms_otp = input('Type SMS otp: ')
    sms_alt_token = http_submit_sms(s, app_id, app_id_hashed, otp_generator, sms_otp, 
                                    server_key, app_privkey)
    del sms_otp

    # register app
    app_register_id, secret_app = http_register_app(s, app_id, app_id_hashed, 
                    otp_generator, server_key, app_privkey, sms_alt_token)

    # write output
    if not only_output:
        write_secret(secret_app)

    # write qr or seed
    if show_string:
        print(secret_app)
    else:
        generate_qr_cmd(secret_app)

    del secret_app

def generate_qr_cmd(seed: str=None):
    seed = read_secret_or_fail(seed)
    seed = parse_otp_seed(seed)

    uri = 'otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}'
    qr_uri = uri.format('PosteID', 'username', seed, 'PosteID', 'SHA1', OTP_DIGITS, OTP_PERIOD)

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(qr_uri)

    qr.print_ascii(invert=True)

def generate_code_cmd(seed: str=None, time: int=None):
    seed = read_secret_or_fail(seed)
    seed = parse_otp_seed(seed)

    generator = TOTP(seed, digits=OTP_DIGITS, interval=OTP_PERIOD, digest=hashlib.sha1)

    if time == None:
        code = generator.now()
    else:
        code = generator.at(time)

    print('Your code is: {}'.format(code))


# main

def main():
    # check python version
    if sys.version_info.major < 3 or (sys.version_info.major == 3 and sys.version_info.minor <= 6):
        print('Python 3.6 or higher is required')

    # argument parser
    parser = argparse.ArgumentParser(description='This is a tool to extract the OTP seed of PosteID app')
    option_parser = parser.add_subparsers(title='option', dest='option', required=True, 
                                          description='Action to be performed')

    # extract command 
    extract = option_parser.add_parser('extract', help='Extract OTP code')
    extract.add_argument('-o', '--only-output', action='store_true',
                         help='Only show the output on the screen (do not write output in the secret.txt file)')
    extract.add_argument('-s', '--show-string', action='store_true',
                         help='Print OTP seed as string instead of qr code')
    
    # generate qr
    qr = option_parser.add_parser('generate_qr', help='Generate importable qr code')
    qr.add_argument('-s', '--seed', type=str, help='The OTP seed')

    # generate code
    code = option_parser.add_parser('generate_code', help = 'Generate OTP code of a specific time')
    code.add_argument('-s', '--seed', type=str, help='The OTP seed')
    code.add_argument('-t', '--time', type=str, help='Generate OTP in a precise time (UnixEpoch time), default is now')

    # parse
    args = parser.parse_args()

    if args.option == 'extract':
        extract_cmd(args.only_output, args.show_string)
    elif args.option == 'generate_qr':
        generate_qr_cmd(args.seed)
    elif args.option == 'generate_code':
        generate_code_cmd(args.seed, args.time)


if __name__ == '__main__':
    main()
