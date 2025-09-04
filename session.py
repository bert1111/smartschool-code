from __future__ import annotations
import contextlib
import functools
import json
import time
import logging
import datetime
import requests
from requests import Session
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Self
from urllib.parse import urljoin
import pyotp
import types
from .common import bs4_html, get_all_values_from_form
from .exceptions import SmartSchoolAuthenticationError, SmartSchoolException

if TYPE_CHECKING:
    from requests import Response
    from .credentials import Credentials

logger = logging.getLogger(__name__)

def _handle_cookies_and_login(func):
    @functools.wraps(func)
    def inner(self: 'Smartschool', *args, **kwargs):
        if self.creds is None:
            raise RuntimeError("Smartschool instance must have valid credentials.")
        self._try_login()
        return func(self, *args, **kwargs)
    return inner

@dataclass
class Smartschool:
    creds: "Credentials" = None

    _session: Session = field(init=False)
    _cookie_file: str = field(init=False)

    def __post_init__(self):
        self._session = Session()
        # Dynamische bestandsnaam voor cookie per gebruiker per domain:
        self._cookie_file = self._make_cookie_filename()
        # Cookies laden als ze bestaan
        if Path(self._cookie_file).exists():
            with open(self._cookie_file, 'r') as f:
                cookies = json.load(f)
                self._session.cookies = requests.utils.cookiejar_from_dict(cookies)
        if self.creds is not None:
            self.creds.validate()
        self.post = types.MethodType(_handle_cookies_and_login(Smartschool.post), self)
        self.get = types.MethodType(_handle_cookies_and_login(Smartschool.get), self)

    def _make_cookie_filename(self):
        # Maak bestandsnaam uniek per gebruiker en school
        username = self.creds.username.replace('@', '_')
        domain = str(self.creds.main_url).replace('.', '_')
        return f"cookies_{username}_{domain}.json"

    def _save_cookies(self):
        with open(self._cookie_file, 'w') as f:
            json.dump(requests.utils.dict_from_cookiejar(self._session.cookies), f)

    def _try_login(self) -> None:
        logger.debug("Entering _try_login: Checking session validity.")
        try:
            check_resp = self._session.get(self.create_url("/"), allow_redirects=True)
            check_resp.raise_for_status()
            final_url = str(check_resp.url)
            logger.debug(f"Session validity check (GET /): Status {check_resp.status_code}, Final URL: {final_url}")
            if final_url.endswith(("/login", "/account-verification", "/2fa")):
                logger.debug("Session check indicates login/verification needed.")
            elif check_resp.status_code == 200:
                logger.debug("Session valid based on GET /. Skipping login.")
                return
            else:
                logger.warning(f"Unexpected state: Status {check_resp.status_code}, URL {final_url}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Session check failed: {e}. Proceeding with login.")

        logger.debug("Performing full login/verification flow.")
        try:
            login_page_resp = self._session.get(self.create_url("/login"), allow_redirects=True)
            login_page_resp.raise_for_status()
            final_login_get_url = str(login_page_resp.url)
            logger.debug(f"GET /login final URL: {final_login_get_url}")
            if final_login_get_url.endswith("/login"):
                final_resp = self._do_login(login_page_resp)
            elif final_login_get_url.endswith("/account-verification"):
                final_resp = self._complete_verification(login_page_resp)
            elif final_login_get_url.endswith("/2fa"):
                final_resp = self._complete_verification_2fa(login_page_resp)
            else:
                logger.info(f"GET /login redirected to {final_login_get_url}. Assuming session valid.")
                return
            if str(final_resp.url).endswith(("/login", "/account-verification", "/2fa")):
                logger.error(f"Login ended unexpectedly on {final_resp.url}")
                raise SmartSchoolAuthenticationError(f"Authentication failed, ended on {final_resp.url}")
            elif final_resp.status_code != 200:
                logger.error(f"Login ended with status {final_resp.status_code} at {final_resp.url}")
                raise SmartSchoolAuthenticationError(f"Authentication failed, status {final_resp.status_code} at {final_resp.url}")
            else:
                logger.debug("Login process completed successfully.")
                self._save_cookies()
        except Exception as e:
            logger.exception("Exception during login/verification.")
            if not isinstance(e, SmartSchoolAuthenticationError):
                raise SmartSchoolAuthenticationError(f"Unexpected authentication error: {e}") from e
            else:
                raise

    @_handle_cookies_and_login
    def post(self, url, *args, **kwargs) -> "Response":
        return self._session.post(self.create_url(url), *args, **kwargs)

    @_handle_cookies_and_login
    def get(self, url, *args, **kwargs) -> "Response":
        return self._session.get(self.create_url(url), *args, **kwargs)

    def _do_login(self, login_page_response: "Response") -> "Response":
        logger.debug("Entering _do_login")
        html = bs4_html(login_page_response)
        inputs = get_all_values_from_form(html, 'form[name="login_form"]')
        if not inputs:
            raise SmartSchoolAuthenticationError("Could not find login form inputs.")
        data = {}
        username_field_found = False
        password_field_found = False
        for input_ in inputs:
            input_name = input_.get("name")
            input_value = input_.get("value")
            if not input_name:
                continue
            if "username" in input_name:
                data[input_name] = self.creds.username
                username_field_found = True
            elif "password" in input_name:
                data[input_name] = self.creds.password
                password_field_found = True
            else:
                data[input_name] = input_value
        if not username_field_found or not password_field_found:
            logger.error(f"Login form missing username or password fields: {list(data.keys())}")
            raise SmartSchoolAuthenticationError("Login form parsing failed.")
        logged_data = {k: (v if 'password' not in k else '********') for k, v in data.items()}
        logger.debug(f"Data prepared for login POST: {logged_data}")

        login_post_url = str(login_page_response.url)
        login_post_resp = self._session.post(login_post_url, data=data, allow_redirects=True)
        login_post_resp.raise_for_status()
        self._save_cookies()

        if str(login_post_resp.url).endswith("/account-verification"):
            return self._complete_verification(login_post_resp)
        elif str(login_post_resp.url).endswith("/2fa"):
            return self._complete_verification_2fa(login_post_resp)
        else:
            return login_post_resp

    def _complete_verification(self, verification_page_response: "Response") -> "Response":
        logger.debug("Entering _complete_verification")
        html = bs4_html(verification_page_response)
        current_verification_url = str(verification_page_response.url)
        inputs = get_all_values_from_form(html, 'form[name="account_verification_form"]')
        if not inputs:
            inputs = get_all_values_from_form(html, 'form:has(input#account_verification_form__token)')
        if not inputs:
            raise SmartSchoolAuthenticationError("Could not find verification form fields")
        verification_data = {}
        security_question_field = None
        for input_ in inputs:
            input_name = input_.get("name")
            input_value = input_.get("value")
            if not input_name:
                continue
            if "_security_question_answer" in input_name:
                security_question_field = input_name
            else:
                verification_data[input_name] = input_value
        if not security_question_field:
            raise SmartSchoolAuthenticationError("Missing security question field in verification form")
        if not hasattr(self.creds, 'mfa') or not self.creds.mfa:
            raise SmartSchoolAuthenticationError("Birth date required for verification but not provided")
        birth_date_str = self.creds.mfa
        if isinstance(birth_date_str, datetime.date):
            birth_date_str = birth_date_str.strftime('%Y-%m-%d')
        elif isinstance(birth_date_str, str):
            birth_date_str = birth_date_str.replace('/', '-')
        verification_data[security_question_field] = birth_date_str

        logger.debug(f"Verification POST data: {verification_data}")
        verification_post_resp = self._session.post(current_verification_url, data=verification_data, allow_redirects=True)
        verification_post_resp.raise_for_status()
        self._save_cookies()
        return verification_post_resp

    def _complete_verification_2fa(self, verification_page_response: "Response") -> "Response":
        logger.debug("Entering _complete_verification_2fa")
        check_resp = self._session.get(self.create_url("/2fa/api/v1/config"), allow_redirects=True)
        check_resp.raise_for_status()
        supported = json.loads(check_resp.text)
        if 'googleAuthenticator' not in supported.get('possibleAuthenticationMechanisms', []):
            raise SmartSchoolAuthenticationError("Unsupported 2fa method, only googleAuthenticator supported")
        totp = pyotp.TOTP(self.creds.mfa)
        code = totp.now()
        google2fa = '{"google2fa":"%s"}' % code
        googleAuthenticatorResp = self._session.post(self.create_url("/2fa/api/v1/google-authenticator"), data=google2fa, allow_redirects=True)
        googleAuthenticatorResp.raise_for_status()
        self._save_cookies()
        return googleAuthenticatorResp

    def create_url(self, endpoint: str) -> str:
        return f"{self._url}/{endpoint.lstrip('/')}"

    @cached_property
    def _url(self) -> str:
        return "https://" + self.creds.main_url

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(for: {self.creds.username})"

    def json(self, url, *args, method: str = "get", **kwargs) -> dict | list:
        logger.debug(f"Calling json: method={method.upper()}, url={url}")
        if method.lower() == "post":
            r = self.post(url, *args, **kwargs)
        else:
            r = self.get(url, *args, **kwargs)
        json_ = r.text
        try:
            while isinstance(json_, str):
                if not json_:
                    logger.warning(f"Empty response for {method.upper()} {url}")
                    return {}
                json_ = json.loads(json_)
            return json_
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for {r.url}")
            logger.error(f"Status code: {r.status_code}")
            logger.error("--- Response Start ---")
            logger.error(r.text[:1000])
            logger.error("--- Response End ---")
            raise json.JSONDecodeError(msg=f"Failed to decode JSON from {r.url}: {e.msg}", doc=r.text, pos=e.pos) from None
        except Exception as e:
            logger.exception(f"Unexpected error parsing JSON {r.url}")
            raise

    def post(self, url, *args, **kwargs) -> "Response":
        return self._session.post(self.create_url(url), *args, **kwargs)

    def get(self, url, *args, **kwargs) -> "Response":
        return self._session.get(self.create_url(url), *args, **kwargs)
