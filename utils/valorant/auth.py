# from __future__ import annotations

# Standard
import json
import re
import ssl
from datetime import datetime, timedelta
from typing import Any

# Third
import aiohttp

from ..errors import AuthenticationError
from ..locale_v2 import ValorantTranslator

# Local
from .local import LocalErrorResponse, ResponseLanguage

vlr_locale = ValorantTranslator()


def _extract_tokens(data: str) -> str:
    """Extract tokens from data"""

    pattern = re.compile(
        r'access_token=((?:[a-zA-Z]|\d|\.|-|_)*).*id_token=((?:[a-zA-Z]|\d|\.|-|_)*).*expires_in=(\d*)'
    )
    return pattern.findall(data['response']['parameters']['uri'])[0]


def _extract_tokens_from_uri(url: str) -> tuple[str, str]:
    try:
        access_token = url.split('access_token=')[1].split('&scope')[0]
        token_id = url.split('id_token=')[1].split('&')[0]
        return access_token, token_id
    except IndexError as e:
        raise AuthenticationError('Cookies Invalid') from e


def _extract_auth_tokens(data: dict[str, Any]) -> tuple[str, str]:
    if data.get('type') == 'success':
        redirect_url = data['success']['redirect_url']
        return _extract_tokens_from_uri(redirect_url)

    response = _extract_tokens(data)
    return response[0], response[1]


# https://developers.cloudflare.com/ssl/ssl-tls/cipher-suites/

FORCED_CIPHERS = [
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-RSA-AES128-SHA256',
    'ECDHE-RSA-AES128-SHA',
    'ECDHE-RSA-AES256-SHA',
    'ECDHE-ECDSA-AES128-SHA256',
    'ECDHE-ECDSA-AES128-SHA',
    'ECDHE-ECDSA-AES256-SHA',
    'ECDHE+AES128',
    'ECDHE+AES256',
    'ECDHE+3DES',
    'RSA+AES128',
    'RSA+AES256',
    'RSA+3DES',
]


class ClientSession(aiohttp.ClientSession):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_ciphers(':'.join(FORCED_CIPHERS))
        super().__init__(*args, **kwargs, cookie_jar=aiohttp.CookieJar(), connector=aiohttp.TCPConnector(ssl=ctx))


class Auth:
    RIOT_CLIENT_USER_AGENT = 'RiotClient/60.0.6.4770705.4749685 rso-auth (Windows;10;;Professional, x64)'

    def __init__(self) -> None:
        self._headers: dict[str, Any] = {
            'Content-Type': 'application/json',
            'User-Agent': Auth.RIOT_CLIENT_USER_AGENT,
            'Accept': 'application/json, text/plain, */*',
        }
        self.user_agent = Auth.RIOT_CLIENT_USER_AGENT

        self.locale_code = 'en-US'  # default language
        self.response = {}  # prepare response for local response

    def local_response(self) -> dict[str, Any]:
        """This function is used to check if the local response is enabled."""
        self.response = LocalErrorResponse('AUTH', self.locale_code)
        return self.response

    async def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        """This function is used to authenticate the user."""

        # language
        local_response = self.local_response()

        auth_cookie_payload = {
            'client_id': 'play-valorant-web-prod',
            'nonce': '1',
            'redirect_uri': 'https://playvalorant.com/opt_in',
            'response_type': 'token id_token',
            'scope': 'account openid',
        }

        auth_payloads = [
            {
                'type': 'auth',
                'language': 'en_US',
                'remember': True,
                'riot_identity': {
                    'captcha': '',
                    'username': username,
                    'password': password,
                },
            },
            {'type': 'auth', 'username': username, 'password': password, 'remember': True},
        ]

        async def auth_attempt(payload: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, Any]]:
            session = ClientSession()

            r = await session.post(
                'https://auth.riotgames.com/api/v1/authorization',
                json=auth_cookie_payload,
                headers=self._headers,
            )

            cookies: dict[str, Any] = {'cookie': {}}
            for cookie in r.cookies.items():
                cookies['cookie'][cookie[0]] = str(cookie).split('=')[1].split(';')[0]

            async with session.put(
                'https://auth.riotgames.com/api/v1/authorization', json=payload, headers=self._headers
            ) as r:
                data = await r.json()
                for cookie in r.cookies.items():
                    cookies['cookie'][cookie[0]] = str(cookie).split('=')[1].split(';')[0]
                status = r.status

            await session.close()
            return status, data, cookies

        status, data, cookies = await auth_attempt(auth_payloads[0])
        if data.get('error') == 'auth_failure':
            status, data, cookies = await auth_attempt(auth_payloads[1])

        auth_type = data.get('type')
        auth_error = data.get('error')

        if auth_type in ('response', 'success'):
            access_token, token_id = _extract_auth_tokens(data)

            expiry_token = datetime.now() + timedelta(minutes=59)
            cookies['expiry_token'] = int(datetime.timestamp(expiry_token))  # type: ignore

            return {'auth': 'response', 'data': {'cookie': cookies, 'access_token': access_token, 'token_id': token_id}}

        if auth_type == 'multifactor':
            if status == 429 or auth_error == 'rate_limited':
                raise AuthenticationError(local_response.get('RATELIMIT', 'Please wait a few minutes and try again.'))

            label_modal = local_response.get('INPUT_2FA_CODE')
            WaitFor2FA = {'auth': '2fa', 'cookie': cookies, 'label': label_modal}

            method = data['multifactor'].get('method')
            if method == 'email':
                WaitFor2FA['message'] = (
                    f'{local_response.get("2FA_TO_EMAIL", "Riot sent a code to")} {data["multifactor"]["email"]}'
                )
                return WaitFor2FA

            WaitFor2FA['message'] = local_response.get('2FA_ENABLE', 'You have 2FA enabled!')
            return WaitFor2FA

        if status == 429 or auth_error == 'rate_limited':
            raise AuthenticationError(local_response.get('RATELIMIT', 'Please wait a few minutes and try again.'))

        if auth_error in ('captcha_required', 'captcha_verification_required'):
            raise AuthenticationError(
                'Riot requires CAPTCHA or browser verification. Please log in with `/cookies` instead.'
            )

        if auth_error == 'auth_failure':
            raise AuthenticationError(
                'Riot rejected direct username/password login. '
                'This can happen with Riot Mobile auth, CAPTCHA, or browser verification. '
                'Please log in with `/cookies` instead.'
            )

        message = local_response.get('INVALID_PASSWORD', 'Your username or password may be incorrect!')
        if auth_error:
            message = f'{message} (Riot auth error: {auth_error})'
        elif auth_type:
            message = f'{message} (Riot auth type: {auth_type})'

        raise AuthenticationError(message)

    async def get_entitlements_token(self, access_token: str) -> str:
        """This function is used to get the entitlements token."""

        # language
        local_response = self.local_response()

        session = ClientSession()

        headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {access_token}'}

        async with session.post('https://entitlements.auth.riotgames.com/api/token/v1', headers=headers, json={}) as r:
            data = await r.json()

        await session.close()
        try:
            entitlements_token = data['entitlements_token']
        except KeyError as e:
            raise AuthenticationError(
                local_response.get('COOKIES_EXPIRED', 'Cookies is expired, plz /login again!')
            ) from e
        else:
            return entitlements_token

    async def get_userinfo(self, access_token: str) -> tuple[str, str, str]:
        """This function is used to get the user info."""

        # language
        local_response = self.local_response()

        session = ClientSession()

        headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {access_token}'}

        async with session.post('https://auth.riotgames.com/userinfo', headers=headers, json={}) as r:
            data = await r.json()

        await session.close()
        try:
            puuid = data['sub']
            name = data['acct']['game_name']
            tag = data['acct']['tag_line']
        except KeyError as e:
            raise AuthenticationError(
                local_response.get('NO_NAME_TAG', "This user hasn't created a name or tagline yet.")
            ) from e
        else:
            return puuid, name, tag

    async def get_region(self, access_token: str, token_id: str) -> str:
        """This function is used to get the region."""

        # language
        local_response = self.local_response()

        session = ClientSession()

        headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {access_token}'}

        body = {'id_token': token_id}

        async with session.put(
            'https://riot-geo.pas.si.riotgames.com/pas/v1/product/valorant', headers=headers, json=body
        ) as r:
            data = await r.json()

        await session.close()
        try:
            region = data['affinities']['live']
        except KeyError as e:
            raise AuthenticationError(
                local_response.get('REGION_NOT_FOUND', 'An unknown error occurred, plz `/login` again')
            ) from e
        else:
            return region

    async def give2facode(self, code: str, cookies: dict[str, Any]) -> dict[str, Any]:
        """This function is used to give the 2FA code."""

        # language
        local_response = self.local_response()

        session = ClientSession()

        # headers = {'Content-Type': 'application/json', 'User-Agent': self.user_agent}

        data = {'type': 'multifactor', 'multifactor': {'otp': code, 'rememberDevice': True}}

        async with session.put(
            'https://auth.riotgames.com/api/v1/authorization',
            headers=self._headers,
            json=data,
            cookies=cookies['cookie'],
        ) as r:
            data = await r.json()

        await session.close()
        if data['type'] in ('response', 'success'):
            cookies = {'cookie': {}}
            for cookie in r.cookies.items():
                cookies['cookie'][cookie[0]] = str(cookie).split('=')[1].split(';')[0]

            access_token, token_id = _extract_auth_tokens(data)

            return {'auth': 'response', 'data': {'cookie': cookies, 'access_token': access_token, 'token_id': token_id}}

        return {'auth': 'failed', 'error': local_response.get('2FA_INVALID_CODE')}

    async def redeem_cookies(self, cookies: dict) -> tuple[dict[str, Any], str, str]:
        """This function is used to redeem the cookies."""

        # language
        local_response = self.local_response()

        if isinstance(cookies, str):
            cookies = json.loads(cookies)

        session = ClientSession()

        if 'cookie' in cookies:
            cookies = cookies['cookie']

        async with session.get(
            'https://auth.riotgames.com/authorize?redirect_uri=https%3A%2F%2Fplayvalorant.com%2Fopt_in&client_id=play'
            '-valorant-web-prod&response_type=token%20id_token&scope=account%20openid&nonce=1',
            cookies=cookies,
            allow_redirects=False,
        ) as r:
            await r.text()
            redirect_url = r.headers.get('Location', '')

        if r.status not in (301, 302, 303):
            await session.close()
            raise AuthenticationError(local_response.get('COOKIES_EXPIRED'))

        if redirect_url.startswith('/login') or 'authenticate.riotgames.com/login' in redirect_url:
            await session.close()
            raise AuthenticationError(local_response.get('COOKIES_EXPIRED'))

        old_cookie = cookies.copy()

        new_cookies = {'cookie': old_cookie}
        for cookie in r.cookies.items():
            new_cookies['cookie'][cookie[0]] = str(cookie).split('=')[1].split(';')[0]

        await session.close()

        access_token, _token_id = _extract_tokens_from_uri(redirect_url)
        entitlements_token = await self.get_entitlements_token(access_token)

        return new_cookies, access_token, entitlements_token

    async def temp_auth(self, username: str, password: str) -> dict[str, Any] | None:
        authenticate = await self.authenticate(username, password)
        if authenticate['auth'] == 'response':  # type: ignore
            access_token = authenticate['data']['access_token']  # type: ignore
            token_id = authenticate['data']['token_id']  # type: ignore

            entitlements_token = await self.get_entitlements_token(access_token)
            puuid, name, tag = await self.get_userinfo(access_token)
            region = await self.get_region(access_token, token_id)
            player_name = f'{name}#{tag}' if tag is not None and tag is not None else 'no_username'

            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access_token}',
                'X-Riot-Entitlements-JWT': entitlements_token,
            }
            return {'puuid': puuid, 'region': region, 'headers': headers, 'player_name': player_name}

        raise AuthenticationError(self.local_response().get('TEMP_LOGIN_NOT_SUPPORT_2FA'))

    # next update

    async def login_with_cookie(self, cookies: dict[str, Any] | str) -> dict[str, Any]:
        """This function is used to log in with cookie."""

        # language
        local_response = ResponseLanguage('cookies', self.locale_code)

        cookie_payload = f'ssid={cookies};' if isinstance(cookies, str) and cookies.startswith('e') else cookies

        self._headers['cookie'] = cookie_payload

        session = ClientSession()

        r = await session.get(
            'https://auth.riotgames.com/authorize'
            '?redirect_uri=https%3A%2F%2Fplayvalorant.com%2Fopt_in'
            '&client_id=play-valorant-web-prod'
            '&response_type=token%20id_token'
            '&scope=account%20openid'
            '&nonce=1',
            allow_redirects=False,
            headers=self._headers,
        )

        # pop cookie
        self._headers.pop('cookie')

        redirect_url = r.headers.get('Location', '')

        if r.status not in (301, 302, 303):
            await session.close()
            raise AuthenticationError(local_response.get('FAILED'))

        await session.close()

        # NEW COOKIE
        new_cookies = {'cookie': {}}
        for cookie in r.cookies.items():
            new_cookies['cookie'][cookie[0]] = str(cookie).split('=')[1].split(';')[0]

        accessToken, tokenID = _extract_tokens_from_uri(redirect_url)
        entitlements_token = await self.get_entitlements_token(accessToken)

        return {'cookies': new_cookies, 'AccessToken': accessToken, 'token_id': tokenID, 'emt': entitlements_token}

    async def login_with_redirect_url(self, redirect_url: str) -> dict[str, Any]:
        """Log in with the URL Riot redirects to after a browser login."""

        accessToken, tokenID = _extract_tokens_from_uri(redirect_url)
        entitlements_token = await self.get_entitlements_token(accessToken)

        return {'cookies': {'cookie': {}}, 'AccessToken': accessToken, 'token_id': tokenID, 'emt': entitlements_token}

    async def refresh_token(self, cookies: dict) -> tuple[dict[str, Any], str, str]:
        return await self.redeem_cookies(cookies)
