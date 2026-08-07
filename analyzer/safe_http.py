import requests

from urllib.parse import urljoin

from analyzer.url_validator import is_valid_url


# =========================================================
# SAFE HTTP REQUEST LAYER
# =========================================================

DEFAULT_TIMEOUT = (
    5,
    10
)

MAX_REDIRECTS = 5

REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308
}


class UnsafeTargetError(
    requests.RequestException
):
    """
    Raised when a request or redirect target is not
    suitable for public URL scanning.
    """

    pass


class SafeRequests:
    """
    Small requests-compatible wrapper used by analyzer
    modules that contact user-controlled URLs.

    Security goals:
        - validate the initial target
        - disable environment proxy inheritance
        - disable automatic redirects
        - validate every redirect destination
        - block redirects to localhost/private networks
        - limit redirect depth
        - use bounded connection/read timeouts

    Existing analyzer code can use:

        safe_requests.get(...)
        safe_requests.post(...)
        safe_requests.head(...)
        safe_requests.options(...)
        safe_requests.request(...)
    """

    def request(
        self,
        method,
        url,
        **kwargs
    ):

        if not isinstance(
            method,
            str
        ):

            raise ValueError(
                "HTTP method must be a string."
            )


        method = method.upper().strip()


        if not method:

            raise ValueError(
                "HTTP method cannot be empty."
            )


        # -------------------------------------------------
        # REDIRECT SETTINGS
        # -------------------------------------------------

        allow_redirects = kwargs.pop(
            "allow_redirects",
            True
        )


        max_redirects = kwargs.pop(
            "max_redirects",
            MAX_REDIRECTS
        )


        try:

            max_redirects = int(
                max_redirects
            )

        except (
            TypeError,
            ValueError
        ):

            max_redirects = MAX_REDIRECTS


        max_redirects = max(
            0,
            min(
                max_redirects,
                10
            )
        )


        # -------------------------------------------------
        # TIMEOUT
        # -------------------------------------------------

        timeout = kwargs.pop(
            "timeout",
            DEFAULT_TIMEOUT
        )


        if timeout is None:

            timeout = DEFAULT_TIMEOUT


        # -------------------------------------------------
        # DO NOT ALLOW CALLERS TO SUPPLY PROXY ROUTES
        # -------------------------------------------------

        kwargs.pop(
            "proxies",
            None
        )


        # -------------------------------------------------
        # INITIAL TARGET VALIDATION
        # -------------------------------------------------

        if not is_valid_url(
            url
        ):

            raise UnsafeTargetError(
                (
                    "Blocked unsafe or non-public "
                    f"request target: {url}"
                )
            )


        current_url = url

        current_method = method

        current_kwargs = dict(
            kwargs
        )

        redirect_history = []


        # -------------------------------------------------
        # SESSION
        #
        # trust_env=False prevents HTTP_PROXY / HTTPS_PROXY
        # environment variables from silently routing the
        # scanner through another network endpoint.
        # -------------------------------------------------

        http_session = requests.Session()

        http_session.trust_env = False


        try:

            for redirect_number in range(
                max_redirects + 1
            ):

                # Revalidate immediately before every hop.

                if not is_valid_url(
                    current_url
                ):

                    raise UnsafeTargetError(
                        (
                            "Blocked unsafe or non-public "
                            f"request target: {current_url}"
                        )
                    )


                response = http_session.request(
                    current_method,
                    current_url,
                    allow_redirects=False,
                    timeout=timeout,
                    **current_kwargs
                )


                response.history = list(
                    redirect_history
                )


                # -----------------------------------------
                # RETURN WHEN REDIRECT FOLLOWING IS OFF
                # -----------------------------------------

                if not allow_redirects:

                    return response


                # -----------------------------------------
                # NOT A REDIRECT
                # -----------------------------------------

                if (
                    response.status_code
                    not in REDIRECT_STATUS_CODES
                ):

                    return response


                location = response.headers.get(
                    "Location"
                )


                if not location:

                    return response


                # -----------------------------------------
                # REDIRECT LIMIT
                # -----------------------------------------

                if (
                    redirect_number
                    >= max_redirects
                ):

                    raise requests.TooManyRedirects(
                        (
                            "Too many redirects while "
                            f"requesting {url}"
                        ),
                        response=response
                    )


                # -----------------------------------------
                # BUILD NEXT URL
                #
                # Supports both absolute and relative
                # Location headers.
                # -----------------------------------------

                next_url = urljoin(
                    response.url
                    or current_url,
                    location
                )


                # -----------------------------------------
                # VALIDATE REDIRECT DESTINATION BEFORE
                # SENDING THE NEXT REQUEST.
                # -----------------------------------------

                if not is_valid_url(
                    next_url
                ):

                    raise UnsafeTargetError(
                        (
                            "Blocked redirect to unsafe "
                            f"or non-public target: {next_url}"
                        ),
                        response=response
                    )


                redirect_history.append(
                    response
                )


                # -----------------------------------------
                # MATCH NORMAL BROWSER / requests
                # REDIRECT METHOD BEHAVIOUR.
                # -----------------------------------------

                if (
                    response.status_code == 303
                    and current_method != "HEAD"
                ):

                    current_method = "GET"

                    current_kwargs.pop(
                        "data",
                        None
                    )

                    current_kwargs.pop(
                        "json",
                        None
                    )


                elif (
                    response.status_code
                    in {
                        301,
                        302
                    }
                    and current_method == "POST"
                ):

                    current_method = "GET"

                    current_kwargs.pop(
                        "data",
                        None
                    )

                    current_kwargs.pop(
                        "json",
                        None
                    )


                current_url = next_url


        finally:

            http_session.close()


    # =====================================================
    # REQUESTS-COMPATIBLE SHORTCUTS
    # =====================================================

    def get(
        self,
        url,
        **kwargs
    ):

        return self.request(
            "GET",
            url,
            **kwargs
        )


    def post(
        self,
        url,
        **kwargs
    ):

        return self.request(
            "POST",
            url,
            **kwargs
        )


    def head(
        self,
        url,
        **kwargs
    ):

        return self.request(
            "HEAD",
            url,
            **kwargs
        )


    def options(
        self,
        url,
        **kwargs
    ):

        return self.request(
            "OPTIONS",
            url,
            **kwargs
        )


# Shared wrapper instance used throughout analyzer modules.
safe_requests = SafeRequests()