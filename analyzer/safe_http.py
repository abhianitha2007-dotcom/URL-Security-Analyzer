import threading

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


# =========================================================
# EXCEPTIONS
# =========================================================

class UnsafeTargetError(
    requests.RequestException
):
    """
    Raised when a URL or redirect target is unsafe
    or resolves to a non-public destination.
    """

    pass


# =========================================================
# SAFE REQUEST CLIENT
# =========================================================

class SafeRequests:
    """
    requests-compatible HTTP wrapper used by analyzers.

    Security protections:

        - validates public targets
        - blocks localhost/private targets
        - validates redirects
        - disables environment proxy inheritance
        - limits redirects
        - applies bounded timeouts

    Performance:

        persistent=True enables thread-local connection
        pooling.

        Each worker thread receives its own requests.Session,
        allowing TCP/TLS connections to be reused safely.

        Ordinary SafeRequests() instances remain temporary,
        which preserves compatibility with the automated
        security tests.
    """

    def __init__(
        self,
        persistent=False
    ):

        self.persistent = bool(
            persistent
        )

        self._thread_local = (
            threading.local()
        )


    # =====================================================
    # SESSION MANAGEMENT
    # =====================================================

    def _create_session(
        self
    ):
        """
        Create a hardened requests session.

        Real requests.Session objects receive configured
        connection pools.

        Lightweight test doubles may not implement mount(),
        so adapter configuration is applied only when that
        method exists.
        """

        session = requests.Session()


        # -------------------------------------------------
        # Disable environment proxy inheritance.
        #
        # Fake test sessions generally allow attribute
        # assignment, while real requests.Session objects
        # use this setting normally.
        # -------------------------------------------------

        try:

            session.trust_env = False

        except (
            AttributeError,
            TypeError
        ):

            pass


        # -------------------------------------------------
        # CONNECTION POOLING
        #
        # A real requests.Session supports mount().
        #
        # Our automated security tests replace Session()
        # with a lightweight FakeSession that intentionally
        # does not implement mount(), so this configuration
        # must remain optional.
        # -------------------------------------------------

        mount_method = getattr(
            session,
            "mount",
            None
        )


        if callable(
            mount_method
        ):

            adapter = (
                requests.adapters.HTTPAdapter(
                    pool_connections=20,
                    pool_maxsize=20,
                    max_retries=0
                )
            )


            mount_method(
                "http://",
                adapter
            )


            mount_method(
                "https://",
                adapter
            )


        return session


    def _get_session(
        self
    ):
        """
        Return:

            session,
            should_close

        Temporary SafeRequests instances create a new
        session per request.

        Persistent instances reuse one session per thread.
        """

        if not self.persistent:

            return (
                self._create_session(),
                True
            )


        session = getattr(
            self._thread_local,
            "session",
            None
        )


        if session is None:

            session = (
                self._create_session()
            )


            self._thread_local.session = (
                session
            )


        return (
            session,
            False
        )


    def close(
        self
    ):
        """
        Close the persistent session belonging to the
        current thread, if one exists.
        """

        session = getattr(
            self._thread_local,
            "session",
            None
        )


        if session is None:

            return


        try:

            close_method = getattr(
                session,
                "close",
                None
            )


            if callable(
                close_method
            ):

                close_method()


        finally:

            try:

                del self._thread_local.session

            except AttributeError:

                pass


    # =====================================================
    # MAIN REQUEST METHOD
    # =====================================================

    def request(
        self,
        method,
        url,
        **kwargs
    ):

        # -------------------------------------------------
        # METHOD VALIDATION
        # -------------------------------------------------

        if not isinstance(
            method,
            str
        ):

            raise ValueError(
                "HTTP method must be a string."
            )


        method = (
            method
            .upper()
            .strip()
        )


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

            max_redirects = (
                MAX_REDIRECTS
            )


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
        # CALLERS CANNOT PROVIDE PROXIES
        # -------------------------------------------------

        kwargs.pop(
            "proxies",
            None
        )


        # -------------------------------------------------
        # REQUEST STATE
        # -------------------------------------------------

        current_url = url

        current_method = method

        current_kwargs = dict(
            kwargs
        )

        redirect_history = []


        # -------------------------------------------------
        # GET HTTP SESSION
        # -------------------------------------------------

        (
            http_session,
            should_close
        ) = self._get_session()


        # -------------------------------------------------
        # COOKIE ISOLATION
        #
        # Shared analyzer sessions reuse TCP/TLS connections,
        # but cookies from previous independent analyzer
        # requests should not leak into later requests.
        # -------------------------------------------------

        if self.persistent:

            cookies = getattr(
                http_session,
                "cookies",
                None
            )


            if cookies is not None:

                clear_method = getattr(
                    cookies,
                    "clear",
                    None
                )


                if callable(
                    clear_method
                ):

                    try:

                        clear_method()

                    except (
                        AttributeError,
                        KeyError,
                        ValueError
                    ):

                        pass


        try:

            for redirect_number in range(
                max_redirects + 1
            ):

                # =========================================
                # SSRF VALIDATION
                #
                # Validate immediately before every actual
                # outbound request.
                # =========================================

                if not is_valid_url(
                    current_url
                ):

                    if redirect_history:

                        message = (
                            "Blocked redirect to unsafe "
                            "or non-public target: "
                            f"{current_url}"
                        )

                    else:

                        message = (
                            "Blocked unsafe or non-public "
                            "request target: "
                            f"{current_url}"
                        )


                    response = (
                        redirect_history[-1]
                        if redirect_history
                        else None
                    )


                    raise UnsafeTargetError(
                        message,
                        response=response
                    )


                # =========================================
                # SEND REQUEST
                # =========================================

                response = (
                    http_session.request(
                        current_method,
                        current_url,
                        allow_redirects=False,
                        timeout=timeout,
                        **current_kwargs
                    )
                )


                # -------------------------------------------------
                # Some test doubles expose history normally,
                # while real requests.Response objects support
                # assignment here.
                # -------------------------------------------------

                try:

                    response.history = list(
                        redirect_history
                    )

                except AttributeError:

                    pass


                # =========================================
                # REDIRECT FOLLOWING DISABLED
                # =========================================

                if not allow_redirects:

                    return response


                # =========================================
                # NORMAL RESPONSE
                # =========================================

                if (
                    response.status_code
                    not in REDIRECT_STATUS_CODES
                ):

                    return response


                # =========================================
                # REDIRECT LOCATION
                # =========================================

                location = (
                    response.headers.get(
                        "Location"
                    )
                )


                if not location:

                    return response


                # =========================================
                # REDIRECT LIMIT
                # =========================================

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


                # =========================================
                # BUILD REDIRECT URL
                # =========================================

                next_url = urljoin(
                    response.url
                    or current_url,
                    location
                )


                redirect_history.append(
                    response
                )


                # =========================================
                # MATCH NORMAL REDIRECT METHOD BEHAVIOUR
                # =========================================

                if (
                    response.status_code
                    == 303
                    and current_method
                    != "HEAD"
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
                    and current_method
                    == "POST"
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


                # -------------------------------------------------
                # The redirected URL will be validated at the
                # beginning of the next loop iteration before
                # another outbound connection is made.
                # -------------------------------------------------

                current_url = next_url


        finally:

            # -------------------------------------------------
            # Temporary clients preserve the original behaviour.
            #
            # Persistent clients retain their connection pool.
            # -------------------------------------------------

            if should_close:

                close_method = getattr(
                    http_session,
                    "close",
                    None
                )


                if callable(
                    close_method
                ):

                    close_method()


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


# =========================================================
# SHARED ANALYZER CLIENT
# =========================================================

# Analyzer modules import this shared object.
#
# Persistent mode allows a single thread to reuse TCP/TLS
# connections between analyzer modules.
#
# Thread-local storage also makes this compatible with the
# concurrency improvements we will add later.

safe_requests = SafeRequests(
    persistent=True
)