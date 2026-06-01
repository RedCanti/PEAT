from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

__all__ = ["inject_credentials"]


def inject_credentials(url: str, username: str | None, password: str | None) -> str:
    """
    Inject basic-auth credentials into a server URL's userinfo.

    This lets operators keep usernames and passwords in a (gitignored) PEAT
    config file or ``PEAT_*`` environment variables instead of embedding them
    in the ``--*-server`` URL, where shell quoting and percent-encoding of
    special characters is error-prone.

    Precedence: credentials already present in ``url`` always win. If ``url``
    already carries a ``user:pass@`` userinfo component, it is returned
    unchanged so that an explicit ``--*-server`` value is never overridden.

    The username and password are percent-encoded so that characters which are
    significant in a URL authority (``:@/?#[]`` etc.) survive intact; the
    Elasticsearch/OpenSearch client and ``requests`` both percent-decode the
    userinfo before use.

    Args:
        url: The server URL (e.g. ``https://so-manager:9200/``).
        username: Username to inject, or :obj:`None`/empty to leave ``url`` as-is.
        password: Password to inject. May be :obj:`None` (username only).

    Returns:
        The URL with credentials injected into its userinfo, or the original
        ``url`` unchanged when ``username`` is falsy or ``url`` already has
        credentials.
    """
    if not username:
        return url

    parts = urlsplit(url)
    # Explicit credentials in the URL win over configured ones.
    if "@" in parts.netloc:
        return url

    userinfo = quote(username, safe="")
    if password is not None:
        userinfo += ":" + quote(password, safe="")

    new_netloc = f"{userinfo}@{parts.netloc}"
    return urlunsplit((parts.scheme, new_netloc, parts.path, parts.query, parts.fragment))
