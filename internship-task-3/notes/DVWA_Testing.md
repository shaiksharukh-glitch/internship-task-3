OWASP stands for Open Web Application Security Project.

OWASP is a global nonprofit organization focused on improving the security of software. It provides free resources, tools, and best practices for developers and security professionals to identify, prevent, and fix vulnerabilities in web applications.

One of its most well-known contributions is the ‘OWASP Top 10,’ which is a list of the 10 most critical web application security risks, like SQL Injection, Cross-Site Scripting (XSS), and Broken Authentication. It serves as a guideline to help developers and security teams secure applications against common threats.”**

DVWA (Damn Vulnerable Web Application)

What is DVWA?

DVWA is an intentionally vulnerable web application designed for learning web security.

Key points:
Written in PHP and uses MySQL / MariaDB for data storage.
Allows users to practice common web vulnerabilities safely.
Great for beginners/intermediate students to understand attacks without harming real systems.
Supports various security levels: low, medium, high, impossible.
Purpose of DVWA

DVWA exists for educational and training purposes:

Learning by doing: Instead of just reading about vulnerabilities, you actually exploit them.
Safe environment: You won’t damage live systems or databases.
Understanding OWASP Top 10: DVWA has examples of multiple vulnerabilities like:
SQL Injection (SQLi)
Cross-Site Scripting (XSS)
CSRF (Cross-Site Request Forgery)
File Inclusion
Command Execution
Weak passwords / authentication flaws
Mitigation testing: You can see how security mechanisms (like prepared statements, input validation, and headers) stop attacks.
Security Levels in DVWA

DVWA allows you to change security settings:

Level Behavior - Low No input filtering → attacks work easily (good for learning) - Medium Some input validation & escaping → attacks need tweaking - High Proper security → attacks harder or blocked - Impossible Security cannot be bypassed → shows how a fully secure system behaves

Example Vulnerabilities in DVWA

SQL Injection (SQLi)
User input is directly added into SQL queries.
Example: SELECT * FROM users WHERE id='$id';
Vulnerable if $id comes from GET/POST without validation.
Attackers can retrieve usernames/passwords.
Cross-Site Scripting (XSS)
Injecting malicious scripts in forms/comments.
Can steal cookies or redirect users.
CSRF (Cross-Site Request Forgery)
Tricks logged-in users into performing actions without consent.
DVWA demonstrates this by changing passwords via hidden forms.
File Inclusion
LFI/RFI allows reading or executing server files.
Commonly used to steal configs or run malicious code.
How DVWA Works

User accesses a page (e.g., SQLi page).
The page takes user input (like id) and builds an SQL query.
If the input isn’t sanitized:
SQLi can extract data from the DB.
XSS can inject scripts.
By switching security levels:
Low → vulnerable
High → input is filtered / prepared statements are used
You can test attacks, then implement fixes → demonstrates vulnerability → mitigation.
Command	Purpose	Notes
nano filename	Opens an existing file (or creates it if it doesn’t exist) in a text editor so you can manually edit it.	You type inside the editor, save with Ctrl+O and exit with Ctrl+X.
tee filename	Creates a new file (or overwrites an existing file) and writes content to it from standard input.	Often used with <<'EOF' ... EOF (heredoc) to create files programmatically without opening an editor. > /dev/null is added if you don’t want to display the content in the terminal while creating it.
STEP 1: SQL Injection

What is SQL Injection (SQLi)?
Definition:
SQL Injection is a vulnerability where an attacker can manipulate a web application’s SQL queries by injecting malicious input.
Why it happens:
When user input is directly inserted into SQL queries without validation or escaping.
The database executes whatever the input modifies the query to do.
Real-world example (without DVWA):
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE user_id = '$id'";
If a user enters 1 → query works normally.
If a user enters 1 OR 1=1 → query becomes:
SELECT * FROM users WHERE user_id = '1' OR 1=1;
1=1 is always true → returns all rows in the database.
Danger:
Attackers can read sensitive data, modify/delete records, or even compromise the system.
Why DVWA is Safe for SQLi
Localhost Only:
DVWA runs on 127.0.0.1 (your own machine).
No internet exposure → only you can access it.
Dedicated Database User:
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa_pass';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
SQLi can only affect the dvwa database.
Root DB and OS files are safe.
Resettable Environment:
setup.php → Create / Reset Database resets the database anytime.
DVWA Security Levels

Low: No filtering → SQLi works easily.
Medium/High/Impossible:
Adds input validation, escaping, or prepared statements.
Helps demonstrate how proper coding prevents attacks.
Why Low:
It allows you to see the vulnerability in action.
Learning first in low helps understand the mechanics of SQLi.
Performing SQLi in DVWA

Steps:
Go to the SQL Injection page:
http://127.0.0.1/DVWA/vulnerabilities/sqli/
Input box ID takes user input. Example: 1 OR 1=1
The PHP page executes the query:
$query = "SELECT first_name, last_name, user_id FROM users WHERE user_id = '$id'";
Our input manipulates the query to:
SELECT first_name, last_name, user_id FROM users WHERE user_id = '1' OR 1=1;
OR 1=1 always evaluates to true → all users are returned.
Output: You see multiple usernames and passwords on the page.
Demonstrating the Fix (Prepared Statements)

Prepared statements separate query structure from user input:
$stmt = $db->prepare("SELECT * FROM users WHERE user_id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
? is a placeholder; $id is bound safely.
Even if the user enters '1 OR 1=1', the database treats it as a literal value, not part of SQL.
It only provides the first id as output.
Result: Injection fails → only correct user_id rows are returned.
STEP 2- Cross-Site Scripting (XSS)

What is XSS?

Cross-Site Scripting (XSS) is a class of web vulnerability where an attacker is able to inject client-side scripts (usually JavaScript) into pages viewed by other users. When the victim’s browser executes the injected script, the attacker can do things like steal session cookies, manipulate the DOM, perform actions as the user, show fake UI, etc.

Two common types you’ll test

Stored (Persistent) XSS

How it works: Attacker submits malicious script into a site input (comment, profile, message) that the server stores in the database. When any user later views that stored data, the script runs in their browser.
Impact: Broad — any user who views the page can be affected; can be used to steal cookies, perform actions, pivot.
Consequences of Stored XSS include:
Redirecting users to malicious sites
Stealing cookies or session tokens
Defacing the website
Performing actions on behalf of other users
Commands
Open DVWA and navigate to Stored XSS page:
Enter malicious payload in the Guestbook form:
Name: Bhagyalaxmi
Message: 
Click Sign Guestbook
Output
The page reloads and shows the guestbook entries.
A popup with 2 appears — this confirms that the browser executed the injected script.
When any user loads that page, the malicious code executes in their browser.
In our lab, the popup 2 is just a safe demonstration — it proves that the input was executed as code instead of being treated as plain text.
In real life, a hacker could replace alert(2) with something harmful: stealing cookies, logging keystrokes, redirecting the user, etc.
Reflected (Non-persistent) XSS

How it works: The server reflects attacker-controlled input immediately in a response (e.g., search term shown in results or a name parameter echoed back), without storing it. The attacker crafts a URL containing the payload and convinces a victim to click it.
Impact: Targeted — requires tricking a victim (phishing link), but still very dangerous.
Consequences include:
Stealing cookies/session tokens
Phishing attacks
Redirection to malicious websites
Commands:
Open DVWA and navigate to Reflected XSS page
Your name: <script>alert('Reflected XSS Mallicious Content')</script>
Output:
The input was reflected directly in the page response.
The browser executed it as JavaScript, producing the alert popup.
This demonstrates a Reflected XSS vulnerability, showing that any user who clicks the link could trigger the script.
Attackers exploit it via malicious links in emails, social media, or phishing pages.
Why it happens

The app outputs user data (from query string, form fields, DB) into HTML without escaping/encoding it.
Browsers parse the HTML and run any script tags, event handlers, onerror, etc.
How to prevent XSS (two main techniques we’ll demonstrate)

Input Sanitization / input validation (server-side)/ WhiteListing:

Checking and restricting what users can input before it goes to the database or page.Restrict what users can input. Example: allow only letters/numbers for a name field. Remove or encode HTML special characters (<, >, &, ", '). This ensures scripts are displayed as text, not executed.Malicious users often inject scripts via form fields. If we restrict inputs to safe characters, scripts cannot execute.Displayed as text, not executed.
Output Encoding / Escaping

Even if user input contains HTML or scripts, encode it before rendering on the page. Prevents browser from interpreting input as executable code. Use htmlspecialchars (PHP) , HTMLEncode() (other languages),or template auto-escaping to render user data as text, not as HTML. Prefer the output encoding model (escape on output). Encode user data before rendering it on a page.Any injected script is shown as text, popup doesn’t appear.
Content Security Policy (CSP):

A browser-enforced rule that restricts what resources (scripts, images, CSS) can run on your site. Browser policy delivered via headers that restrict which scripts can execute (e.g., only scripts from the same origin, disallow inline scripts). CSP is defense-in-depth — it mitigates impact even if something slips through. Even if a malicious script is injected, CSP can block execution.
Desc- I implemented a nonce-based Content Security Policy to allow a single trusted inline script while blocking arbitrary injected inline scripts. csp_nonce_demo.php issues a per-response nonce in the Content-Security-Policy header and includes a matching nonce attribute on an inline <script>. The trusted inline script executed successfully (see csp_demo_output.png). The response header containing the nonce is shown in csp_demo_header_code.png. When an injected script without the correct nonce was added dynamically via the console, the browser blocked it and logged a CSP violation (see csp_demo_console_block.png). This proves nonce-based CSP permits only explicitly trusted inline scripts and prevents execution of injected code.
STEP 3- Cross-Site Request Forgery (CSRF)

CSRF (Cross-Site Request Forgery) is a type of web security vulnerability. It tricks a logged-in user into unknowingly performing actions on a website (like changing their password, transferring money, deleting an account) without their consent.

How it Works (Simple Example)
You are logged in to DVWA (or any site) in one tab.
The site uses your session cookie to know you are authenticated.
Attacker sends you a malicious link or form.
Example:
<script>document.forms[0].submit();</script>
If you are still logged in, this request will change your password without you knowing.
Why is it Dangerous?
No user interaction needed except clicking/opening attacker’s page.
Works silently because cookies are sent automatically by the browser.
Can lead to account takeover.
How to Prevent (Mitigation)
The most common protection is CSRF Token (anti-CSRF token):
Website generates a random unique token for each form request.
The token is stored in the user’s session.
When form is submitted, the token is validated.
If token is missing/wrong → request is blocked.
In short:
CSRF = Attacker tricks logged-in user to perform actions without consent.
Why used in labs like DVWA? → To practice how an attacker can exploit it and how a developer prevents it.
Protection = CSRF Tokens (sometimes combined with SameSite cookies).
Result
PoC (vulnerable): While logged in as admin, I hosted a malicious page csrf_exploit.html that auto-submits a GET form to DVWA’s password-change endpoint (/DVWA/vulnerabilities/csrf/) with password_new=hacked123. Visiting the exploit page caused the admin password to be changed to hacked123.and logging in with admin/hacked123 succeeded. This proves the CSRF exploit changed the admin password and resulted in account takeover.
Mitigation (token based): I switched DVWA Security to High, which added a per-session hidden token to the CSRF form (e.g. ). Re-running the same exploit (which lacks the token) produced a rejected request shown in Network/Response . This demonstrates token-based CSRF protection — the attacker cannot know the per-session token and therefore cannot craft a valid request.Thus, tested by switching DVWA security to High, after which the same exploit is rejected.
STEP 4- File Inclusion Attacks

File Inclusion vulnerabilities occur when a web application constructs filesystem or URL include paths using untrusted user input and then performs a dynamic include/require (or equivalent).

Two main flavors:

Local File Inclusion LFI (read sensitive files).

attacker causes the server to include a file from the local filesystem reading sensitive local files (/etc/passwd, /etc/hosts, /etc/hostname).
A vulnerability where user input is used (unsafely) to construct a local filesystem path that is included by the application (e.g., PHP include($page)), allowing an attacker to read server-side files.
Demo php: $file = $_GET['page']; include($file);
Remote File Inclusion RFI (execute malicious code).

attacker causes the server to include and execute a remote resource (including attacker-controlled PHP (demo via test_include.php and a webroot rfi_demo.php).
RFI requires server-side support for including remote URLs (PHP allow_url_include).
RFI requires additional PHP settings; allow_url_include = Off prevents direct RFI.
allow_url_include = Off prevented direct remote http:// RFI on this host; log-poisoning and local file. inclusion were explored.
Including a locally created PHP file (/var/www/html/test_include.php) via the vulnerable page parameter executed code as www-data — demonstrating LFI leading to code execution. allow_url_include remained Off, so I Indirect RFI was performed.
Log-Poisoning (LFI → RCE vector)
Definition: An exploitation technique where an attacker injects PHP code into server-writable artifacts (access log, error log, upload entries, session files) and then uses LFI to include and execute that log, resulting in RCE.
curl -s -A '' "http://127.0.0.1/DVWA/"
sudo tail -n 40 /var/log/apache2/access.log
include the log (logged-in session required):
http://127.0.0.1/DVWA/vulnerabilities/fi/?page=/var/log/apache2/access.log&cmd=id
Causes

Unsanitized user input used directly in include, require, or file access APIs.
Overly permissive server/PHP settings: e.g., allow_url_include = On, weak open_basedir or world-readable config/log files.
Poor design: dynamically including files by raw name or path supplied by user instead of mapping tokens to known resources.
Typical vulnerable code pattern (PHP example)

// Vulnerable: directly includes whatever the user supplies
$page = $_GET['page']; include($page);
This lets an attacker control what include() tries to open/include.
Execution Steps

A. LFI — file reads
/etc/passwd — classic proof (world-readable), shows web user/home directories.
/etc/hosts & /etc/hostname — low-risk proofs that show host identity.
php://filter/convert.base64-encode/resource=/path/to/file.php — retrieve PHP source without executing it (base64 output decoded locally).
What this proves: The application can read arbitrary files via the page parameter → Information disclosure.
B. Include execution (code exec proof)
Created /var/www/html/test_include.php containing echo + environment info (PHP version, get_current_user(), getmyuid(), getcwd()).
Included via DVWA: http://127.0.0.1/DVWA/vulnerabilities/fi/?page=/var/www/html/test_include.php
Output showed Current user: www-data and environment details.
What this proves: The app executes included PHP code as the webserver user — a direct path to code execution if an attacker can place PHP code into an includable location.
STEP 5- Burp Suite Advanced

Burp Suite is an integrated platform for testing web application security. Its core components (Proxy, Repeater, Intruder, Scanner, Decoder, Sequencer, Comparer, and Extender) let you intercept, manipulate, and automate HTTP(S) traffic to discover and verify vulnerabilities.
In this section we focus on two common, high-value activities:
Intercepting & modifying login requests (manual testing & fault-injection)
Fuzzing with Intruder (automated parameter testing / brute force / payload permutation)
These techniques are essential to assess authentication weaknesses, CSRF/token handling, input validation, and brute-force resistance. Use them only in authorized, lab or pentest engagements.
Intercepting & Modifying Login Requests
What it is
Intercepting is the act of capturing HTTP(S) requests and responses between your browser and the target server using Burp Proxy. Modifying a login request means editing the captured request (headers, body, cookies, tokens) before forwarding it to the server to observe how the server responds to tampered input.
Why it matters
Login is a security-critical function. Manipulating login requests lets you test:
Credential validation logic (weak checks, SQLi, canonicalization issues).
CSRF protections (missing or mis-validated tokens).
Session handling (cookie creation, session fixation).
Header handling (injection into logs, user-agent, referer).
Rate-limiting and brute‑force defenses (how server responds to rapid retries).
Key components & flow
Browser → Burp Proxy → Server: Burp acts as a man-in-the-middle (MITM).
Intercept ON: Burp holds the request until you forward or drop it.
Modify: Edit username/password, hidden fields (tokens), or headers and forward to server.
Response analysis: Check status code, headers (Location, Set-Cookie), body content, and timing differences to infer success/failure.
Typical manipulations and objectives
Change credentials: Test for authentication bypass or weak checks.
SQL injection attempts in username/password fields: detect unsanitized DB queries.
Remove/alter CSRF token: verify server rejects/accepts the request without a valid token.
Header injection: put payloads in User-Agent or Referer to test log-poisoning vectors.
Cookie tampering: modify session cookies to test for predictable session IDs or privilege escalation.
What to look for in responses
302 redirect to dashboard + Set-Cookie → likely successful login.
200 OK with login form → likely failed authentication.
Different response body length or text (e.g., presence of “Logout”, “Welcome”) → indicate success.
Errors or stack traces → input triggered server error (sensitive info leak).
Ethical considerations
Intercepting/modifying requests is intrusive — do it only on systems you own or have permission to test.
Mask or avoid capturing real users’ credentials in shared artifacts.
2 — Burp Intruder — Theory & Attack Types

What Intruder does
Intruder automates customized HTTP request modifications and sends many variations to the server. It is used for credential guessing, parameter fuzzing, payload enumeration, and discovering logic flaws.
Attack modes (how to choose)
Sniper — single payload position; test many payloads against one parameter (e.g., fuzz only password). Good for focused brute-force or single-parameter fuzzing.
Battering Ram — same payload applied to all marked positions (rare for login).
Pitchfork — multiple payload sets used in parallel (index-aligned); good when you have matched username/password lists.
Cluster Bomb — Cartesian product of multiple payload sets (exhaustive combinations); powerful but resource-intensive.
Components of an Intruder attack
Positions — request parts you mark for substitution (form fields, headers, cookies).
Payload sets — lists of values to inject into each position (wordlists, generated payloads).
Payload processing — transformations, encodings, or insertion of runtime tokens.
Grep/Match rules — text or header patterns used to detect interesting responses (e.g., redirect header, “Welcome” text).
Options — throttle rates, thread counts, timeouts, and success-detection configuration.
Practical payload types
Credential lists (usernames/passwords).
SQLi probes (' OR '1'='1, UNION SELECT ...).
XSS payloads (for testing reflected contexts).
Boundary/format tests (long strings, format strings).
Headers with suspicious content (to test log injection).
Detecting successful results
Header checks: Location redirect to a dashboard URL.
Body checks: presence of dashboard-specific tokens (Welcome, Logout).
Response length: unusually large/small responses compared to baseline.
Set-Cookie: new session or privilege cookie.
Configure Intruder’s Grep - Match to highlight responses that meet these criteria.
CSRF & dynamic tokens — a practical caveat
Many login flows include a CSRF token (user_token) which changes every session. Intruder replaying the same request will fail if the token is stale.
Solutions:
Manually refresh token before runs (small lists).
Use Burp Pro’s Session Handling Rules and macros to fetch a fresh token per request.
For demos, use a logged-in browser cookie jar or small automated flows.
Resource & rate considerations
Intruder sends many requests — be mindful of target stability and local resource limits.
Use throttling and small lists for demonstrations; never run high-volume attacks against production systems.
3 — Practical Attack Scenarios (theory → example)

Scenario A — Test password strength for known user
Mode: Sniper on password field.
Payloads: small password list.
Detection: Location header or body contains “Logout”.
Purpose: demonstrate brute-force risk and justify rate limiting/MFA.
Scenario B — Username enumeration
Mode: Sniper or Pitchfork (if testing username/password pairs).
Payloads: common usernames.
Detection: differences in response time or body indicating existence of account.
Scenario C — Token manipulation to test CSRF
Intercept login: remove or change hidden token.
Expected: server rejects login / returns error.
Purpose: verify server implements CSRF protections.
Scenario D — Header/log injection test
Modify User-Agent to include <?php or suspicious string.
If server logs headers verbatim and LFI exists, this could be later used for log-poisoning → RCE.
4 — Defenses & Mitigations

For login/authentication
Enforce strong password policy, account lockout, rate limits, and progressive delays.
Implement MFA.
Use secure session handling (HttpOnly, Secure, SameSite; regenerate session ID on login).
Do not leak detailed error messages on authentication failure (avoid “user does not exist” vs “wrong password”).
For CSRF & token handling
Use per-session/per-form CSRF tokens bound to session and validated server-side.
Use SameSite cookies and include CSRF checks on all state-changing endpoints.
For log-injection and input handling
Sanitize and encode headers and inputs written to logs; avoid storing raw user-controlled content if it may later be executed.
Harden logging directories and file permissions to reduce risk of inclusion.
For intrusion detection
Monitor for repeated failed login attempts, unusual headers, or high request rates.
Use WAF rules to block common fuzzing signatures and high-frequency attacks.
Only run these tests against systems you control or have explicit permission to test.
Keep credential & session data private. For public reports, redact session IDs and any sensitive data.
5- Implementation

Intercepting & modifying HTTP requests
Intercepting means capturing an HTTP(S) request between the client and server, inspecting the raw request, changing fields (headers, cookies, POST body) and forwarding the modified request to observe server behavior. This is used in web security testing to validate authentication, session management, input validation, and to simulate tampering attacks. Interception is typically performed via a proxy (Burp Suite Proxy) which the client routes traffic through; Burp pauses requests (Intercept) so the tester can edit them before forwarding.
Important HTTP parts used here
Request line & path: POST /DVWA/login.php HTTP/1.1 — target resource and method.
Headers: Host, Cookie, Content-Type — control routing, session, and content interpretation.
Body (form data): username=...&password=...&user_token=... — parameters that the server uses to authenticate.
CSRF token (user_token): a hidden field used to prevent Cross-Site Request Forgery; must be included/valid in the POST.
Session cookie (PHPSESSID): identifies the user session; necessary to link the login POST to the correct session state.
Intruder
Burp Intruder automates parameter fuzzing and brute-force style attacks: you mark positions (e.g., password), supply a payload list, and Intruder substitutes payloads at positions and records responses (status, length, body). Differences in response behavior reveal interesting inputs (e.g., successful login, error messages).
How to detect “success” during fuzzing Look for differences in HTTP status (302 redirect on login success vs 200/400 on failure), response length changes, presence of keywords in body (“Welcome”, username), or headers like Location:.
Task: Intercept and modify login requests; Perform fuzzing with Intruder tool.
Method: Fetched DVWA login page to obtain CSRF token and session cookie. Constructed a raw POST request inside Burp (target: POST /DVWA/login.php) and marked the password parameter for injection. Used Burp Intruder with a small payload list (/tmp/mini_wl.txt) to fuzz the password parameter and observed differing responses (Status 302 & Length 533 vs Status 400 & Length 483). Used Burp Repeater to manually edit and resend login requests to demonstrate intercept-and-modify. Screenshots attached: Intruder results table, Intruder response preview, Repeater request/response.
STEP 6- Web Security Headers

Web security headers are HTTP response headers that tell the browser how to behave when interacting with a website.They protect websites from common attacks such as:
Cross-Site Scripting (XSS) , Clickjacking , MIME type sniffing , Information leaks, Unauthorized access to device APIs
Using proper security headers is a simple yet powerful way to improve a site’s security posture.
Task:
Analyze a test site using https://securityheaders.com
Identify missing headers
Add proper HTTP headers in Apache configuration
Verify headers are correctly applied
Test site used: Local DVWA (http://127.0.0.1/DVWA/)
Commands and Steps
Step 1 – Enable Apache headers module
sudo a2enmod headers (a2enmod headers → enables the module.)
sudo systemctl reload apache2 (reload apache2 → applies changes without restarting the server)
Purpose: Apache requires mod_headers to add custom headers.
Step 2 – Backup Apache vhost
sudo cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf.bak
Purpose: Always backup configuration files before editing.If anything goes wrong, you can restore the backup.
Step 3 – Add security headers in Apache vhost
Edit the default vhost: sudo nano /etc/apache2/sites-available/000-default.conf
Inside <VirtualHost *:80>, add:
=== Security Headers (for DVWA testing) ===
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
=== Content-Security-Policy in Report-Only mode to avoid breaking DVWA ===
Header always set Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self';"
=== HSTS only if HTTPS is enabled ===
=== Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains" ===
=== End security headers ===
Theory Behind Each Header
X-Content-Type-Options: nosniff
Prevents the browser from interpreting files as a different MIME type than declared.
Protects against attacks where a malicious file is served with wrong type.
X-Frame-Options: SAMEORIGIN
Prevents your site from being embedded in an iframe on another domain.
Mitigates clickjacking, where attackers trick users into clicking hidden buttons.
Referrer-Policy: strict-origin-when-cross-origin
Controls what information is sent in the Referer header.
Limits sensitive data leakage to external sites.
Permissions-Policy
Restricts access to browser APIs like camera, microphone, geolocation.
Minimizes attack surface for malicious scripts.
Content-Security-Policy-Report-Only
Restricts where scripts, styles, images can load from (self, inline, eval).
Protects against XSS, malicious scripts, data injection.
Report-Only mode logs violations without blocking, good for testing.
Strict-Transport-Security
Forces HTTPS connections for a period (max-age) and all subdomains.
Protects against downgrade attacks and ensures encrypted traffic.
Step 4- Test Apache configuration
sudo apachectl configtest (configtest → checks syntax.)
Expected output: Syntax OK (you might see a warning about ServerName; it’s safe).
sudo systemctl reload apache2 (reload → applies the new headers.)
Step 5- Verify headers.
Command used:
curl -I http://127.0.0.1/DVWA/ | grep -i 'X-Content-Type-Options|X-Frame-Options|Referrer-Policy|Permissions-Policy|Content-Security-Policy|Strict-Transport-Security'
Explanation:curl -I → fetch only headers. grep -i → filter headers we care about.
Output should show all headers we added:
Strict-Transport-Security will appear only if DVWA uses HTTPS.
CSP is in Report-Only mode for DVWA so the site doesn’t break.
HSTS works only over HTTPS, so leave commented on HTTP.
Step 6- Result - All required headers are applied to DVWA. Verified locally via curl.
