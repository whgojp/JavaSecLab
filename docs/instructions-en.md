# Common Vulnerabilities

## Cross-Site Scripting
The current coverage includes reflected XSS, stored XSS, DOM XSS, unsafe rendering in template engines, stored XSS caused by file uploads, XSS in third-party components, WebSocket XSS, postMessage XSS, CSP, HttpOnly, output encoding, and other common scenarios.

The essence of XSS is that untrusted data reaches a browser execution context and is parsed as HTML, script, URL, or executable DOM operations. The preferred fix is to handle data according to the output context: use HTML entity encoding or safe DOM APIs for plain text, and use the corresponding encoding and allowlist validation for URLs, attributes, JavaScript, CSS, and similar locations. CSP, HttpOnly, and input filtering are auxiliary defenses and cannot replace fixing the root cause.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| Reflected XSS | GET/POST parameters, direct String output, Content-Type differences | Covers the basic cause where the request itself triggers the issue and the response type affects browser parsing |
| Reflected safe patterns | Front-end and back-end allowlists, CSP, HTML body output encoding, HttpOnly | Covers common defenses and makes clear that allowlists, CSP, and HttpOnly are not root-cause fixes |
| Stored XSS | Form content, persisted User-Agent, unsafe table rendering | Covers store-first-then-trigger behavior, including header data entering a persistence chain |
| Stored safe patterns | Output encoding during table rendering | Explains that the database may store the raw value, but the page must encode or sanitize it according to context before rendering |
| DOM XSS | innerHTML, localStorage, hash redirects, location, eval, document.write | Covers common source-to-sink client-side chains |
| DOM safe patterns | textContent, URL protocol allowlist, command mapping, createTextNode | Covers recommended DOM-side fixes |
| Other scenarios | Thymeleaf `th:utext`, file upload, jQuery/Swagger/UEditor, WebSocket, postMessage | Covers template, file, supply-chain, and HTML5 communication scenarios |

### Reflected XSS Tests

Page: `/xss/reflect/vul`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| GET JSON response | `GET /xss/reflect/vul1?payload=<img src=x onerror=alert(1)>` | HTML event payload | The interface returns the payload; if the page result area renders HTML unsafely, it can trigger |
| POST JSON response | `POST /xss/reflect/vul1` | `payload=<img src=x onerror=alert(1)>` | The interface returns the payload; verifies that the POST entry is also controllable |
| Direct String output | `GET /xss/reflect/vul2?payload=<script>alert(1)</script>` | Script tag | The response body contains the payload directly, used to observe browser parsing behavior |
| text/plain | `GET /xss/reflect/vul3?type=plain&payload=<script>alert(1)</script>` | Script tag | `Content-Type` is `text/plain;charset=utf-8`, so the browser displays it as text |
| text/html | `GET /xss/reflect/vul3?type=html&payload=<script>alert(1)</script>` | Script tag | `Content-Type` is `text/html;charset=utf-8`, so the browser parses it as HTML |
| Traffic sample / example payloads | Page dropdowns and buttons | Tag probing, traffic hijacking, cookie reading, page tampering | Example values can be filled in and buttons can submit them |

### Reflected XSS Safe Scenario Tests

Page: `/xss/reflect/safe`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Front-end allowlist | `GET /xss/reflect/safe1?type=frontEnd&payload=<script>alert(1)</script>` | Non-allowlisted characters | The front-end blocks it when the page button is used; a direct request still returns, showing that the front end is not a security boundary |
| Back-end allowlist | `GET /xss/reflect/safe1?type=backEnd&payload=<script>alert(1)</script>` | Non-allowlisted characters | Returns "The input contains illegal characters, please check your input" |
| CSP Header | `GET /xss/reflect/safe2?payload=<script>alert(1)</script>` | Script tag | The response includes `Content-Security-Policy`, used to demonstrate a defensive layer |
| Manual HTML body encoding | `GET /xss/reflect/safe3?type=manual&payload=<img src=x onerror=alert(1)>` | HTML event payload | Returns entity-encoded content and does not execute as a tag |
| Spring HTML encoding | `GET /xss/reflect/safe3?type=spring&payload=<img src=x onerror=alert(1)>` | HTML event payload | Returns Spring-encoded content |
| HttpOnly | `GET /xss/reflect/safe4?payload=<script>alert(document.cookie)</script>` | Cookie-reading payload | Returns the configuration result, and the `Set-Cookie` response should include `HttpOnly` |

### Stored XSS Tests

Page: `/xss/store`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Native write | `POST /xss/store/vul` | `payload=<img src=x onerror=alert(1)>` | Write succeeds; the vulnerability table can trigger if rendered unsafely |
| User-Agent persistence | `POST /xss/store/vul` | Header `User-Agent: <img src=x onerror=alert(1)>` | The UA field is persisted; the vulnerability table can trigger if rendered unsafely |
| List query | `GET /xss/store/getXssList?page=1&limit=10` | None | Returns paginated data including the just-written record |
| Safe table | Safe scenario table on the page | Stored malicious content | Content and User-Agent are shown with HTML entity encoding and do not execute scripts |
| Delete record | `POST /xss/store/deleteOne?id=<record ID>` | Existing ID | Returns deletion success and the page table record disappears |

### DOM XSS Tests

Page: `/xss/dom`

| Scenario | Entry | Test Input | Expected Result |
| --- | --- | --- | --- |
| innerHTML | Multiple code scenarios / innerHTML | `123<img src=x onerror=alert(1)>123` | The result area is written with `innerHTML`, and the event payload can execute |
| LocalStorage | Multiple code scenarios / LocalStorage | `123<img src=x onerror=alert(1)>123` | Data is first written to `localStorage`, then read back and unsafely written into the DOM |
| hash redirect | `/xss/dom/href#javascript:alert(1)` | `javascript:` pseudo-protocol | The page reads `location.hash` and assigns it to `location.href` |
| location | Multiple code scenarios / location object | `javascript:alert(1)` | Assigned directly to `window.location`, used to demonstrate a dangerous URL sink |
| eval | Multiple code scenarios / eval execution | `alert(1)` | User input is executed by `eval` |
| document.write | Multiple code scenarios / document object | `<img src=x onerror=alert(1)>` | `document.write` writes HTML and may trigger execution |
| Safe text output | Safe scenario / text output | `<img src=x onerror=alert(1)>` | Uses `textContent`, so it is displayed as text |
| URL validation | Safe scenario / URL redirect | `javascript:alert(1)` | Dangerous protocol is blocked |
| eval replacement | Safe scenario / eval replacement | `alert(1)` | No command matches the allowlist, execution is refused |
| DOM API | Safe scenario / DOM API | `<img src=x onerror=alert(1)>` | Displayed using a text node, so scripts do not execute |

### Other XSS Scenario Tests

Page: `/xss/other`

| Scenario | Request / Entry | Test Input | Expected Result |
| --- | --- | --- | --- |
| Thymeleaf `th:utext` | `GET /xss/other/vul2OtherTemplate?type=html&payload=<img src=x onerror=alert(1)>` | HTML event payload | `th:utext` renders as HTML, demonstrating unsafe template output |
| Thymeleaf `th:text` | `GET /xss/other/vul2OtherTemplate?type=text&payload=<img src=x onerror=alert(1)>` | HTML event payload | `th:text` escapes entities and displays it as text |
| HTML file upload | `POST /xss/other/vul1Upload?type=html` | `xss.html` | Returns an accessible file path; visiting it triggers or shows behavior according to the browser's parsing strategy |
| SVG file upload | `POST /xss/other/vul1Upload?type=svg` | `xss.svg` | Returns an accessible file path, used to verify the risk of parsable files |
| XML file upload | `POST /xss/other/vul1Upload?type=xml` | `xss.xml` | After the back end parses it successfully, it is written to disk and returns an access path |
| PDF file upload | `POST /xss/other/vul1Upload?type=pdf` | `xss.pdf` | Returns an access path; PDF script execution depends on the reader implementation |
| jQuery component XSS | `/xss/other/jquery-xss` | Built-in example on the page | The page can be opened to demonstrate risks in old jQuery versions |
| Swagger UI component XSS | `/swagger-ui/index.html?configUrl=...` | Malicious config URL example | The page can be opened to demonstrate supply-chain component risk |
| UEditor | `/ueditor`, `/ueditor/config` | Editor upload/configuration | The page and config endpoints are accessible, and the upload endpoint returns UEditor-formatted results |
| WebSocket XSS | Page HTML5 feature / WebSocket XSS | `<img src=x onerror=alert(1)>` | The server broadcasts the message and the front end writes it into the message area using `innerHTML` |
| postMessage XSS | Page HTML5 feature / PostMessage XSS | `<img src=x onerror=alert(1)>` | The receiving window does not validate `origin` and writes the message using `innerHTML` |

## CSRF

Current coverage focuses on three core scenarios: state-changing requests based on authenticated cookies, CSRF token validation, and Origin/Referer auxiliary checks. The module demonstrates the attack chain of "the user is already logged in + the browser automatically carries credentials + the server lacks request-source or intent verification."

The essence of CSRF is that an attacker induces a logged-in user to visit a malicious page or trigger a malicious request. The browser automatically carries the target site's Cookie/Session credentials, and the server mistakenly believes the request came from the user, thereby performing sensitive operations such as transfers, password changes, or account binding. The preferred fix is to use framework-provided CSRF protection or an unpredictable CSRF token; Origin/Referer, SameSite cookies, secondary confirmation, and operation auditing are important supplements, but they should not replace tokens and server-side authorization checks.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| Native vulnerability | `GET /csrf/vul` performs transfers based only on the login session | Covers the most basic CSRF risk; GET state changes make the problem worse |
| Token protection | `GET /csrf/safe1` validates a random token in the session | Covers the mainstream CSRF fix |
| Source checking | `GET /csrf/safe2` checks the protocol, domain, and port of Origin/Referer | Suitable as an auxiliary defense beyond tokens |
| Security guidance | Page guidance on SameSite, secondary confirmation, short validity, and auditing | Covers business-side hardening suggestions |

### CSRF Vulnerability Scenario Tests

Page: `/csrf`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /csrf` | Logged-in session | The page opens normally, showing the native vulnerability, token protection, Origin/Referer auxiliary checks, and code snippets |
| Native transfer | `GET /csrf/vul?receiver=zhangsan&amount=100` | Logged-in session | Returns the current logged-in user, recipient, and amount, showing that a state change can be triggered with only Cookie/Session credentials |
| Access without login | `GET /csrf/vul?receiver=zhangsan&amount=100` | No login session | Redirects to the login page or is blocked by the authentication flow |
| GET state change | Form under "Vulnerability Scenario: Native Vulnerability" on the page | `receiver=zhangsan&amount=100` | Clicking it opens the transfer result via GET, making the CSRF risk easy to observe |

### CSRF Safe Scenario Tests

Page: `/csrf`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Get token | `GET /csrf/getCsrfToken` | Logged-in session | Returns a random `csrfToken` and stores it in the session |
| Missing token | `GET /csrf/safe1?receiver=zhangsan&amount=100` | No `csrfToken` | Returns `success=false` and "Token expired!" |
| Incorrect token | `GET /csrf/safe1?receiver=zhangsan&amount=100&csrfToken=bad` | Wrong token | Returns `success=false` and "Token expired!" |
| Correct token | `GET /csrf/safe1?receiver=zhangsan&amount=100&csrfToken=<session token>` | Token generated in the session | Returns the current user, recipient, amount, and token |
| Missing Origin/Referer | `GET /csrf/safe2?receiver=zhangsan&amount=100` | No source header | Returns `success=false` and "Origin/Referer invalid!" |
| Malicious Origin | `GET /csrf/safe2?receiver=zhangsan&amount=100` | Header `Origin: http://evil.example` | Returns `success=false` |
| Same-origin Origin | `GET /csrf/safe2?receiver=zhangsan&amount=100` | Header `Origin: http://127.0.0.1` | Returns the current user, recipient, and amount |
| Same-origin Referer | `GET /csrf/safe2?receiver=zhangsan&amount=100` | Header `Referer: http://127.0.0.1/csrf` | Returns the current user, recipient, and amount |

## SQL Injection

Current coverage includes JDBC raw concatenation, fake prepared-statement concatenation, JdbcTemplate concatenation, parameterized queries, MyBatis dynamic SQL, Hibernate HQL/raw SQL, and JPA JPQL/dynamic sorting.

The essence of SQL injection is that untrusted input enters the SQL syntax structure and changes the meaning of the original SQL. The preferred fix is to use parameterized queries; column names, table names, sort directions, and other SQL structure elements must use enums or allowlist mappings. Blacklists, type checks, and ESAPI encoding are only auxiliary measures and should not be the first choice for remediation.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| JDBC | Raw SQL concatenation, fake prepared-statement concatenation, JdbcTemplate concatenation | Covers the basic cause of the vulnerability and is suitable for beginners |
| JDBC safe patterns | PreparedStatement, JdbcTemplate parameter binding | Covers common safe remediation for DML |
| Auxiliary measures | Blacklists, data type checks, ESAPI `encodeForSQL` | Can be kept, but the page should emphasize that these are not the preferred fix |
| Special structures and exploitation chains | ORDER BY, LIKE, LIMIT, second-order SQL injection, UNION reflected output | Covers SQL structures that parameter binding cannot directly handle, as well as stored chains and reflected output exploitation |
| MyBatis | Built-in methods, custom `#{}`, `${}` ORDER BY/LIKE/IN, foreach | Covers typical MyBatis pitfalls |
| Hibernate | Raw SQL, HQL, `setParameter` | Covers injection even when using ORM |
| JPA | JPQL, dynamic sorting, named parameters, Criteria allowlists | Covers common JPA risk points |

### JDBC Vulnerability Scenario Tests

Page: `/sqli/jdbc/jdbcVul`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Raw concatenation - query | `GET /sqli/jdbc/vul1?type=select&id=1 OR 1=1` | `id=1 OR 1=1` | The vulnerable scenario returns multiple records or leaks SQL behavior through an error |
| Raw concatenation - insert error | `GET /sqli/jdbc/vul1?type=add` | `password=1' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND '1'='1` | Returns database error information or an execution exception |
| Fake prepared statement | `GET /sqli/jdbc/vul2?type=select&id=1 OR 1=1` | `id=1 OR 1=1` | Still injectable, proving that preparing after concatenation is ineffective |
| JdbcTemplate concatenation | `GET /sqli/jdbc/vul3?type=select&id=1 OR 1=1` | `id=1 OR 1=1` | Still injectable |
| Traffic sample download | Traffic analysis dropdown in the top-right of the page | Delay / boolean / error / XPath | Selecting one should download the corresponding `pcapng` file |

### JDBC Safe and Auxiliary Scenario Tests

Page: `/sqli/jdbc/jdbcSafe`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| PreparedStatement | `GET /sqli/jdbc/safe1?type=select&id=1 OR 1=1` | Non-numeric or injected payload | The injection semantics are not executed, and the server returns a parameter error or query failure |
| JdbcTemplate parameter binding | `GET /sqli/jdbc/safe2?type=select&id=1 OR 1=1` | Injection payload | Injection semantics are not executed |
| Blacklist auxiliary check | `GET /sqli/jdbc/safe3?type=select&id=1 and sleep(5)` | Blacklisted keyword | Blocked with "Blacklisted SQL injection detected" |
| Data type validation | `GET /sqli/jdbc/safe4?id=1' or '1'='1` | String-based injection | Non-integer input is rejected |
| ESAPI auxiliary | `GET /sqli/jdbc/safe5?id=1' or '1'='1` | String-based injection | Encoding should not change SQL semantics, but it is not the preferred remediation check |

### JDBC Special Scenario Tests

Page: `/sqli/jdbc/jdbcSpecial`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| ORDER BY concatenation | `GET /sqli/jdbc/special1-OrderBy?type=raw&field=username and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)%23` | Dynamic sort field injection | The vulnerable path throws an exception or leaks data |
| ORDER BY placeholder misconception | `GET /sqli/jdbc/special1-OrderBy?type=prepareStatement&field=username` | Valid field | It cannot truly sort by the field, used to show that placeholders cannot bind SQL structure |
| ORDER BY allowlist | `GET /sqli/jdbc/special1-OrderBy?type=writeList&field=username` | Valid field | Returns sorted results normally |
| ORDER BY allowlist blocking | `GET /sqli/jdbc/special1-OrderBy?type=writeList&field=username desc` | Non-allowlisted field | Returns that the field is invalid |
| LIKE concatenation | `GET /sqli/jdbc/special2-Like?type=raw&keyword=1' OR '1'='1` | LIKE injection | The vulnerable path is triggered |
| LIKE parameter binding | `GET /sqli/jdbc/special2-Like?type=prepareStatement&keyword=admin' OR '1'='1` | LIKE injection | Treated as a normal keyword |
| LIMIT parameter | `GET /sqli/jdbc/special3-Limit?type=prepareStatement&size=1` | Positive integer | Returns the limited row count normally |
| Second-order injection - write | `GET /sqli/jdbc/special4-SecondOrder?type=store&username=second_order' OR '1'='1&password=demo` | Malicious username | Parameterized write succeeds, with no trigger in the first step |
| Second-order injection - trigger | `GET /sqli/jdbc/special4-SecondOrder?type=trigger&id=<returned write ID>` | Stored malicious username | The second query concatenates the username from the database and returns multiple records or shows injection effects |
| Second-order injection - safe comparison | `GET /sqli/jdbc/special4-SecondOrder?type=safeTrigger&id=<returned write ID>` | Stored malicious username | Parameter binding is used, and the malicious content is treated as a normal username query |
| UNION reflected output | `GET /sqli/jdbc/special5-Union?type=raw&id=-1 UNION SELECT 1,database(),user()` | UNION payload | Reflects the current database name and database user |
| UNION parameter binding | `GET /sqli/jdbc/special5-Union?type=prepareStatement&id=-1 UNION SELECT 1,database(),user()` | UNION payload | The payload is treated as a normal parameter and does not change the SQL structure |

### MyBatis Scenario Tests

Page: `/sqli/mybatis`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Built-in methods | `POST /sqli/mybatis/safe1?type=select&id=2` | Valid ID | Normal query |
| Built-in methods without ID | `POST /sqli/mybatis/safe1?type=delete` | Missing ID | Returns `id cannot be empty!` |
| Custom `#{}` | `POST /sqli/mybatis/safe2?type=select&id=999999` | Non-existent ID | Returns `User ID does not exist!` without a null pointer exception |
| ORDER BY `${}` | `POST /sqli/mybatis/special1-OrderBy?type=raw&field=username and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)%23` | Dynamic field injection | The vulnerable path is triggered |
| ORDER BY `#{}` misconception | `POST /sqli/mybatis/special1-OrderBy?type=prepareStatement&field=username` | Valid field | It cannot be used for true dynamic field sorting |
| ORDER BY allowlist | `POST /sqli/mybatis/special1-OrderBy?type=writeList&field=username` | Valid field | Returns normally |
| LIKE `${}` | `POST /sqli/mybatis/special2-Like?type=raw&keyword=1' OR '1'='1` | LIKE injection | The vulnerable path is triggered |
| LIKE `#{}` | `POST /sqli/mybatis/special2-Like?type=prepareStatement&keyword=admin' OR '1'='1` | LIKE injection | Treated as a normal keyword |
| IN `${}` | `POST /sqli/mybatis/special3-In?type=raw&scope=1) OR 1=1 -- ` | IN injection | The vulnerable path is triggered |
| IN `#{}` misconception | `POST /sqli/mybatis/special3-In?type=prepareStatement&scope=1,2` | Multiple IDs | Treated as a single parameter and cannot expand into multiple placeholders |
| IN foreach | `POST /sqli/mybatis/special3-In?type=Foreach&scope=1,2,abc` | Mixed invalid values | Invalid values are ignored and only valid integers are queried |
| IN foreach empty value | `POST /sqli/mybatis/special3-In?type=Foreach` | Missing scope | Returns `There are no valid integer IDs in scope!` |

### Hibernate and JPA Scenario Tests

Page: `/sqli/hibernate`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Hibernate raw SQL | `POST /sqli/hibernate/vul1?username=admin' OR 1=1 OR '1'='1` | Injection payload | Returns multiple records or shows injection effects |
| Hibernate HQL | `GET /sqli/hibernate/vul2?username=admin' OR 1=1 OR '1'='1` | Injection payload | Returns multiple records or shows injection effects |
| Hibernate parameterization | `POST /sqli/hibernate/safe?username=admin' OR 1=1 OR '1'='1` | Injection payload | Treated as a normal username and returns no record found |

Page: `/sqli/jpa`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| JPA JPQL | `GET /sqli/jpa/vul1?username=admin' OR '1'='1` | Injection payload | Returns multiple records or shows injection effects |
| JPA dynamic sorting | `GET /sqli/jpa/vul2?orderBy=username desc` | Dynamic sort field | Normal sorting; abnormal payloads should expose the risk |
| JPA parameterization | `GET /sqli/jpa/safe?username=admin' OR '1'='1` | Injection payload | Treated as a normal username and returns no record found |
| JPA sort allowlist | `GET /sqli/jpa/safe-order?orderBy=username` | Valid field | Normal sorting |
| JPA sort allowlist blocking | `GET /sqli/jpa/safe-order?orderBy=username desc` | Non-allowlisted field | Returns that the sort field is invalid |

## Arbitrary File Operations

Current coverage includes four common risks: arbitrary file upload, arbitrary file read, arbitrary file download, and arbitrary file deletion. It can chain the typical file security path of "upload a malicious file -> access it through static mapping -> read/download sensitive files -> delete business files."

The essence of arbitrary-file vulnerabilities is that user-controlled file names, paths, content, or metadata enter file-system operations without proper restrictions on directory boundaries, file types, access methods, and business permissions. When fixing, do not rely only on string replacement, blacklists, or front-end limits. Use back-end allowlists, server-generated file names, path normalization, real-path checks, directory isolation, permission checks, and audit logs.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| File upload | Arbitrary type upload, image suffix allowlist, image content validation | Covers the upload entry, suffix-check misconceptions, and the effect of how uploaded files are accessed |
| File read | Absolute path / directory traversal read, upload directory restriction | Covers sensitive file reads and safe directory boundary checks |
| File download | Absolute path / directory traversal download, file-name validation, upload directory restriction | Covers the common risks in attachment download APIs |
| File deletion | Arbitrary path deletion, upload directory restriction | Covers destructive file operation risks and emphasizes testing only with temporary files |
| Static mapping | `/file/**` mapped to the upload directory | Explains that uploaded files can be accessed and that script parsing, content type, and separate-domain isolation must be considered |

### File Upload Tests

Page: `/file/upload`

| Scenario | Request / Entry | Test Input | Expected Result |
| --- | --- | --- | --- |
| Arbitrary file upload | `POST /file/upload/vul` | `test.jsp` or any file extension | Returns "File uploaded successfully" and a `/file/<filename>` access path |
| Access after upload | `GET /file/<filename>` | Filename returned in the previous step | The file is accessible through static mapping; Spring Boot does not parse JSP by default |
| Safe upload - image | `POST /file/upload/safe` | A real `png/jpg/gif/jpeg/bmp/ico` image | The suffix allowlist and image content validation both pass, and the upload succeeds |
| Safe upload - script blocked | `POST /file/upload/safe` | `jsp/php/html` | Returns "Only images are allowed!" |
| Safe upload - fake suffix blocked | `POST /file/upload/safe` | `test.png` whose content is not an image | Returns "The file content does not match the image type!" |
| Traffic sample / example payload | Payload / traffic analysis dropdown in the top-right of the page | `test.jsp`, `upload.pcapng` | The corresponding test files can be downloaded |

### File Read Tests

Page: `/file/read`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Absolute path read | `GET /file/read/vul?fileName=/etc/hosts` | `/etc/hosts` | Returns the file content |
| Directory traversal read | `GET /file/read/vul?fileName=../../../../etc/hosts` | `../` payload | If the path resolves to a real file, returns the file content |
| Safe read - privilege escalation blocked | `GET /file/read/safe?fileName=/etc/hosts` | Absolute path | Returns "Access denied: invalid file path" or is inaccessible |
| Safe read - file inside directory | `GET /file/read/safe?fileName=<filename inside upload directory>` | A normal file within the upload directory | Returns the file content |
| Safe read - symlink bypass | `GET /file/read/safe?fileName=<symlink pointing outside>` | Symlink inside the upload directory | Returns "The real file path is invalid" |

### File Download Tests

Page: `/file/download`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Absolute path download | `GET /file/download/vul?fileName=/etc/passwd` | `/etc/passwd` | Returns the file as an attachment and can be downloaded if it exists |
| Directory traversal download | `GET /file/download/vul?fileName=../../../../etc/hosts` | `../` payload | If the path resolves to a real file, returns it as an attachment |
| Safe download - invalid filename | `GET /file/download/safe?fileName=/etc/hosts` | Absolute path | Returns 400 or 404 and does not allow download |
| Safe download - file inside directory | `GET /file/download/safe?fileName=<filename inside upload directory>` | A normal file within the upload directory | Downloads normally |
| Safe download - symlink bypass | `GET /file/download/safe?fileName=<symlink pointing outside>` | Symlink inside the upload directory | Returns 403 "The real file path is invalid" |

### File Deletion Tests

Page: `/file/delete`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Arbitrary path deletion | `GET /file/delete/vul?filePath=./src/main/resources/static/upload/demo.txt` | Temporary test file | Returns deletion success when the file exists |
| Directory traversal deletion | `GET /file/delete/vul?filePath=../../tmp/demo.txt` | Temporary files only | If the path exists and permission allows, deletion is attempted |
| Safe deletion - privilege escalation blocked | `GET /file/delete/safe?fileName=../test` | `../` payload | Returns "Access denied: invalid file path" |
| Safe deletion - file inside directory | `GET /file/delete/safe?fileName=<filename inside upload directory>` | A normal file within the upload directory | Deletes successfully when the file exists |
| Safe deletion - symlink bypass | `GET /file/delete/safe?fileName=<symlink pointing outside>` | Symlink inside the upload directory | Returns "The real file path is invalid" |

## SSRF

Current coverage includes arbitrary-protocol requests, local file reads, internal HTTP access, following redirect chains into internal networks, and common fixes such as protocol/domain allowlists, resolved-IP verification, and disabling automatic redirects.

The essence of SSRF is that the server uses a user-controlled URL, host name, or resource address to initiate network requests without restricting the protocol, target host, resolved IP, or redirect chain. Attackers can use the server's network identity to access internal services, cloud metadata, management ports, local files, or third-party resources. The preferred fix is to use business-level enums or server-side mappings instead of accepting full URLs directly; if a URL must be accepted, restrict the protocol, validate an allowlisted domain, resolve all target IPs and block internal addresses, and re-check each hop in any 30x redirect chain.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| Arbitrary protocol request | `URLConnection` directly requests a user-supplied URL | Covers the most basic SSRF cause and demonstrates `file://` and `http://` |
| Local file read | `file:///etc/hosts`, `file:///etc/passwd` | Covers the impact of reading local server files |
| Internal HTTP access | `http://127.0.0.1/ssrf/internal/metadata` | Covers internal-service / cloud-metadata risks using built-in mock endpoints in the lab |
| Redirect-chain risk | `/ssrf/redirect?target=...` | Covers the common bypass where only the first hop is checked while redirects are followed automatically |
| Safe patterns | http(s) protocol, domain allowlist, resolved-IP check, automatic redirect disabled | Covers the recommended remediation path |

### SSRF Vulnerability Scenario Tests

Page: `/ssrf`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /ssrf` | None | The page opens normally, showing vulnerability scenarios, safe scenarios, tips, and code snippets |
| Local file read | `GET /ssrf/vul?url=file:///etc/hosts` | `file:///etc/hosts` | Returns the local hosts file content |
| Internal HTTP access | `GET /ssrf/vul?url=http://127.0.0.1/ssrf/internal/metadata` | Local internal mock metadata URL | Returns mock metadata such as `instance-id`, `role`, and `token` |
| Redirect-chain access to internal network | `GET /ssrf/vul?url=http://127.0.0.1/ssrf/redirect?target=http://127.0.0.1/ssrf/internal/metadata` | First hop is a redirect endpoint | The vulnerable request follows the redirect and returns the mock metadata |
| Protocol probing | `GET /ssrf/vul?url=dict://127.0.0.1:6379/info` | Non-HTTP protocol | Returns a connection exception or protocol handling result, used to observe arbitrary-protocol risk |
| Traffic sample download | Traffic analysis button on the page | `ssrf.pcapng` | The corresponding packet capture can be downloaded |

### SSRF Safe Scenario Tests

Page: `/ssrf`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Non-HTTP protocol blocked | `GET /ssrf/safe?url=file:///etc/hosts` | `file://` | Returns "Detected a non-http(s) protocol!" |
| Internal address blocked | `GET /ssrf/safe?url=http://127.0.0.1/ssrf/internal/metadata` | Loopback address | Returns "Non-allowlisted domain!" |
| Userinfo confusion blocked | `GET /ssrf/safe?url=http://baidu.com@127.0.0.1/ssrf/internal/metadata` | `userinfo@host` | Returns "Non-allowlisted domain!" |
| Allowlisted domain | `GET /ssrf/safe?url=http://baidu.com` | Allowlisted domain | Passes the protocol and allowlist checks and returns the remote response or network access result |
| Redirect-chain blocked | `GET /ssrf/safe?url=http://127.0.0.1/ssrf/redirect?target=http://127.0.0.1/ssrf/internal/metadata` | Redirect to internal network | The first-hop target is not on the allowlist, so it directly returns "Non-allowlisted domain!"; the safe code also disables automatic redirects |
| Timeout control | Access a slow or unreachable HTTP address | Slow target | After connect/read timeout, returns an exception message and does not block the request thread for long |

## XXE

Current coverage includes the three common Java XML parsing entry points: XMLReader, SAXParser, and DocumentBuilder. It can demonstrate reading local files through external entities, using external entities to access internal network addresses, and the remediation approach of disabling DOCTYPE, external entities, external DTDs, and external schemas.

The essence of XXE is that when an application parses untrusted XML and allows DTDs or external entities, an attacker can use SYSTEM/PUBLIC external entities to make the parser read local files, access internal addresses, trigger SSRF, or cause denial of service through entity expansion. The fix should not rely on the default behavior of a particular parser version. At every XML parsing entry point, explicitly disable DOCTYPE, external general entities, external parameter entities, and external DTD loading; DOM-style parsers should also restrict `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA`.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| SAX/XMLReader | `XMLReaderFactory.createXMLReader()` | Covers external-entity expansion risk in the underlying SAX parsing entry |
| SAXParser | `SAXParserFactory.newInstance()` | Covers common SAXParser wrapper scenarios and emphasizes not relying on default safety behavior |
| DOM/DocumentBuilder | `DocumentBuilderFactory.newInstance()` | Covers common DOM parsing, config import, and XML document reading scenarios in business code |
| Safe patterns | Disable DOCTYPE, external entities, external DTDs, and external schemas; configure an empty `EntityResolver` | Covers the recommended remediation path |
| Auxiliary detection | Keyword blacklist detection for `ENTITY`, `DOCTYPE` | Kept as auxiliary detection only, not as root-cause remediation |

### XXE Vulnerability Scenario Tests

Page: `/xxe/vul`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /xxe/vul` | None | The page opens normally, showing XMLReader, SAXParser, and DocumentBuilder vulnerability scenarios and code snippets |
| XMLReader reads local file | `GET /xxe/vul1?payload=<xml>` | `<!ENTITY xxe SYSTEM "file:///etc/hosts">` | Returns the hosts file content, proving that the external entity was expanded |
| XMLReader accesses internal network | `GET /xxe/vul1?payload=<xml>` | `<!ENTITY xxe SYSTEM "http://127.0.0.1/ssrf/internal/metadata">` | Returns mock metadata, proving that an SSRF chain can be triggered |
| SAXParser reads local file | `GET /xxe/vul2?payload=<xml>` | `<!ENTITY xxe SYSTEM "file:///etc/hosts">` | Returns the hosts file content or the parser's external-entity expansion result |
| DocumentBuilder reads local file | `GET /xxe/vul3?payload=<xml>` | `<!ENTITY xxe SYSTEM "file:///etc/hosts">` | Returns the hosts file content, proving that the DOM parser is also affected |
| DocumentBuilder accesses internal network | `GET /xxe/vul3?payload=<xml>` | `<!ENTITY xxe SYSTEM "http://127.0.0.1/ssrf/internal/metadata">` | Returns mock metadata |
| Audit sink points | Page tips | XMLReader, SAXParser, DocumentBuilder, XMLStreamReader, and similar | The page lists common XML parsing entry points to help code review |

### XXE Safe Scenario Tests

Page: `/xxe/safe`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /xxe/safe` | None | The page opens normally, showing safe configuration and auxiliary detection scenarios |
| XMLReader safe configuration | `GET /xxe/safe1?payload=<xml>` | Payload with DOCTYPE and external entities | Returns an error stating that DOCTYPE is forbidden or external entities cannot be expanded, without leaking file content |
| XMLReader normal XML | `GET /xxe/safe1?payload=<root>hello</root>` | Normal XML without DTD | Returns `hello` |
| DocumentBuilder safe configuration | `GET /xxe/safe3?payload=<xml>` | Payload with DOCTYPE and external entities | Returns an error stating that DOCTYPE is forbidden or external entities cannot be expanded, without leaking file content |
| DocumentBuilder normal XML | `GET /xxe/safe3?payload=<root>hello</root>` | Normal XML without DTD | Returns `hello` |
| Blacklist auxiliary blocking | `GET /xxe/safe2?payload=<xml>` | Payload with `DOCTYPE` or `ENTITY` keywords | Returns `[+] Malicious XML detected!` |
| Blacklist normal XML | `GET /xxe/safe2?payload=<root>hello</root>` | Normal XML | Returns `[-] XML content is safe` |

## Cross-Origin Security

Current coverage includes incorrect CORS configuration, CORS allowlist remediation, JSONP sensitive-data leakage, JSONP callback validation, and public-data responses. The module mainly demonstrates that the same-origin policy constrains a browser script's ability to "read cross-origin responses," and once the server incorrectly relaxes CORS or continues to use JSONP for sensitive data, it may expose login-session data to attacker sites.

The essence of cross-origin security issues is improper configuration of cross-site read boundaries. CORS is not an authentication or authorization mechanism. `Access-Control-Allow-Origin` only tells the browser which origins may read the response; when credentials are allowed, it must return the trusted Origin precisely and cannot reflect arbitrary origins or use a wildcard strategy. JSONP relies on `script` tags to load and execute cross-origin content, so it is not suitable for sensitive user identity, permissions, orders, tokens, or similar data. If it must be kept, it should only serve public read-only data and must strictly validate the callback.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| CORS vulnerability | `GET /crossorigin/corsVul` reflects the request `Origin` and allows credentials | Covers the typical incorrect configuration for cross-origin reading of sensitive data |
| CORS safe pattern | `GET /crossorigin/corsSafe` matches trusted Origins exactly and restricts methods and headers | Covers key fixes such as allowlists, credentials, and `Vary: Origin` |
| JSONP vulnerability | `GET /crossorigin/jsonpVul?callback=stealData` returns sensitive data | Covers the problem that any site can read JSONP through a `script` tag |
| JSONP safe pattern | `GET /crossorigin/jsonpSafe?callback=stealData` validates the callback and returns only public data | Covers the minimum security requirements when JSONP must be retained |

### CORS Vulnerability Scenario Tests

Page: `/crossorigin/cors`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /crossorigin/cors` | Logged-in session | The page opens normally, showing CORS vulnerability, allowlist remediation, and code snippets |
| Direct access without Origin | `GET /crossorigin/corsVul` | No `Origin` header | Returns sensitive demo data, and the response carries the default `Access-Control-Allow-Origin: http://example.com` |
| Reflect arbitrary Origin | `GET /crossorigin/corsVul` | Header `Origin: http://evil.example` | Returns sensitive demo data, and `Access-Control-Allow-Origin` is reflected to the malicious origin |
| Allow credentials | `GET /crossorigin/corsVul` | Header `Origin: http://evil.example` | The response includes `Access-Control-Allow-Credentials: true`, showing that cross-origin scripts can read the response when credentials are included |
| Preflight request | `OPTIONS /crossorigin/corsVul` | Header `Origin: http://evil.example` | Returns allowed methods and headers, used to demonstrate an overly broad preflight policy |

### CORS Safe Scenario Tests

Page: `/crossorigin/cors`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Same-origin access | `GET /crossorigin/corsSafe` | No `Origin` header | Returns "Same-origin requests do not need CORS response headers" and does not expose cross-origin reading policy |
| Non-allowlisted Origin | `GET /crossorigin/corsSafe` | Header `Origin: http://evil.example` | Returns 403 or is rejected by the CORS filter, and does not return a trusted `Access-Control-Allow-Origin` |
| Allowlisted Origin | `GET /crossorigin/corsSafe` | Header `Origin: http://127.0.0.1:8080` | Returns success, and the response carries `Access-Control-Allow-Origin: http://127.0.0.1:8080` |
| Allowlisted preflight | `OPTIONS /crossorigin/corsSafe` | Header `Origin: http://127.0.0.1:8080` | Returns allowed `GET, OPTIONS` and the necessary request headers |

### JSONP Vulnerability Scenario Tests

Page: `/crossorigin/jsonp`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /crossorigin/jsonp` | Logged-in session | The page opens normally, showing JSONP hijacking, safe patterns, and code snippets |
| JSONP sensitive data | `GET /crossorigin/jsonpVul?callback=stealData` | `callback=stealData` | Returns `stealData({"username":"admin","password":"Admin123"});` |
| Callback not validated | `GET /crossorigin/jsonpVul?callback=alert` | `callback=alert` | Returns executable script format, showing that any callback name is controllable |

### JSONP Safe Scenario Tests

Page: `/crossorigin/jsonp`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Valid callback | `GET /crossorigin/jsonpSafe?callback=stealData` | Valid function name | Returns `stealData({"message":"public data only"});` and does not include sensitive account or password data |
| Namespaced callback | `GET /crossorigin/jsonpSafe?callback=app.stealData` | Valid namespaced function name | Returns `app.stealData({"message":"public data only"});` |
| Invalid callback | `GET /crossorigin/jsonpSafe?callback=alert(1)` | Invalid function name with parentheses | Returns 400 and `Invalid callback` |
| Response headers | `GET /crossorigin/jsonpSafe?callback=stealData` | Valid function name | The response `Content-Type` is JavaScript, and it includes `X-Content-Type-Options: nosniff` |

## RCE

Current coverage includes two main lines: command injection and code injection. Command injection includes three entry points: `ProcessBuilder`, `Runtime.getRuntime().exec()`, and reflective invocation of `ProcessImpl`. Code injection includes `GroovyShell.evaluate` and a controlled action-dispatch remediation pattern.

The essence of RCE is that untrusted input enters a server-side "executable context." Command injection usually happens when user input enters system commands, shell syntax, or command arguments; code injection usually happens when user input enters a script engine, expression engine, template engine, dynamic compilation, or plugin execution logic. The preferred fix is to remove dynamic execution capabilities and replace them with business APIs or server-side fixed-action mappings. If system commands must be invoked, do not concatenate strings, do not enter `sh -c` or `cmd.exe /c`, allow only fixed commands and fixed parameters, and add timeouts, least privilege, output limits, and auditing.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| ProcessBuilder command injection | `GET /command/vul1` executes user input with `sh -c` | Covers shell metacharacter concatenation, pipes, redirection, and other high-risk command injection causes |
| Runtime command execution | `GET /command/vul2` executes user input directly | Covers a common Java command-execution sink and shows that it is dangerous even without a shell |
| ProcessImpl reflection | `GET /command/vul3` reflects into the JDK internal process-start entry | Covers the problem that auditing only `Runtime.exec` is not enough; newer JDKs may block it due to module restrictions |
| Safe command execution | `GET /command/safe` uses an action allowlist mapped to fixed commands | Covers fixed server-side actions, fixed parameters, timeout handling, and output reading order |
| Groovy code injection | `GET /code/vulGroovy` executes `GroovyShell.evaluate(payload)` | Covers script-engine code execution risk |
| Safe code execution | `GET /code/safeGroovy` uses controlled action dispatch | Covers the remediation idea of turning "arbitrary scripts" into "limited business actions" |

### Command Injection Scenario Tests

Page: `/command`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /command` | Logged-in session | The page opens normally, showing ProcessBuilder, Runtime, ProcessImpl, allowlist safe scenarios, and code snippets |
| Basic ProcessBuilder command | `GET /command/vul1?payload=whoami` | `whoami` | Returns the current running user |
| ProcessBuilder shell concatenation | `GET /command/vul1?payload=echo rce; whoami` | shell metacharacter `;` | Returns the `echo` output and the current user, showing that `sh -c` interpreted the concatenated command |
| Basic Runtime command | `GET /command/vul2?payload=whoami` | `whoami` | Returns the current running user |
| Runtime non-shell semantics | `GET /command/vul2?payload=echo rce` | Program and arguments | Returns `rce`, but `;`, `&&`, and similar tokens are not interpreted like a shell |
| ProcessImpl reflection | `GET /command/vul3?payload=whoami` | `whoami` | On older versions or with open modules, returns the current user; newer JDKs may return a module access restriction error |
| Traffic sample download | Link labeled "Traffic Analysis" on the page | `command_injection.pcapng` | The command-injection traffic capture can be downloaded |

### Safe Command Execution Scenario Tests

Page: `/command`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Allowlisted action-list | `GET /command/safe?payload=list` | `list` | Executes the server-side fixed `ls` action and returns directory output |
| Allowlisted action-date | `GET /command/safe?payload=date` | `date` | Executes the server-side fixed `date` action and returns the current time |
| Illegal command blocked | `GET /command/safe?payload=whoami;id` | Concatenated command | Returns "This action is not allowed!" |
| Arbitrary command blocked | `GET /command/safe?payload=whoami` | Unconfigured action | Returns "This action is not allowed!" |
| Timeout protection | Safe code review | Long-running commands are not in the allowlist | Users cannot trigger arbitrary long-running commands; fixed commands also use a wait timeout |

### Groovy Code Injection Scenario Tests

Page: `/code`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /code` | Logged-in session | The page opens normally, showing Groovy code injection, safe action dispatch, and code snippets |
| Expression execution | `GET /code/vulGroovy?payload=1%2B2%2B3` | `1+2+3` | Returns `6`, proving that the input is executed as Groovy code |
| Command execution | `GET /code/vulGroovy?payload='whoami'.execute()` | Groovy `execute()` | Returns the current running user or process output |
| Unexpected Java capability | `GET /code/vulGroovy?payload=System.getProperty('user.dir')` | Java API call | Returns the server working directory, showing that code execution is broader than command execution |
| Traffic sample download | Link labeled "Traffic Analysis" on the page | `code_injection.pcapng` | The code-injection traffic capture can be downloaded |

### Safe Groovy Scenario Tests

Page: `/code`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Controlled action - hello | `GET /code/safeGroovy?payload=hello` | `hello` | Returns `Hello JavaSecLab` |
| Controlled action - time | `GET /code/safeGroovy?payload=time` | `time` | Returns the server's current time |
| Controlled action - sum | `GET /code/safeGroovy?payload=sum` | `sum` | Returns `6` |
| Illegal script blocked | `GET /code/safeGroovy?payload='whoami'.execute()` | Groovy command-execution script | Returns "Illegal action input!" |

## Logic Vulnerabilities

Current coverage includes four main lines: authorization bypass, captcha security, payment business logic, and concurrency safety. Authorization bypass includes horizontal and vertical privilege escalation; captcha covers captcha reuse, universal captchas, weak graphic captchas, SMS captcha echoing, and parameter bypass; payment covers amount tampering, order replay, process bypass, integer overflow, and floating-point precision issues; concurrency safety covers race conditions and idempotency checks.

The essence of a logic vulnerability is not a single dangerous API, but a design error in business state, authorization boundaries, validation order, or trusted source. When fixing, do not rely only on front-end restrictions, hidden menus, invisible parameters, or client-side prices. Establish unified server-side validation around "who the current user is, what they are allowed to do, which resource belongs to whom, what state the order is in, and whether key parameters are trustworthy", and combine this with idempotency, transactions, locks, audits, and risk control.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| Horizontal privilege escalation | `GET /logic/idor/horizontal/getUserInfo` queries users based on request parameters | Covers access to another user's resources by users at the same privilege level through object identifiers |
| Vertical privilege escalation | `GET /logic/idor/vertical/vul` low-privilege users directly access the admin page | Covers missing server-side role checks for administrator functions |
| Graphic captcha | Reused captcha, universal captcha, weak captcha recognition, safe captcha | Covers captcha lifecycle, fixed backdoors, and recognition difficulty |
| SMS captcha | Captcha echoing, `code_verify=true` parameter bypass | Covers response leakage and trusting client-side verification results |
| Payment logic | Amount tampering, order replay, process bypass, integer overflow, floating-point precision | Covers common high-risk business logic issues in transaction flows |
| Concurrency safety | Concurrent duplicate payment, synchronization lock, and idempotency checks | Covers duplicate deductions and state races caused by concurrent reads and writes to shared resources |

### Authorization Bypass Tests

Page: `/logic/idor/horizontal`, `/logic/idor/vertical`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Horizontal privilege page | `GET /logic/idor/horizontal` | Logged-in session | The page opens normally, showing horizontal privilege escalation vulnerabilities and session-check safe scenarios |
| Horizontal privilege vulnerability | `GET /logic/idor/horizontal/getUserInfo?username=123` | Any existing user | Returns the specified user's information, showing that only the request parameter is trusted |
| Horizontal privilege safe block | `GET /logic/idor/horizontal/safe?username=admin` | Different from the current logged-in user | Returns "You do not have permission to view this user's profile" |
| Horizontal privilege safe allow | `GET /logic/idor/horizontal/safe?username=<current logged-in user>` | Current logged-in user | Returns the current user's information |
| Vertical privilege page | `GET /logic/idor/vertical` | Logged-in session | The page opens normally, showing vertical privilege scenarios |
| Vertical privilege vulnerability | `GET /logic/idor/vertical/vul` | Normal logged-in user | Can access the admin page, showing missing server-side role checks |
| Vertical privilege safe check | `GET /logic/idor/vertical/safe` | Normal logged-in user | Returns no admin permission; the admin user passes the check |

### Graphic Captcha Tests

Page: `/logic/captcha/graphic`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /logic/captcha/graphic` | Logged-in session | The page opens normally, showing captcha expiration, universal captcha, recognizable captcha, and safe scenarios |
| Get vulnerable captcha | `GET /logic/captcha/graphic/img` | Same session | Returns an image captcha and stores a 4-digit captcha in the session |
| Captcha reuse | `POST /logic/captcha/graphic/vul1` | Correct captcha submitted twice | The captcha is not cleared after success within 5 minutes and can be reused |
| Universal captcha | `POST /logic/captcha/graphic/vul2` | `username=admin&password=admin123&captcha=6666` | Passes without the real image captcha |
| Weak captcha recognition | `POST /logic/captcha/graphic/vul3` | OCR- or manually recognized 4-digit captcha | The correct captcha passes, showing that weak captchas are easy to recognize or brute-force |
| Get safe captcha | `GET /logic/captcha/graphic/safeImg` | Same session | Returns a 6-digit captcha and sets a shorter validity period |
| Safe captcha error | `POST /logic/captcha/graphic/safe` | Wrong captcha | Returns "Captcha error, please re-enter!" and clears the captcha |

### SMS Captcha Tests

Page: `/logic/captcha/sms`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /logic/captcha/sms` | Logged-in session | The page opens normally, showing captcha echoing and captcha bypass scenarios |
| Phone format validation | `GET /logic/captcha/sms/code?phone=abc` | Invalid phone number | Returns "Phone number format is incorrect!" |
| Captcha echoing | `GET /logic/captcha/sms/code?phone=18888888888` | Valid phone number | The response directly includes the SMS captcha |
| Echoed captcha validation | `POST /logic/captcha/sms/vul1` | Use the captcha from the response | Returns validation passed |
| Prepare captcha bypass | `GET /logic/captcha/sms/code2?phone=18888888888` | Valid phone number | The response does not echo the captcha, but the session stores it |
| Parameter bypass | `POST /logic/captcha/sms/vul2?phone=18888888888&code=000000&code_verify=true` | Any wrong captcha | Returns validation passed, showing that the client-controlled parameter is trusted |

### Payment Logic Tests

Page: `/logic/pay`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /logic/pay` | Logged-in session | The page opens normally, showing six payment logic vulnerabilities and a balance reset button |
| Reset balance | `POST /logic/pay/resetBalance` | None | Returns that the balance has been reset to 1000 yuan |
| Amount parameter tampering | `POST /logic/pay/vul1` | `count=1&price=0.01` | Payment succeeds using the client-side price, showing that the real server-side price is not validated |
| Order replay | `POST /logic/pay/vul2` | Repeated payment for the same `orderId` | Each request deducts funds, showing missing idempotency and payment-state checks |
| Concurrent race | Concurrent `POST /logic/pay/vul3` | Concurrent requests with the same `orderId` and amount | Duplicate deductions or inconsistent balance calculations may occur |
| Create order | `POST /logic/pay/vul4/create` | `orderId=bypass123&amount=200` | Returns that the order was created successfully and is unpaid |
| Process bypass | `POST /logic/pay/vul4/notify` | `orderId=bypass123&success=true` | The order can be changed to paid without an actual payment |
| Integer overflow | `POST /logic/pay/vul5` | `count=2147483647&price=10` | `int` multiplication overflows, which may produce a negative amount and cause balance anomalies |
| Floating-point precision | `POST /logic/pay/vul6` | `count=0.1&price=0.2` | The actual deducted amount shows binary floating-point precision errors |

### Concurrency Safety Tests

Page: `/logic/concurrent`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /logic/concurrent` | Logged-in session | The page opens normally, showing race-condition vulnerabilities and synchronized-lock / idempotency safe scenarios |
| Reset test data | `POST /logic/concurrent/reset` | None | Returns that the balance has been reset to 1000 yuan and the order state has been cleared |
| Concurrent duplicate payment | Concurrent `POST /logic/concurrent/vul` | `orderId=race123&amount=100` | Multiple requests for the same order may succeed at the same time, causing duplicate deductions or inconsistent balance results |
| Safe idempotency check | Concurrent `POST /logic/concurrent/safe` | `orderId=safeRace123&amount=100` | The first request deducts successfully, and later requests for the same order return "Order already paid, duplicate deduction denied" |

## Other Vulnerabilities

Current coverage includes four vulnerability types that are easy to scatter around business edges: URL redirect, XFF spoofing, DoS resource consumption, and XPath injection. This module works well as a supplement to the broader lab: instead of centering on a single technology stack, it demonstrates issues often underestimated in real projects, such as input trust, redirect control, proxy-header trust, resource limits, and expression concatenation.

The remediation core for these issues is: URL redirects must use server-side mappings or strict allowlists, and arbitrary external URLs must not be placed directly into `Location`; XFF can only be parsed when the request comes from a trusted proxy and must never be trusted directly from the client; DoS-style features need limits on size, quantity, depth, timeout, and concurrency; XPath queries should use variable binding or exact business-layer matching and must not concatenate expressions.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| URL redirect | Spring MVC, ModelAndView, Servlet, ResponseEntity, and response-header redirects | Covers common Java Web redirect sinks and the allowlist remediation idea |
| XFF spoofing | Directly trusting `X-Forwarded-For` as the client IP | Covers bypassing IP controls and log pollution via forged request headers |
| DoS resource consumption | Controllable image width/height parameters, ZIP recursive extraction | Covers expensive image generation and resource amplification through archives |
| XPath injection | Username and password concatenated into an XPath expression | Covers authentication bypass in XML query scenarios |

### URL Redirect Tests

Page: `/other/URLRedirect/vul`, `/other/URLRedirect/safe`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Vulnerable page | `GET /other/URLRedirect/vul` | Logged-in session | The page opens normally, showing six redirect implementations |
| Spring redirect | `GET /other/URLRedirect/vul1?url=http://example.com` | External URL | Returns 302, and `Location` points to the external URL |
| ModelAndView redirect | `GET /other/URLRedirect/vul2?url=http://example.com` | External URL | Returns 302, and `Location` points to the external URL |
| Servlet setHeader | `GET /other/URLRedirect/vul3?url=http://example.com` | External URL | Returns 301, and `Location` points to the external URL |
| Servlet sendRedirect | `GET /other/URLRedirect/vul4?url=http://example.com` | External URL | Returns 302, and `Location` points to the external URL |
| ResponseEntity redirect | `GET /other/URLRedirect/vul5?url=http://example.com` | External URL | Returns 302, and `Location` points to the external URL |
| ResponseStatus redirect | `GET /other/URLRedirect/vul6?url=http://example.com` | External URL | Returns 302, and `Location` points to the external URL |
| Safe page | `GET /other/URLRedirect/safe` | Logged-in session | The page opens normally, showing internal forwarding and allowlist validation |
| Allowlist block | `GET /other/URLRedirect/safe2?url=http://example.com` | Non-allowlisted URL | Returns 403 and `Forbidden: url not in WhiteUrlList!` |
| Allowlist allow | `GET /other/URLRedirect/safe2?url=https://blog.csdn.net/weixin_53009585` | Allowlisted domain | Returns 302 and allows the redirect |

### XFF Spoofing Tests

Page: `/other/xff`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /other/xff` | Logged-in session | The page opens normally, showing XFF vulnerabilities and trusted-proxy safe scenarios |
| Original IP access | `GET /other/xff/vul1` | No XFF header | The page shows the real connection source and does not leak sensitive information limited to 8.8.8.8 |
| XFF spoofing vulnerability | `GET /other/xff/vul2?xff=true` | Header `X-Forwarded-For: 8.8.8.8` | Returns sensitive information, showing that the client header is directly trusted |
| XFF disabled | `GET /other/xff/vul2?xff=false` | Header `X-Forwarded-For: 8.8.8.8` | Uses the real connection source and does not return sensitive information |
| Safe block | `GET /other/xff/safe?xff=true` | Direct local connection with spoofed XFF | Returns "Untrusted proxy source, ignoring XFF header" and does not leak sensitive information |

### DoS Tests

Page: `/other/dos`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /other/dos` | Logged-in session | The page opens normally, showing image resource consumption, image size limits, and ZIP extraction scenarios |
| Controllable image parameters | `GET /other/dos/vul?width=1200&height=1200` | Large width and height | Returns an image, showing that the server allocates resources based on user input |
| Image size blocked | `GET /other/dos/safe?width=1200&height=1200` | Width/height above the limit | Returns 400 and "Image size exceeds the limit" |
| Normal image generation | `GET /other/dos/safe?width=300&height=120` | Reasonable width/height | Returns a JPEG image |
| ZIP upload empty file | `POST /other/dos/vul2` | No file uploaded | Returns "Please select a ZIP file first" |
| ZIP extraction resource consumption | `POST /other/dos/vul2` | ZIP file | The server tries to extract it, and recursive ZIPs or many files can cause resource pressure |

### XPath Injection Tests

Page: `/other/xpath`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /other/xpath` | Logged-in session | The page opens normally, showing XPath injection and variable-binding safe scenarios |
| Normal authentication | `GET /other/xpath/vul?username=admin&password=password` | Correct username and password | Returns authentication passed |
| Universal-condition bypass | `GET /other/xpath/vul?username=admin&password=' or '1'='1` | XPath injection payload | Returns authentication passed, showing that the expression was modified by concatenation |
| Safe block | `POST /other/xpath/safe` | `username=admin&password=' or '1'='1` | Returns authentication failed |
| Safe normal authentication | `POST /other/xpath/safe` | `username=admin&password=password` | Returns authentication passed |

## Sensitive Information Disclosure

Current coverage includes four scenarios: JavaScript front-end leaks, directory traversal, leftover test pages, and backup-file leaks. The focus of this module is not a single dangerous API, but the fact that content that should never be exposed to users has been placed in accessible locations: front-end code, build artifacts, directory listings, test tools, source archives, logs, and temporary files can all become attack entry points.

The remediation core for sensitive-information disclosure is minimizing exposure and checking before release: keys, authentication logic, internal APIs, and sensitive config must not enter the front end; static directories should not contain backups, logs, or test files; directory listing and test pages should be disabled by default; any diagnostic entry that must remain should have strong authentication, allowlisting, auditing, timeouts, and input restrictions; leaked keys, tokens, cookies, and passwords should be rotated immediately.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| JS leaks | Hard-coded front-end credentials, Webpack bundle leaking cloud keys | Covers common sensitive information leaks in front-end source and build artifacts |
| Directory traversal | Controllable directory listing, blacklist filtering, root-directory restriction | Covers risks of file-name, path, and resource discovery from directory browsing features |
| Test pages | Leftover Ping page, command concatenation, safe Ping comparison | Covers exposed test entry points and high-risk chains caused by improper input handling |
| Backup files | Web source archives, log files | Covers leakage of source, config, SQL, Session, and debug logs |

### JS Leak Tests

Page: `/infoLeak/js`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /infoLeak/js` | Logged-in session | The page opens normally, showing front-end hard-coding and Webpack leak scenarios |
| Front-end hard-coded page | `GET /infoLeak/js/hard-coding` | None | Returns the login page, and the page source contains hard-coded account credentials |
| Front-end hard-coded login | Browser submits `/infoLeak/js/hard-coding` | `superadmin` / `Admin@1024.com` | Redirects to `/infoLeak/js/loginSuccess` |
| Webpack leaked JS | `GET /other/infoleak/chunk-0226s3f2.57e3ed6f.js` | None | Returns a JS file containing sensitive configuration such as `SecretId`, `SecretKey`, and Bucket values |

### Directory Traversal Tests

Page: `/infoLeak/dirTraversal`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /infoLeak/dirTraversal` | Logged-in session | The page opens normally, showing directory traversal vulnerabilities and two safe patterns |
| Directory listing vulnerability | `GET /infoLeak/dirTraversal/vul?dir=/` | Root directory parameter | Returns the static directory listing |
| Directory traversal attempt | `GET /infoLeak/dirTraversal/vul?dir=../` | `../` | May list parent-directory content outside the static directory |
| Blacklist block | `GET /infoLeak/dirTraversal/safe1?dir=../` | `../` | Returns "Illegal character!" |
| Root directory restriction | `GET /infoLeak/dirTraversal/safe2?dir=../` | `../` | Returns `Directory not found or access denied.` |
| Safe directory access | `GET /infoLeak/dirTraversal/safe2?dir=/` | Root directory parameter | Only returns the file list within the allowed root directory |

### Test Page Tests

Page: `/infoLeak/ceShiPage`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /infoLeak/ceShiPage` | Logged-in session | The page opens normally, showing a leftover Ping test entry |
| Ping page | `GET /infoLeak/ceShiPage/pingPage` | None | The page opens normally, showing vulnerable Ping and safe Ping forms |
| Command concatenation vulnerability | `GET /infoLeak/ceShiPage/ping?ip=127.0.0.1%20%26%20whoami` | `127.0.0.1 & whoami` | Returns ping output and may append the current process user, showing that shell metacharacters are effective |
| Safe Ping blocked | `GET /infoLeak/ceShiPage/safePing?ip=127.0.0.1%20%26%20whoami` | Input containing `&` | Returns "Invalid target address" |
| Safe Ping normal | `GET /infoLeak/ceShiPage/safePing?ip=127.0.0.1` | Valid address | Returns ping output or the system ping result |

### Backup File Tests

Page: `/infoLeak/backUp`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /infoLeak/backUp` | Logged-in session | The page opens normally, showing source backup and log leak scenarios |
| Source archive download | `GET /other/infoleak/www.zip` | None | Returns a downloadable archive, showing that source backup files are exposed in the Web directory |
| Log file access | `GET /other/infoleak/JavaSecLab_logs.txt` | None | Returns log content containing sensitive information such as SQL, account data, SessionId, and captcha values |

## Login Confrontation

Current coverage includes four main lines: account security, login bypass, JavaScript reverse engineering, and credential security. Account security includes username enumeration and weak passwords; login bypass includes bypassing by modifying the response packet and bypassing password-reset steps; JavaScript reverse engineering includes client-side signature reproduction and bypassing front-end RSA encryption; credential security includes JWT claim forgery.

The essence of login-confrontation issues is that the authentication flow places key trust in the wrong place: error messages reveal account state, password strength is too low, the server trusts client responses or step state, front-end algorithms and keys can be reversed, and token claims are overtrusted. The fix should unify authentication-failure messages, enforce strong passwords and rate limiting, perform all authentication state, flow state, and authorization checks on the server, and combine that with MFA, risk control, auditing, short-lived tokens, and key rotation.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| Account security | Username enumeration, weak passwords | Covers the most common information disclosure and low-strength password risks at the authentication entry |
| Login bypass | Modifying the response packet to bypass, bypassing password-reset steps | Covers trusting client-side state and missing server-side prechecks in multi-step flows |
| JS reverse engineering | Sign-request bypass, front-end RSA-encryption bypass | Covers the common misconception that front-end algorithms and fixed keys can be used as a security boundary |
| Credential security | JWT claim forgery | Covers privilege abuse caused by static keys and overtrusting the role claim in tokens |

### Account Security Tests

Page: `/loginconfront/account`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /loginconfront/account` | Logged-in session | The page opens normally, showing username enumeration and weak password scenarios |
| Username does not exist | `POST /loginconfront/account/vul1` | `username=qwer&password=x` | Returns "User does not exist!", allowing the attacker to infer that the account is absent |
| Username exists but password is wrong | `POST /loginconfront/account/vul1` | `username=admin&password=wrong` | Returns "Password is incorrect, please try again!", allowing the attacker to infer that the account exists |
| Username enumeration login success | `POST /loginconfront/account/vul1` | `username=admin&password=admin123` | Returns login success |
| Weak password hit | `POST /loginconfront/account/vul2` | `username=admin&password=admin` | Returns login success, showing that the default/weak password can directly break authentication |
| Weak password failure message | `POST /loginconfront/account/vul2` | `username=admin&password=wrong` | Returns the unified "Account or password incorrect!" message |

### Login Bypass Tests

Page: `/loginconfront/bypass`, `/loginconfront/bypass/reset`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /loginconfront/bypass` | Logged-in session | The page opens normally, showing response-modification bypass and password-reset step bypass scenarios |
| First-step validation failure | `POST /loginconfront/bypass/vul1step1` | `username=admin&password=wrong` | Returns "Account validation failed, please try again!" |
| First-step validation success | `POST /loginconfront/bypass/vul1step1` | `username=admin&password=admin123` | Returns "Account validation passed, please wait!" |
| Response-packet modification bypass point | `POST /loginconfront/bypass/vul1step2` | `code=0` | Returns "Login successful, welcome!", showing that the second step trusts the success state sent by the client |
| Password reset page | `GET /loginconfront/bypass/reset` | Logged-in session | The page opens normally, showing a three-step password reset flow |
| Username step | `POST /loginconfront/bypass/step1` | `username=admin` | Returns "Username verification successful!" |
| Old password wrong | `POST /loginconfront/bypass/step2` | `oldPassword=bad` | Returns "Old password incorrect!" |
| Normal old-password validation | `POST /loginconfront/bypass/step2` | `oldPassword=!@#qwf@3123` | Returns "Password verification successful!" |
| Skip presteps to reset | `POST /loginconfront/bypass/step3` | `newPassword=newpass123` | Even if the old-password check was not completed, it still returns "Password reset successful!", showing that the back end lacks strict step-state validation |

### JS Reverse Engineering Tests

Page: `/loginconfront/reverse`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /loginconfront/reverse` | Logged-in session | The page opens normally, showing sign-request bypass and front-end RSA-encryption bypass scenarios |
| Missing / wrong sign | `POST /loginconfront/reverse/vul1` | Incorrect `sign` | Returns "Signature verification failed" |
| Reproduced sign success | `POST /loginconfront/reverse/vul1` | MD5 signature generated using the front-end fixed key and parameter concatenation rules | Returns "Login successful! Username: admin, password: admin123" |
| Sign does not match parameters | `POST /loginconfront/reverse/vul1` | Password changed but old sign reused | Returns "Signature verification failed" |
| RSA ciphertext error | `POST /loginconfront/reverse/vul2` | Invalid ciphertext or wrong field | Returns "Decryption failed!" |
| Front-end RSA encryption reproduced | `POST /loginconfront/reverse/vul2` | Encrypt `admin/admin123` using the page public key | Returns login success, showing that public-key encryption cannot prove the request came from a trusted front end |

### Credential Security Tests

Page: `/loginconfront/credential`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /loginconfront/credential` | Logged-in session | The page opens normally, showing JWT claim forgery scenarios |
| Generate JWT | `GET /loginconfront/credential/generate-jwt?username=admin&role=admin` | Any username and role claim | Returns a signed JWT |
| Missing JWT | `GET /loginconfront/credential/vul1` | No `Auth_Token` header | Returns "Missing Auth_Token request header" |
| Invalid JWT | `GET /loginconfront/credential/vul1` | Header `Auth_Token: bad.jwt.token` | Returns JWT parsing failure |
| JWT parsed successfully | `GET /loginconfront/credential/vul1` | Header carrying the generated JWT | Returns `user:admin,role:admin`, showing that the server trusts the role claim in the token |

# Java Topics

## Spring Boot Framework-Related Vulnerabilities

Current coverage includes four common risks in the Spring Boot ecosystem: Swagger/OpenAPI documentation exposure, sensitive Spring Boot Actuator endpoints, Druid console exposure, and MySQL JDBC deserialization. The focus is not the Spring Boot framework itself, but the exposure surface that appears when development and operations helper features are carried into production.

The essence of Spring Boot-related vulnerabilities is usually poor management of configuration boundaries and runtime exposure: API docs, management endpoints, consoles, data-source connections, and driver parameters are meant for development, operations, or internal systems, but become reachable from the public network or ordinary users. The fix should follow the principle of minimal exposure in production: disable unnecessary components, add authentication and internal-network restrictions to management entry points, redact sensitive endpoints, prohibit user-controlled JDBC URLs, and avoid Java native deserialization of untrusted data.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| Swagger/OpenAPI | `/v3/api-docs`, Swagger UI | Covers interface-document exposure without authentication, leading to leakage of endpoints, parameters, and model information |
| Actuator | `/sys/actuator`, `/sys/actuator/health` | Covers management-endpoint exposure and health-detail leakage |
| Druid console | `/druid/index.html` | Covers exposure of the connection-pool console, leaking SQL, URI, Session, and data-source information |
| MySQL JDBC deserialization | `/springboot/vul`, `/springboot/insert`, `/springboot/jdbc` | Covers the risk chain of untrusted JDBC URLs and native deserialization of byte streams read from the database |

### Spring Boot Page and Resource Tests

Page: `/springboot`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /springboot` | Logged-in session | The page opens normally, showing the four categories: Swagger, Actuator, Druid, and MySQL JDBC |
| Swagger traffic sample | `GET /other/datapackage/springboot/swagger_ui.pcapng` | None | Returns a downloadable traffic sample |
| Actuator traffic sample | `GET /other/datapackage/springboot/actuator.pcapng` | None | Returns a downloadable traffic sample |
| Druid traffic sample | `GET /other/datapackage/springboot/druid.pcapng` | None | Returns a downloadable traffic sample |
| MySQL JDBC traffic sample | `GET /other/datapackage/springboot/mysql_jdbc.pcapng` | None | Returns a downloadable traffic sample |

### Swagger/OpenAPI Exposure Tests

Page: `/springboot`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| OpenAPI JSON | `GET /v3/api-docs` | Logged-in session | Returns the OpenAPI document, containing interface descriptions such as `openapi` and `paths` |
| Swagger UI | `GET /swagger-ui/index.html` | Logged-in session | The Swagger UI page is accessible |
| Risk confirmation | View the contents of `/v3/api-docs` | None | You can see the back-end endpoint paths, parameters, and model information, showing that the documentation is not isolated in production |

### Actuator Exposure Tests

Page: `/springboot`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Actuator root endpoint | `GET /sys/actuator` | Logged-in session | Returns `_links`, listing the accessible management endpoints |
| Health details | `GET /sys/actuator/health` | Logged-in session | Returns `status` and component details |
| Mappings endpoint | `GET /sys/actuator/mappings` | Logged-in session | Returns application request-mapping information, showing that routes can be enumerated |

### Druid Console Exposure Tests

Page: `/springboot`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Druid home | `GET /druid/index.html` | No login required or logged-in session | Returns the Druid monitoring page |
| Druid data-source info | `GET /druid/datasource.json` | No login required or logged-in session | Returns data-source monitoring JSON |
| Druid URI statistics | `GET /druid/weburi.json` | No login required or logged-in session | Returns Web URI access statistics |

### MySQL JDBC Deserialization Tests

Page: `/springboot`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Missing JDBC URL | `GET /springboot/vul` | No `url` parameter | Returns "JDBC URL cannot be empty" |
| Fake MySQL connection attempt | `GET /springboot/vul?url=jdbc:mysql://127.0.0.1:1/test&username=root&password=x` | Unavailable MySQL address | Returns JDBC connection failure, showing that the server uses the user-supplied JDBC URL to initiate the connection |
| Insert test object | `GET /springboot/insert?command=true` | Safe test command `true` | Returns "Malicious object inserted successfully!" |
| Trigger local deserialization chain | `GET /springboot/jdbc` | Depends on the object written in the previous step | Returns "Triggered MYSQL-JDBC deserialization vulnerability!" |

## SpEL Expression Injection

Current coverage includes native SpEL expression execution and the `SimpleEvaluationContext` safe-context restriction scenario. The module mainly demonstrates the process where untrusted input enters `SpelExpressionParser.parseExpression()` directly and is executed through `Expression.getValue()`, upgrading expression evaluation from dynamic computation to type references, static method calls, and command execution.

The essence of SpEL injection is that untrusted input enters the expression's "executable context" and changes the original business-computation semantics. `StandardEvaluationContext` is relatively complete and suitable for trusted internal expressions, but not for directly executing user input. The fix should avoid parsing untrusted expressions. When expression capability is truly needed, use `SimpleEvaluationContext`, fixed templates, allowlisted expressions, parameter binding, and a least-privilege context, and prohibit Java type references, constructors, Bean references, and arbitrary method calls.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| Expression probing | `100-1` | Covers the basic expression-execution capability and can be used to identify whether expressions are being parsed |
| Type reference | `T(java.lang.Math).abs(-1)` | Covers `T()` type references and static method-call capability |
| Command execution | `T(java.lang.Runtime).getRuntime().exec('true')` | Covers the high-risk chain from method call to system command execution |
| Safe context | `/spel/safe` uses `SimpleEvaluationContext` | Covers restrictions on type references, constructors, Bean references, and similar capabilities |

### SpEL Vulnerability Scenario Tests

Page: `/spel`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /spel` | Logged-in session | The page opens normally, showing native vulnerability scenarios and `SimpleEvaluationContext` safe scenarios |
| Arithmetic expression probing | `GET /spel/vul?ex=100-1` | `100-1` | Returns `99`, showing that the input is parsed and executed as a SpEL expression |
| Type reference probing | `GET /spel/vul?ex=T(java.lang.Math).abs(-1)` | Java type reference | Returns `1`, showing that `StandardEvaluationContext` allows type references and static method calls |
| Command execution chain | `GET /spel/vul?ex=T(java.lang.Runtime).getRuntime().exec('true')` | Safe test command `true` | Returns a `Process`-related object string or execution-result object, showing that the command-execution sink is reachable |
| Invalid expression | `GET /spel/vul?ex=T(java.lang.Runtime).getRuntime().exec(` | Syntax error expression | Returns "SPEL expression execution failed" |
| Traffic sample download | `GET /other/datapackage/spel/spel.pcapng` | None | Returns a downloadable traffic sample |

### SpEL Safe Scenario Tests

Page: `/spel`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Safe arithmetic expression | `GET /spel/safe?ex=100-1` | `100-1` | Returns `99`, showing that low-risk expressions can still be evaluated |
| Block type reference | `GET /spel/safe?ex=T(java.lang.Math).abs(-1)` | Java type reference | Returns "Expression is restricted by the safe context", showing that type references are forbidden |
| Block command execution | `GET /spel/safe?ex=T(java.lang.Runtime).getRuntime().exec('true')` | Command-execution expression | Returns "Expression is restricted by the safe context" and does not execute system commands |
| Safe scenario error handling | `GET /spel/safe?ex=T(java.lang.Runtime).getRuntime().exec(` | Syntax error expression | Returns "Expression is restricted by the safe context" or a parsing error message |

## SSTI Template Injection

Current coverage includes two typical Thymeleaf view-name injection triggers: a controllable Controller return value and a URL path parameter concatenated into the view name. The module mainly demonstrates that after untrusted input enters the server-side template parsing context, the `__${...}__` preprocessing expression is evaluated by Thymeleaf first and then enters the template-name or fragment-parsing flow.

The essence of SSTI is that untrusted input enters the template's "executable context." In Java Web applications, risk entry points include not only page content, but also view names, fragment expressions, mail templates, report templates, dynamic template content, and multi-template-engine configurations. The fix should avoid letting users control template names, template paths, fragments, or template content; when selecting templates dynamically, use fixed enum or allowlist mappings; when returning plain strings, use `@ResponseBody`, `ResponseEntity`, or explicit writing to `HttpServletResponse` to avoid entering view resolution; and prefer automatic escaping for variable output while using `th:utext` cautiously.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| Controllable return view name | `/ssti/vul1?para=...` | Covers a Controller directly concatenating user input into the view name, causing Thymeleaf preprocessing expressions to execute |
| URL path concatenated into view name | `/ssti/vul2/{path}` | Covers a path variable concatenated into the view name and then triggering Thymeleaf preprocessing expressions |
| Allowlist template selection | `/ssti/safe1?para=...` | Covers allowing only fixed template names and rejecting expressions from entering the template path |
| Skip view resolution | `/ssti/safe2/{path}` | Covers writing directly to the response body so Thymeleaf view resolution is no longer triggered |
| Output boundary | `/ssti/vul3?para=...` | Currently outputs only a string through `th:utext`; it does not execute the input as a template expression and should be categorized as an HTML output / XSS boundary rather than the main SSTI scenario |

### SSTI Vulnerability Scenario Tests

Page: `/ssti`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /ssti` | Logged-in session | The page opens normally, showing controllable-return, controllable-URL, and safe-comparison scenarios |
| Controllable return arithmetic probing | `GET /ssti/vul1?para=__${7*7}__::.x` | Thymeleaf preprocessing expression | Returns 500, and the template name in the error message contains `vul/ssti/49`, showing that the expression was executed |
| Controllable return command chain | `GET /ssti/vul1?para=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x` | Safe test command `id` | Returns 500, and the template name in the error message is replaced by a command-output fragment, showing that the command-execution sink is reachable |
| Controllable URL arithmetic probing | `GET /ssti/vul2/__${7*7}__::.x` | Thymeleaf preprocessing expression | Returns 500, and the template name in the error message contains `vul/ssti/49`, showing that the expression was executed |
| Output boundary | `GET /ssti/vul3?para=__${7*7}__::.x` | Template expression string | The page outputs `__${7*7}__::.x` as-is and does not execute the expression |
| Return traffic sample download | `GET /other/datapackage/ssti/ssti_return.pcapng` | None | Returns a downloadable traffic sample |
| URL traffic sample download | `GET /other/datapackage/ssti/ssti_url.pcapng` | None | Returns a downloadable traffic sample |

### SSTI Safe Scenario Tests

Page: `/ssti`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Allowlisted template | `GET /ssti/safe1?para=ssti` | Allowlisted template name | Returns the SSTI module page |
| Allowlisted expression rejected | `GET /ssti/safe1?para=__${7*7}__::.x` | Thymeleaf preprocessing expression | Returns a 401 page and the expression does not enter the view name |
| Skip view resolution | `GET /ssti/safe2/__${7*7}__::.x` | Thymeleaf preprocessing expression | Returns plain text "View resolution has been skipped..." and does not trigger Thymeleaf parsing |

## Deserialization

Current coverage includes three Java deserialization entry points: Java native `ObjectInputStream.readObject()`, SnakeYAML `Yaml.load()`, and XMLDecoder `readObject()`. The module mainly demonstrates that when "untrusted data is restored into an object," attackers can use object graphs, type tags, constructors, setters, `readObject`, or component gadget chains to upgrade a normal data parsing entry into risks such as code execution, class loading, file operations, or denial of service.

The essence of deserialization vulnerabilities is that untrusted input enters the object-construction and method-call context. The preferred fix is to avoid using Java native serialization protocols to receive external input. When parsing is truly necessary, JSON/XML/YAML should be bound as plain data to fixed DTOs, arbitrary type parsing should be disabled, and you should use type allowlists, JEP 290 `ObjectInputFilter`, `SafeConstructor`, dependency upgrades, external-entity disabling, size limits, and isolated execution. A blacklist alone or turning off one gadget switch only reduces specific exploitation chains and should not be considered a complete fix.

Covered types

| Category | Existing Scenarios | Conclusion |
| --- | --- | --- |
| JDK native deserialization | `/readObject/vul`, `/readObject/safe1`, `/readObject/safe2` | Covers `ObjectInputStream` reading untrusted byte streams directly, along with gadget-switch and type-allowlist comparisons |
| SnakeYAML | `/snakeYaml/vul`, `/snakeYaml/safe` | Covers the default `Constructor` instantiating objects according to `!!ClassName`, and `SafeConstructor` parsing only basic types |
| XMLDecoder | `/xmlDecoder/vul`, `/xmlDecoder/safe` | Covers XMLDecoder executing method calls through an object graph, and replacing it with a normal XML parser instead of dangerous object deserialization |

### ReadObject Tests

Page: `/readObject`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /readObject` | Logged-in session | The page opens normally, showing native deserialization, gadget-switch, and allowlist safe scenarios |
| Empty payload | `POST /readObject/vul` | No `payload` provided | Returns "Payload cannot be empty" or a payload error message, and the page does not show a 500 |
| Benign object deserialization | `POST /readObject/vul` | `payload=rO0ABXQACkphdmFTZWNMYWI=` | Returns `JavaSecLab`, showing that the server executed `ObjectInputStream.readObject()` |
| Commons Collections switch | `POST /readObject/safe1` | Use the sample payload shown on the page | Returns execution failure or a disabled message, showing that a specific gadget chain is restricted; this is not a complete defense |
| Type allowlist | `POST /readObject/safe2` | Use the sample gadget payload shown on the page | Returns deserialization failure, showing that non-allowlisted classes are rejected; protocol-native types such as `String` may still pass and should be further restricted with JEP 290 |

### SnakeYAML Tests

Page: `/snakeYaml`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /snakeYaml` | Logged-in session | The page opens normally, showing the comparison between default `Constructor` and `SafeConstructor` |
| Default type instantiation | `POST /snakeYaml/vul` | `payload=!!top.whgojp.modules.sqli.entity.Sqli {id: 1, username: test, password: pass}` | The parsing result contains `Sqli` object information, showing that `!!ClassName` was instantiated |
| Safe parsing of normal YAML | `POST /snakeYaml/safe` | `payload=name: JavaSecLab` | Returns a normal Map parsing result |
| Block Java type tags | `POST /snakeYaml/safe` | `payload=!!top.whgojp.modules.sqli.entity.Sqli {id: 1, username: test, password: pass}` | Returns deserialization failure, showing that `SafeConstructor` does not allow arbitrary Java type construction |

### XMLDecoder Tests

Page: `/xmlDecoder`

| Scenario | Request | Test Input | Expected Result |
| --- | --- | --- | --- |
| Page access | `GET /xmlDecoder` | Logged-in session | The page opens normally, showing XMLDecoder object-graph execution and a normal XML parser comparison |
| Empty payload | `POST /xmlDecoder/vul` | No `payload` provided | Returns "Payload cannot be empty" |
| XMLDecoder command-execution chain | `POST /xmlDecoder/vul` | `payload=true` | Returns "Command executed successfully", showing that XMLDecoder constructed and started ProcessBuilder |
| Normal XML parser comparison | `POST /xmlDecoder/safe` | `payload=true` | Returns "Command parsed successfully:true", only parses the text parameter and does not call `ProcessBuilder.start()` |
| Empty payload in safe scenario | `POST /xmlDecoder/safe` | No `payload` provided | Returns "Payload cannot be empty", and the page does not show a 500 |
