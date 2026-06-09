/**
 * @description 存放静态代码
 * @author:  whgojp
 * @email:  whgojp@foxmail.com
 * @Date: 2024/5/19 19:03
 */
const vul1ReflectRaw = "// 原生漏洞场景，未加任何过滤，Controller接口返回JSON类型结果\n" +
    "public R vul1(String payload) {\n" +
    "    return R.ok(payload);\n" +
    "}\n" +
    "// R 是对返回结果的封装工具util\n" +
    "// 返回结果：\n" +
    "// {\n" +
    "//     \"msg\": \"<script>alert(document.cookie)</script>\",\n" +
    "//     \"code\": 0\n" +
    "// }\n" +
    "// JSON响应本身通常不会直接执行脚本；前端若把字段用innerHTML等方式写入页面，才会触发XSS\n" +
    "\n" +
    "// 原生漏洞场景,未加任何过滤，Controller接口返回String类型结果\n" +
    "public String vul2(String payload) {\n" +
    "    return payload;\n" +
    "}"
const vul2ReflectContentType = "// Tomcat内置HttpServletResponse，Content-Type导致反射XSS\n" +
    "public void vul3(String type,String payload, HttpServletResponse response) {\n" +
    "    switch (type) {\n" +
    "        case \"html\":\n" +
    "            response.getWriter().print(payload);\n" +
    "            response.setContentType(\"text/html;charset=utf-8\");\n" +
    "            response.getWriter().flush();\n" +
    "            break;\n" +
    "        case \"plain\":\n" +
    "            response.getWriter().print(payload);\n" +
    "            response.setContentType(\"text/plain;charset=utf-8\");\n" +
    "            response.getWriter().flush();\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const safe1CheckUserInput = "// 使用白名单限制输入格式，适合约束字段类型；最终仍需根据输出位置进行上下文编码\n" +
    "// 前端校验代码\n" +
    "var whitelistRegex = /^[a-zA-Z0-9_\\s]+$/;\n" +
    "\n" +
    "// 检查输入值是否符合白名单要求\n" +
    "if (!whitelistRegex.test(value)) {\n" +
    "\tlayer.msg('输入内容包含非法字符，请检查输入', {icon: 2, offset: '10px'});\n" +
    "\treturn false; // 取消表单提交\n" +
    "    } else {\n" +
    "    \t// 正常发送请求\n" +
    "    }\n" +
    "\n" +
    "// 后端校验代码\n" +
    "private static final String WHITELIST_REGEX = \"^[a-zA-Z0-9_\\\\s]+$\";\n" +
    "private static final Pattern pattern = Pattern.compile(WHITELIST_REGEX);\n" +
    "\n" +
    "Matcher matcher = pattern.matcher(payload);\n" +
    "if (matcher.matches()){\n" +
    "    return R.ok(payload);\n" +
    "}else return R.error(\"输入内容包含非法字符，请检查输入\");"
const safe2CSP = "// 内容安全策略（Content Security Policy）是浏览器实施的额外防护层，可降低恶意脚本加载和执行风险，但不能替代输出编码与安全DOM/模板用法\n" +
    "// 前端Meta配置\n" +
    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self' https://apis.example.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' data: https://*.example.com;\">\n" +
    "\n" +
    "\n" +
    "// 后端Header配置\n" +
    "public String safe2(String payload,HttpServletResponse response) {\n" +
    "    response.setHeader(\"Content-Security-Policy\", \"default-src 'self'; script-src 'self'\");\n" +
    "    response.setHeader(\"Content-Security-Policy-Report-Only\", \"default-src 'self'; report-uri /xss/reflect/csp-report-endpoint\");\n" +
    "    return payload;\n" +
    "}"

const safe3EntityEscape = '// HTML正文输出编码会将特殊字符转换为HTML实体，避免浏览器把不可信数据解析为标签或脚本\n' +
    '// 注意：HTML属性、URL、JavaScript字符串、CSS等不同上下文需要使用不同的编码或白名单校验策略\n' +
    'public R safe3(@ApiParam(String type, String payload) {\n' +
    '    String filterContented = "";\n' +
    '    switch (type){\n' +
    '        case "manual":\n' +
    '            payload = StringUtils.replace(payload, "&", "&amp;");\n' +
    '            payload = StringUtils.replace(payload, "<", "&lt;");\n' +
    '            payload = StringUtils.replace(payload, ">", "&gt;");\n' +
    '            payload = StringUtils.replace(payload, "\\"", "&quot;");\n' +
    '            payload = StringUtils.replace(payload, "\'", "&#x27;");\n' +
    '            payload = StringUtils.replace(payload, "/", "&#x2F;");\n' +
    '            filterContented = payload;\n' +
    '            break;\n' +
    '        case "spring":\n' +
    '            filterContented = HtmlUtils.htmlEscape(payload);\n' +
    '            break;\n' +
    '            ...\n' +
    '    }\n' +
    '}'

const safe4HttpOnly = "// HttpOnly可以阻止客户端脚本直接读取带有该属性的Cookie，降低XSS窃取Cookie的影响，但不能修复XSS本身\n" +
    "// 单个接口配置\n" +
    "public R safe4(String payload, HttpServletRequest request,HttpServletResponse response) {\n" +
    "    Cookie cookie = request.getCookies()[0];\n" +
    "    cookie.setHttpOnly(true); // 设置为 HttpOnly\n" +
    "    cookie.setMaxAge(600);  // 这里设置生效时间为十分钟\n" +
    "    cookie.setPath(\"/\");\n" +
    "    response.addCookie(cookie);\n" +
    "    return R.ok(payload);\n" +
    "}\n" +
    "\n" +
    "// 全局配置\n" +
    "// application.yml配置\n" +
    "server:\n" +
    "  servlet:\n" +
    "    session:\n" +
    "      cookie:\n" +
    "        http-only: true\n" +
    "\n" +
    "// 2、Springboot配置类\n" +
    "@Configuration\n" +
    "public class ServerConfig {\n" +
    "    @Bean\n" +
    "    public WebServerFactoryCustomizer<ConfigurableWebServerFactory> webServerFactoryCustomizer() {\n" +
    "        return factory -> {\n" +
    "            Session session = new Session();\n" +
    "            session.getCookie().setHttpOnly(true);\n" +
    "            factory.setSession(session);\n" +
    "            ...\n" +
    "}"

const vul1StoreRaw = "// 原生漏洞场景，未加任何过滤，将用户输入和User-Agent持久化；后续页面不安全渲染时触发存储型XSS\n" +
    "// Controller层\n" +
    "public R vul(String payload,HttpServletRequest request) {\n" +
    "    String ua = request.getHeader(\"User-Agent\");\n" +
    "    final int code = xssService.insertOne(payload,ua);\n" +
    "    ...\n" +
    "}\n" +
    "// Service层\n" +
    "public int insertOne(String content, String ua) {\n" +
    "    final int code = xssMapper.insertAll(content,ua,DateUtil.now());\n" +
    "    return code;\n" +
    "}\n" +
    "// Mapper层\n" +
    "int insertAll(String content,String ua,String date);\n" +
    "\n" +
    "<insert id=\"insertAll\">\n" +
    "    insert into xss\n" +
    "        (content,ua, date)\n" +
    "    values (#{content,jdbcType=VARCHAR},#{ua,jdbcType=VARCHAR}, #{date,jdbcType=VARCHAR})\n" +
    "</insert>"

const safe1StoreEntityEscape = "// 表格数据渲染：数据库仍保存原始值，输出到HTML页面前按HTML正文文本编码\n" +
    "table.render({\n" +
    "\t...\n" +
    "    cols: [\n" +
    "        {field: 'id', title: 'ID', sort: true, width: '60', fixed: 'left'},\n" +
    "        {field: 'content', title: 'Content', width: '200', templet: function(d){\n" +
    "                return escapeHtml(d.content); \n" +
    "            }},\n" +
    "        {field: 'ua', title: 'User-Agent', width: '200', templet: function(d){\n" +
    "                return escapeHtml(d.ua); \n" +
    "            }},\n" +
    "      \t...\n" +
    "// 方法一、HTML正文输出编码函数\n" +
    "function escapeHtml(html) {\n" +
    "    if (html === null || html === undefined) {\n" +
    "        return '';\n" +
    "    }\n" +
    "    var text = document.createElement(\"textarea\");\n" +
    "    text.textContent = String(html);\n" +
    "    return text.innerHTML;\n" +
    "}\n" +
    "// 方法二、JavaScript的文本节点\n" +
    "var textNode = document.createTextNode(htmlContent);\n" +
    "element.appendChild(textNode);\n" +
    "// 方法三、jQuery的text()方法\n" +
    "$('#element').text(htmlContent);\n"

const vul1DomRaw = "// 1. innerHTML XSS\n" +
    "form.on('submit(vul1-dom-raw)', function (data) {\n" +
    "    var userInput = document.getElementById('vul1-dom-raw-input').value;\n" +
    "    var outputDiv = document.getElementById('vul-dom-raw-result');\n" +
    "    outputDiv.innerHTML = userInput;  // 漏洞点：直接使用innerHTML插入用户输入\n" +
    "    return false;\n" +
    "});\n" +
    "\n" +
    "// 2. LocalStorage XSS\n" +
    "form.on('submit(vul3-dom-raw-submit)', function (data) {\n" +
    "    localStorage.setItem('vul4-dom-raw', document.getElementById('vul4-dom-raw-input').value);\n" +
    "    var storedData = localStorage.getItem('vul4-dom-raw');\n" +
    "    document.getElementById('vul-dom-raw-result').innerHTML = storedData;  // 漏洞点：从存储读取后直接插入\n" +
    "    return false;\n" +
    "});\n" +
    "\n" +
    "// 3. href跳转XSS\n" +
    "var hash = location.hash;\n" +
    "if(hash){\n" +
    "    var url = hash.substring(1);  // 去掉#号\n" +
    "    console.log(url);\n" +
    "    location.href = url;  // 漏洞点：直接使用hash部分作为跳转URL\n" +
    "}\n" +
    "\n" +
    "// 4. Location对象XSS\n" +
    "form.on('submit(location-xss)', function(data) {\n" +
    "    var payload = data.field.locationPayload;\n" +
    "    window.location = payload;  // 漏洞点：直接使用用户输入修改location\n" +
    "    return false;\n" +
    "});\n" +
    "\n" +
    "// 5. Eval执行XSS\n" +
    "form.on('submit(eval-xss)', function(data) {\n" +
    "    var payload = data.field.evalPayload;\n" +
    "    eval(payload);  // 漏洞点：直接执行用户输入的JavaScript代码\n" +
    "    return false;\n" +
    "});\n" +
    "\n" +
    "// 6. Document对象XSS\n" +
    "form.on('submit(document-write)', function(data) {\n" +
    "    var payload = data.field.documentPayload;\n" +
    "    document.write(payload);  // 漏洞点：直接写入用户输入的HTML\n" +
    "    document.close();\n" +
    "    return false;\n" +
    "});\n" +
    "form.on('submit(document-domain)', function(data) {\n" +
    "    var payload = data.field.documentPayload;\n" +
    "    document.domain = payload;  // 风险点：直接修改document.domain会放宽同源边界或造成异常行为\n" +
    "    return false;\n" +
    "});"

const safeDomCode = "// 1. 普通文本输出：使用textContent，不解析HTML\n" +
    "document.getElementById('safe-dom-result').textContent = userInput;\n" +
    "\n" +
    "// 2. URL跳转：校验协议白名单，拒绝javascript:、data:等危险协议\n" +
    "var url = new URL(userInput, window.location.origin);\n" +
    "var allowedProtocols = ['http:', 'https:'];\n" +
    "if (allowedProtocols.indexOf(url.protocol) === -1) {\n" +
    "    throw new Error('dangerous protocol');\n" +
    "}\n" +
    "\n" +
    "// 3. 替代eval：使用命令白名单映射，而不是执行用户输入\n" +
    "var actions = {\n" +
    "    showTime: function () { return new Date().toLocaleString(); },\n" +
    "    showLocation: function () { return window.location.pathname; }\n" +
    "};\n" +
    "var action = actions[userInput];\n" +
    "if (action) {\n" +
    "    action();\n" +
    "}\n" +
    "\n" +
    "// 4. DOM API：创建文本节点，不拼接HTML字符串\n" +
    "var node = document.createTextNode(userInput);\n" +
    "element.appendChild(node);\n" +
    "\n" +
    "// 如果业务必须展示富文本，应先使用白名单HTML净化库处理后再渲染\n"

const vul1OtherUpload = "// 上传可被浏览器或预览服务解析的HTML/SVG/XML/PDF等文件，后续访问文件时可能触发XSS或内容安全问题\n" +
    "public String uploadFile(MultipartFile file, String suffix,String path) throws IOException {\n" +
    "    String uploadFolderPath = sysConstant.getUploadFolder();\n" +
    "    try {\n" +
    "        String fileName = +DateUtil.current() + \".\"+suffix;\n" +
    "        String newFilePath = uploadFolderPath + \"/\" + fileName;\n" +
    "\n" +
    "        file.transferTo(new File(newFilePath)); // 将文件保存到指定路径\n" +
    "        log.info(\"上传文件成功，文件路径：\" + newFilePath);\n" +
    "        return \"上传文件成功，文件路径：\" + path + fileName;\n" +
    "    } catch (IOException e) {\n" +
    "        e.printStackTrace(); // 打印异常堆栈信息\n" +
    "        log.info(\"文件上传失败\" + e.getMessage());\n" +
    "        return \"文件上传失败\" + e.getMessage();\n" +
    "    }\n" +
    "}"

const vul2OtherTemplate = "// th:utext会把内容作为HTML渲染；th:text会进行HTML转义\n" +
    "public String handleTemplateInjection(String payload,String type, Model model) {\n" +
    "    if (\"html\".equals(type)) {\n" +
    "        model.addAttribute(\"html\", payload);\n" +
    "    } else if (\"text\".equals(type)) {\n" +
    "        model.addAttribute(\"text\", payload);\n" +
    "    }\n" +
    "    return \"vul/xss/other\";\n" +
    "}\n" +
    "\n" +
    "<div class=\"layui-card-body layui-text layadmin-text\" style=\"color: red;font-size: 15px;\">\n" +
    "        <p th:utext=\"${html}\"></p>\n" +
    "        <p th:text=\"${text}\"></p>\n" +
    "</div>"
const vul3SCMSec = "// jQuery依赖\n" +
    "<head>\n" +
    "  <meta charset=\"utf-8\">\n" +
    "  <title>jQuery XSS Examples (CVE-2020-11022/CVE-2020-11023)</title>\n" +
    "  <!-- 测试JQuery -->\n" +
    "  <script src=\"/lib/jquery-1.6.1.js\"></script>\n" +
    "  <!-- <script src=\"./jquery.min.js\"></script> -->\n" +
    "</head>\n" +
    "\n" +
    "<!--swagger依赖-->\n" +
    "<dependency>\n" +
    "    <groupId>io.springfox</groupId>\n" +
    "    <artifactId>springfox-boot-starter</artifactId>\n" +
    "    <version>3.0.0</version>\t// 该版本存在xss\n" +
    "</dependency>\n" +
    "\n" +
    "// Ueditor编辑器未做任何限制 抓上传数据包后，可以上传任意类型文件";

const vulHtml5 = "1、PostMessage XSS\n" +
    "// 接收端：直接使用innerHTML插入消息\n" +
    "window.addEventListener('message', function(event) {\n" +
    "    // 故意不验证origin\n" +
    "    document.getElementById('messageContainer').innerHTML = event.data;\n" +
    "});\n" +
    "2、WebSocket XSS\n" +
    "// 客户端：直接使用innerHTML插入消息\n" +
    "ws.onmessage = function(event) {\n" +
    "    document.getElementById('wsMessageContainer').innerHTML = event.data;\n" +
    "};\n" +
    "// 服务端：直接广播用户输入\n" +
    "protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {\n" +
    "    broadcast(message.getPayload());\n" +
    "}"

const vul1RawJoint = "// Native SQL is dynamically concatenated without processing user-controlled parameters.\n" +
    "public R vul1(String type,String id,String username,String password) {\n" +
    "    // Register the database driver.\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "\n" +
    "    // Create a database connection through DriverManager.getConnection().\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "\n" +
    "    // Create a Statement object through Connection#createStatement().\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            // The id column is auto-incremented here.\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "            // Execute the SQL through Statement.\n" +
    "            // INSERT, UPDATE, and DELETE statements should use executeUpdate().\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            // Close ResultSet, Statement, and Connection objects to release resources.\n" +
    "            stmt.close();\n" +
    "            conn.close();\n" +
    "            return R.ok(message);\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET password = '\" + password + \"', username = '\" + username + \"' WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        }\n" +
    "}"

const vul2prepareStatementJoint = "// A PreparedStatement is created with conn.prepareStatement(sql), but stmt.executeUpdate(sql) still passes the full SQL string, so the precompiled parameter binding is not used.\n" +
    "public R vul2(String type,String id,String username,String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement stmt;\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = '\" + id + \"'\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = '\" + username + \"', password = '\" + password + \"' WHERE id = '\" + id + \"'\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const vul3JdbcTemplateJoint = "// JdbcTemplate is Spring's wrapper around JDBC; the underlying implementation is still JDBC.\n" +
    "public R vul3(String type,String id,String username,String password) {\n" +
    "    DriverManagerDataSource dataSource = new DriverManagerDataSource();\n" +
    "    dataSource.setDriverClassName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    dataSource.setUrl(dbUrl);\n" +
    "    dataSource.setUsername(dbUser);\n" +
    "    dataSource.setPassword(dbPass);\n" +
    "    JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "            // Spring JdbcTemplate manages connection acquisition and release automatically.\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = '\" + username + \"', password = '\" + password + \"' WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "            resultList = jdbctemplate.queryForList(sql);\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const safe1PrepareStatementParametric = "// Use precompilation with ? placeholders, also known as parameterized SQL.\n" +
    "public R safe1(String type,String id,String username,String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement stmt;\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            // The ? placeholders separate the SQL structure from parameter values.\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES (?, ?)\"; \n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            // Bind parameters.\n" +
    "            stmt.setString(1, username); \n" +
    "            stmt.setString(2, password);\n" +
    "            // With precompiled statements, do not pass the SQL string again.\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, id);\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = ?, password = ? WHERE id = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, username);  \n" +
    "            stmt.setString(2, password);\n" +
    "            stmt.setString(3, id);\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, id);\n" +
    "            ResultSet rs = stmt.executeQuery();\n" +
    "            ...\n" +
    "   }\n" +
    "}"
const safe2JdbcTemplatePrepareStatementParametric = "// JdbcTemplate parameter binding can effectively prevent SQL injection in typical DML scenarios.\n" +
    "public R safe2(String type,String id,String username,String password) {\n" +
    "    DriverManagerDataSource dataSource = new DriverManagerDataSource();\n" +
    "    dataSource.setDriverClassName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    dataSource.setUrl(dbUrl);\n" +
    "    dataSource.setUsername(dbUser);\n" +
    "    dataSource.setPassword(dbPass);\n" +
    "    JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES (?,?)\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, username, password);\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = ?\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, id);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = ?, password = ? WHERE id = ?\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, username, password, id);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = ?\";\n" +
    "            stringObjectMap = jdbctemplate.queryForMap(sql, id);\n" +
    "            ...\n" +
    "    }\n" +
    "}\n"
const safe3BlacklistcheckSqlBlackList = "// A blacklist can only be an auxiliary detection or blocking layer; it should not replace parameterized queries.\n" +
    "// Missing keywords, encoding tricks, and syntax variants can all bypass it.\n" +
    "public R safe3(String type,String id,String username,String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            if (checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(password)) {\n" +
    "                return R.error(\"The blacklist detected a possible SQL injection payload.\");\n" +
    "            } else {\n" +
    "                sql = \"INSERT INTO sqli (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"delete\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id)) {\n" +
    "                return R.error(\"The blacklist detected a possible SQL injection payload.\");\n" +
    "            } else {\n" +
    "                sql = \"DELETE FROM sqli WHERE id = '\" + id + \"'\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"update\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id) || checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(password)) {\n" +
    "                return R.error(\"The blacklist detected a possible SQL injection payload.\");\n" +
    "            } else {\n" +
    "                sql = \"UPDATE sqli SET password = '\" + password + \"', username = '\" + username + \"' WHERE id = '\" + id + \"'\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"select\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id)) {\n" +
    "                return R.error(\"The blacklist detected a possible SQL injection payload.\");\n" +
    "            } else {\n" +
    "                sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "                ResultSet rs = stmt.executeQuery(sql);\n" +
    "                ...\n" +
    "    }\n" +
    "}\n"
const safe4RequestRarameterValidate = "// Use strong typing to validate user request parameters.\n" +
    "public R safe4(Integer id) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    message = checkUserInput.checkUser(id);\n" +
    "    if (!message.isEmpty()) return R.error(message);\n" +
    "    sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "    ResultSet rs = stmt.executeQuery(sql);\n" +
    "    ...\n" +
    "}"
const safe4EASAPIFilter = "// encodeForSQL is a legacy or database-specific Codec supplement and is not recommended as the primary fix.\n" +
    "// Parameterized queries remain the preferred SQL injection defense.\n" +
    "public R safe5(String id) {\n" +
    "    Codec<Character> oracleCodec = new OracleCodec();\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    // Encode the id with OracleCodec only as a scenario-specific supplement.\n" +
    "    String sql = \"select * from sqli where id = '\" + ESAPI.encoder().encodeForSQL(oracleCodec, id) + \"'\";\n" +
    "    // String sql = \"select * from sqli where id = '\" + id + \"'\";\n" +
    "    ResultSet rs = stmt.executeQuery(sql);\n" +
    "}"
const special1OrderBy = "// Placeholders can only bind values; they cannot bind SQL structure such as column names, table names, keywords, or sort directions.\n" +
    "// Dynamic ORDER BY fields should use enum mapping or a whitelist.\n" +
    "public R special1OrderBy(String type,String field) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement preparedStatement;\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            sql = \"SELECT * FROM sqli ORDER BY \" + field;\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "        case \"prepareStatement\":\n" +
    "            // ORDER BY ? treats the field name as a regular value or expression, so it will not sort by the requested field.\n" +
    "            sql = \"select * from sqli order by ?\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setString(1, field);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "        case \"writeList\":\n" +
    "            if (!checkUserInput.checkSqlWhiteList(field)) {\n" +
    "                return R.error(\"Invalid field parameter.\");\n" +
    "            }\n" +
    "            sql = \"SELECT * FROM sqli ORDER BY \" + field;\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "   }\n" +
    "}\n" +
    "/**\n" +
    " * SQL injection keyword whitelist\n" +
    " */\n" +
    "public boolean checkSqlWhiteList(String content) {\n" +
    "    String[] white_list = {\"id\", \"username\", \"password\"};\n" +
    "    for (String s : white_list) {\n" +
    "        if (content.toLowerCase().equals(s)) {\n" +
    "            return true;\n" +
    "        }\n" +
    "    }\n" +
    "    return false;\n" +
    "}"
const special2Like = "public R special2Like(String type,String keyword) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    ...\n" +
    "    switch (type) {\n" +
    "        case \"raw\":                 // Query string concatenation\n" +
    "//          sql = \"SELECT * FROM sqli WHERE username LIKE '%\" + keyword + \"%'\";\n" +
    "            sql = \"SELECT * FROM sqli WHERE username LIKE concat('%', '\" + keyword + \"', '%')\";\n" +
    "            rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        case \"prepareStatement\":    // Use precompilation\n" +
    "            sql = \"SELECT * FROM sqli WHERE username LIKE ?\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setString(1, \"%\" + keyword + \"%\");\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const special3Limit = "public R special3Limit(String type,String size) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    ...\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            sql = \"SELECT * FROM sqli ORDER BY id DESC LIMIT \" + size;\n" +
    "            rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        // Use precompilation\n" +
    "        case \"prepareStatement\":\n" +
    "            sql = \"SELECT * FROM sqli ORDER BY id DESC LIMIT ?\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setInt(1, Integer.parseInt(size));\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const special4SecondOrder = "// Step 1: write the malicious value with parameters; SQL injection is not triggered yet.\n" +
    "public R special4SecondOrder(String type,String id,String username,String password) {\n" +
    "    switch (type) {\n" +
    "        case \"store\":\n" +
    "            String insertSql = \"INSERT INTO sqli (username, password) VALUES (?, ?)\";\n" +
    "            PreparedStatement ps = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS);\n" +
    "            ps.setString(1, username);\n" +
    "            ps.setString(2, password);\n" +
    "            ps.executeUpdate();\n" +
    "            ...\n" +
    "        case \"trigger\":\n" +
    "            // Step 2: fetch the stored username by id.\n" +
    "            String storedUsername = queryUsernameById(id);\n" +
    "            // Vulnerability: historical data from the database is concatenated back into SQL structure.\n" +
    "            String vulSql = \"SELECT id, username, password FROM sqli WHERE username = '\" + storedUsername + \"'\";\n" +
    "            ResultSet rs = stmt.executeQuery(vulSql);\n" +
    "            ...\n" +
    "        case \"safeTrigger\":\n" +
    "            String safeSql = \"SELECT id, username, password FROM sqli WHERE username = ?\";\n" +
    "            PreparedStatement safePs = conn.prepareStatement(safeSql);\n" +
    "            safePs.setString(1, storedUsername);\n" +
    "            ResultSet safeRs = safePs.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}\n"
const special5Union = "// UNION-based echo requires the original query and union query to have matching column counts and compatible types.\n" +
    "public R special5Union(String type,String id) {\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            String sql = \"SELECT id, username, password FROM sqli WHERE id = \" + id;\n" +
    "            // Example: id = -1 UNION SELECT 1,database(),user()\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        case \"prepareStatement\":\n" +
    "            String safeSql = \"SELECT id, username, password FROM sqli WHERE id = ?\";\n" +
    "            PreparedStatement ps = conn.prepareStatement(safeSql);\n" +
    "            ps.setString(1, id);\n" +
    "            ResultSet safeRs = ps.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}\n"

// MyBatis
const vul1CustomMethod = "vul1CustomMethod"
const safe1NativeMethod = "// The add operation is used as the example here.\n" +
    "// Controller layer\n" +
    "public R safe1(\n" +
    "switch (type) {\n" +
    "    case \"add\":\n" +
    "        rowsAffected = sqliService.nativeInsert(new Sqli(id, username, password));\n" +
    "        message = (rowsAffected > 0) ? \"Insert succeeded, username:\" + username + \" password:\" + password : \"Insert failed\";\n" +
    "        return R.ok(message);\n" +
    "        ...\n" +
    "}\n" +
    "// Service layer\n" +
    "@Override\n" +
    "public int nativeInsert(Sqli user) {\n" +
    "    return sqliMapper.insert(user);\n" +
    "}\n" +
    "\n" +
    "// Mapper layer\n" +
    "int insert(T entity); \n"

const safe2CustomMethod = "// The add operation is used as the example here.\n" +
    "// Controller layer\n" +
    "public R safe2( \n" +
    "switch (type) {\n" +
    "    case \"add\":\n" +
    "        // Insert data with the method generated by the MyBatiX plugin.\n" +
    "        rowsAffected = sqliService.customInsert(new Sqli(id, username, password));\n" +
    "        message = (rowsAffected > 0) ? \"Insert succeeded, username:\" + username + \" password:\" + password : \"Insert failed\";\n" +
    "        return R.ok(message);\n" +
    "        ...\n" +
    "}\n" +
    "// Service layer\n" +
    "// Custom SQL using #{}\n" +
    "@Override\n" +
    "public int customInsert(Sqli user) {\n" +
    "    return sqliMapper.customInsert(user);\n" +
    "}\n" +
    "\n" +
    "// Mapper layer\n" +
    "<insert id=\"customInsert\">\n" +
    "    insert into sqli (id,username,password) values (#{id,jdbcType=INTEGER},#{username,jdbcType=VARCHAR},#{password,jdbcType=VARCHAR})\n" +
    "</insert>"

const mybatisSpecial1OrderBy =
    "// Controller layer\n" +
    "public R special1OrderBy() {\n" +
    "  List<Sqli> sqlis = new ArrayList<>();\n" +
    "  switch (type) {\n" +
    "      case \"raw\":\n" +
    "          sqlis = sqliService.orderByVul(field);\n" +
    "          break;\n" +
    "      case \"prepareStatement\":\n" +
    "          sqlis = sqliService.orderByPrepareStatement(field);\n" +
    "          break;\n" +
    "      case \"writeList\":\n" +
    "          if (!checkUserInput.checkSqlWhiteList(field)) {\n" +
    "              return R.error(\"Invalid field parameter.\");\n" +
    "          }\n" +
    "          sqlis = sqliService.orderByWriteList(field);\n" +
    "      ...\n" +
    "// Service layer\n" +
    "// Custom SQL using #{}\n" +
    "@Override\n" +
    "public List<Sqli> orderByVul(String field) {\n" +
    "    return sqliMapper.orderByVul(field);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> orderByPrepareStatement(String field) {\n" +
    "    return sqliMapper.orderByPrepareStatement(field);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> orderByWriteList(String field) {\n" +
    "    return sqliMapper.orderByWriteList(field);\n" +
    "}\n" +
    "// Mapper layer\n" +
    "<!--    ORDER BY injection issue with ${}: use ${} only for controlled SQL structure after whitelist mapping. -->\n" +
    "<select id=\"orderByVul\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli\n" +
    "    <if test=\"field != null and field != ''\">\n" +
    "        ORDER BY ${field}\n" +
    "    </if>\n" +
    "</select>\n" +
    "<!--    ORDER BY with #{}: #{} can only bind values, not column names, so sorting does not work. -->\n" +
    "<select id=\"orderByPrepareStatement\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli\n" +
    "    <if test=\"field != null and field != ''\">\n" +
    "        ORDER BY #{field}\n" +
    "    </if>\n" +
    "</select>\n" +
    "<!--    Safe ORDER BY: whitelist-map the column name before placing it into controlled SQL structure with ${}. -->\n" +
    "<select id=\"orderByWriteList\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli\n" +
    "    <if test=\"field != null and field != ''\">\n" +
    "        <choose>\n" +
    "            <!-- Sort-column whitelist -->\n" +
    "            <when test=\"field == 'id' or field == 'username' or field == 'password'\">\n" +
    "                ORDER BY ${field}\n" +
    "            </when>\n" +
    "            <otherwise>\n" +
    "                <!-- Default to sorting by id -->\n" +
    "                ORDER BY id\n" +
    "            </otherwise>\n" +
    "        </choose>\n" +
    "    </if>\n" +
    "</select>"

const mybatisSpecial2Like = "// Controller layer\n" +
    "public R special1OrderBy() {\n" +
    "@PostMapping(\"/special2-Like\")\n" +
    "public R special2Like(String type,String keyword) {\n" +
    "    List<Sqli> sqlis = new ArrayList<>();\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            sqlis = sqliService.likeVul(keyword);\n" +
    "            break;\n" +
    "        case \"prepareStatement\":\n" +
    "            sqlis = sqliService.likePrepareStatement(keyword);\n" +
    "            break;\n" +
    "    ...\n" +
    "// Service layer\n" +
    "@Override\n" +
    "public List<Sqli> orderByWriteList(String field) {\n" +
    "    return sqliMapper.orderByWriteList(field);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> likeVul(String keyword) {\n" +
    "    return sqliMapper.likeVul(keyword);\n" +
    "}\n" +
    "// Mapper layer\n" +
    "<!--  Fuzzy search -->\n" +
    "<select id=\"likeVul\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli WHERE username LIKE '%${keyword}%'\n" +
    "</select>\n" +
    "<select id=\"likePrepareStatement\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli WHERE username LIKE CONCAT('%', #{keyword}, '%')\n" +
    "</select>"

const mybatisSpecial3In = "// Controller layer\n" +
    "public R special3In(String type,String scope) {\n" +
    "  switch (type) {\n" +
    "      case \"raw\":\n" +
    "          sqlis = sqliService.inVul(scope);\n" +
    "          break;\n" +
    "      case \"prepareStatement\":\n" +
    "          sqlis = sqliService.inPrepareStatement(scope);\n" +
    "          break;\n" +
    "      case \"Foreach\":\n" +
    "          List<Integer> idList = parseInputToList(scope);\n" +
    "          if (idList.isEmpty()) {\n" +
    "              return R.error(\"The scope parameter does not contain any valid integer ids.\");\n" +
    "          }\n" +
    "          sqlis = sqliService.inSafeForeach(idList);\n" +
    "          break;\n" +
    "  ...\n" +
    "// Service layer\n" +
    "@Override\n" +
    "public List<Sqli> inVul(String scope) {\n" +
    "    return sqliMapper.inVul(scope);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> inPrepareStatement(String scope) {\n" +
    "    return sqliMapper.inPrepareStatement(scope);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> inSafeForeach(List<Integer> scope) {\n" +
    "    return sqliMapper.inSafeForeach(scope);\n" +
    "}\n" +
    "// Mapper layer\n" +
    "<select id=\"inVul\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    select * from sqli where id in (${id})\n" +
    "</select>\n" +
    "\n" +
    "<select id=\"inPrepareStatement\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    select * from sqli where id in (#{id})\n" +
    "</select>\n" +
    "<select id=\"inSafeForeach\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli WHERE id IN\n" +
    "    <foreach collection=\"scope\" item=\"id\" open=\"(\" separator=\",\" close=\")\">\n" +
    "        #{id}\n" +
    "    </foreach>\n" +
    "</select>"

const vulHibernate = "vulHibernate"

const safeHibernate = "safeHibernate"

const vulJPA = "vulJPA"
const safeJPA = "safeJPA"



// SQL Injection - zh_CN code snippets
const vul1RawJointZh = "// 原生sql语句动态拼接 参数未进行任何处理\n" +
    "public R vul1(String type,String id,String username,String password) {\n" +
    "    //注册数据库驱动类\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "\n" +
    "    //调用DriverManager.getConnection()方法创建Connection连接到数据库\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "\n" +
    "    //调用Connection的createStatement()或prepareStatement()方法 创建Statement对象\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            //这里没有标识id id自增长\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "            //通过Statement对象执行SQL语句，得到ResultSet对象-查询结果集\n" +
    "            // 这里注意一下 insert、update、delete 语句应使用executeUpdate()\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            //关闭ResultSet结果集 Statement对象 以及数据库Connection对象 释放资源\n" +
    "            stmt.close();\n" +
    "            conn.close();\n" +
    "            return R.ok(message);\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET password = '\" + password + \"', username = '\" + username + \"' WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        }\n" +
    "}"

const vul2prepareStatementJointZh = "// 虽然使用了conn.prepareStatement(sql)创建了一个PreparedStatement对象，但在执行 stmt.executeUpdate(sql)时，却是传递了完整的SQL语句作为参数，而不是使用了预编译的功能\n" +
    "public R vul2(String type,String id,String username,String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement stmt;\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = '\" + id + \"'\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = '\" + username + \"', password = '\" + password + \"' WHERE id = '\" + id + \"'\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "    }\n" +
    "}"

const vul3JdbcTemplateJointZh = "// JDBCTemplate是Spring对JDBC的封装，底层实现实际上还是JDBC\n" +
    "public R vul3(String type,String id,String username,String password) {\n" +
    "    DriverManagerDataSource dataSource = new DriverManagerDataSource();\n" +
    "    dataSource.setDriverClassName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    dataSource.setUrl(dbUrl);\n" +
    "    dataSource.setUsername(dbUser);\n" +
    "    dataSource.setPassword(dbPass);\n" +
    "    JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "            //Spring的JdbcTemplate会自动管理连接的获取和释放，不需要手动关闭连接\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = '\" + username + \"', password = '\" + password + \"' WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "            resultList = jdbctemplate.queryForList(sql);\n" +
    "            ...\n" +
    "    }\n" +
    "}"

const safe1PrepareStatementParametricZh = "// 采用预编译的方法，使用?占位，也叫参数化的SQL\n" +
    "public R safe1(String type,String id,String username,String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement stmt;\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            // 这里可以看到使用了?占位符 sql语句和参数进行分离\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES (?, ?)\"; \n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            // 参数化处理\n" +
    "            stmt.setString(1, username); \n" +
    "            stmt.setString(2, password);\n" +
    "            // 使用预编译时 不需要传递sql语句\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, id);\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = ?, password = ? WHERE id = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, username);  \n" +
    "            stmt.setString(2, password);\n" +
    "            stmt.setString(3, id);\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, id);\n" +
    "            ResultSet rs = stmt.executeQuery();\n" +
    "            ...\n" +
    "   }\n" +
    "}"

const safe2JdbcTemplatePrepareStatementParametricZh = "// JDBCTemplate预编译 此时在常规DML场景有效的防止了SQL注入攻击的发生\n" +
    "public R safe2(String type,String id,String username,String password) {\n" +
    "    DriverManagerDataSource dataSource = new DriverManagerDataSource();\n" +
    "    dataSource.setDriverClassName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    dataSource.setUrl(dbUrl);\n" +
    "    dataSource.setUsername(dbUser);\n" +
    "    dataSource.setPassword(dbPass);\n" +
    "    JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO sqli (username, password) VALUES (?,?)\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, username, password);\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM sqli WHERE id = ?\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, id);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = ?, password = ? WHERE id = ?\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, username, password, id);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM sqli WHERE id  = ?\";\n" +
    "            stringObjectMap = jdbctemplate.queryForMap(sql, id);\n" +
    "            ...\n" +
    "    }\n" +
    "}\n"

const safe3BlacklistcheckSqlBlackListZh = "// 黑名单只能作为辅助检测或拦截，不应替代参数化查询。\n" +
    "// 遗漏关键字、编码绕过、语法变形都可能导致绕过。\n" +
    "public R safe3(String type,String id,String username,String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            if (checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(password)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"INSERT INTO sqli (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"delete\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"DELETE FROM sqli WHERE id = '\" + id + \"'\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"update\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id) || checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(password)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"UPDATE sqli SET password = '\" + password + \"', username = '\" + username + \"' WHERE id = '\" + id + \"'\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"select\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "                ResultSet rs = stmt.executeQuery(sql);\n" +
    "                ...\n" +
    "    }\n" +
    "}\n"

const safe4RequestRarameterValidateZh = "// 强制类型转换 对用户请求参数进行校验\n" +
    "public R safe4(Integer id) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    message = checkUserInput.checkUser(id);\n" +
    "    if (!message.isEmpty()) return R.error(message);\n" +
    "    sql = \"SELECT * FROM sqli WHERE id  = \" + id;\n" +
    "    ResultSet rs = stmt.executeQuery(sql);\n" +
    "    ...\n" +
    "}"

const safe4EASAPIFilterZh = "// encodeForSQL是历史方案或特定数据库Codec场景下的补充手段，不推荐作为首选修复。\n" +
    "// SQL注入首选修复仍然是参数化查询。\n" +
    "public R safe5(String id) {\n" +
    "    Codec<Character> oracleCodec = new OracleCodec();\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    // 使用OracleCodec对ID进行SQL编码，仅作为特定场景补充。\n" +
    "    String sql = \"select * from sqli where id = '\" + ESAPI.encoder().encodeForSQL(oracleCodec, id) + \"'\";\n" +
    "    // String sql = \"select * from sqli where id = '\" + id + \"'\";\n" +
    "    ResultSet rs = stmt.executeQuery(sql);\n" +
    "}"

const special1OrderByZh = "// 占位符只能绑定“值”，不能绑定列名、表名、关键字、排序方向等SQL结构。\n" +
    "// ORDER BY动态字段应使用枚举映射或白名单。\n" +
    "public R special1OrderBy(String type,String field) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement preparedStatement;\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            sql = \"SELECT * FROM sqli ORDER BY \" + field;\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "        case \"prepareStatement\":\n" +
    "            // ORDER BY ? 会把字段名当作普通值或表达式处理，不会按传入字段排序。\n" +
    "            sql = \"select * from sqli order by ?\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setString(1, field);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "        case \"writeList\":\n" +
    "            if (!checkUserInput.checkSqlWhiteList(field)) {\n" +
    "                return R.error(\"field字段不合法！\");\n" +
    "            }\n" +
    "            sql = \"SELECT * FROM sqli ORDER BY \" + field;\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "   }\n" +
    "}\n" +
    "/**\n" +
    " * SQL注入关键词白名单\n" +
    " */\n" +
    "public boolean checkSqlWhiteList(String content) {\n" +
    "    String[] white_list = {\"id\", \"username\", \"password\"};\n" +
    "    for (String s : white_list) {\n" +
    "        if (content.toLowerCase().equals(s)) {\n" +
    "            return true;\n" +
    "        }\n" +
    "    }\n" +
    "    return false;\n" +
    "}"

const special2LikeZh = "public R special2Like(String type,String keyword) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    ...\n" +
    "    switch (type) {\n" +
    "        case \"raw\":                 // 查询语句拼接\n" +
    "//          sql = \"SELECT * FROM sqli WHERE username LIKE '%\" + keyword + \"%'\";\n" +
    "            sql = \"SELECT * FROM sqli WHERE username LIKE concat('%', '\" + keyword + \"', '%')\";\n" +
    "            rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        case \"prepareStatement\":    // 使用预编译\n" +
    "            sql = \"SELECT * FROM sqli WHERE username LIKE ?\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setString(1, \"%\" + keyword + \"%\");\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}"

const special3LimitZh = "public R special3Limit(String type,String size) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    ...\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            sql = \"SELECT * FROM sqli ORDER BY id DESC LIMIT \" + size;\n" +
    "            rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        // 使用预编译\n" +
    "        case \"prepareStatement\":\n" +
    "            sql = \"SELECT * FROM sqli ORDER BY id DESC LIMIT ?\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setInt(1, Integer.parseInt(size));\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}"

const special4SecondOrderZh = "// 第一步：参数化写入恶意数据，此时不触发SQL注入。\n" +
    "public R special4SecondOrder(String type,String id,String username,String password) {\n" +
    "    switch (type) {\n" +
    "        case \"store\":\n" +
    "            String insertSql = \"INSERT INTO sqli (username, password) VALUES (?, ?)\";\n" +
    "            PreparedStatement ps = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS);\n" +
    "            ps.setString(1, username);\n" +
    "            ps.setString(2, password);\n" +
    "            ps.executeUpdate();\n" +
    "            ...\n" +
    "        case \"trigger\":\n" +
    "            // 第二步：先通过ID取出已存储的username。\n" +
    "            String storedUsername = queryUsernameById(id);\n" +
    "            // 漏洞点：数据库中的历史数据再次被拼接进SQL结构。\n" +
    "            String vulSql = \"SELECT id, username, password FROM sqli WHERE username = '\" + storedUsername + \"'\";\n" +
    "            ResultSet rs = stmt.executeQuery(vulSql);\n" +
    "            ...\n" +
    "        case \"safeTrigger\":\n" +
    "            String safeSql = \"SELECT id, username, password FROM sqli WHERE username = ?\";\n" +
    "            PreparedStatement safePs = conn.prepareStatement(safeSql);\n" +
    "            safePs.setString(1, storedUsername);\n" +
    "            ResultSet safeRs = safePs.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}\n"

const special5UnionZh = "// UNION回显要求原查询与联合查询列数一致、类型兼容。\n" +
    "public R special5Union(String type,String id) {\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            String sql = \"SELECT id, username, password FROM sqli WHERE id = \" + id;\n" +
    "            // 示例：id = -1 UNION SELECT 1,database(),user()\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        case \"prepareStatement\":\n" +
    "            String safeSql = \"SELECT id, username, password FROM sqli WHERE id = ?\";\n" +
    "            PreparedStatement ps = conn.prepareStatement(safeSql);\n" +
    "            ps.setString(1, id);\n" +
    "            ResultSet safeRs = ps.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}\n"

// MyBatis

const safe1NativeMethodZh = "// 这里以增加功能为例\n" +
    "// Controller层\n" +
    "public R safe1(\n" +
    "switch (type) {\n" +
    "    case \"add\":\n" +
    "        rowsAffected = sqliService.nativeInsert(new Sqli(id, username, password));\n" +
    "        message = (rowsAffected > 0) ? \"数据插入成功 username:\" + username + \" password:\" + password : \"数据插入失败\";\n" +
    "        return R.ok(message);\n" +
    "        ...\n" +
    "}\n" +
    "// Service层\n" +
    "@Override\n" +
    "public int nativeInsert(Sqli user) {\n" +
    "    return sqliMapper.insert(user);\n" +
    "}\n" +
    "\n" +
    "// Mapper层\n" +
    "int insert(T entity); \n"

const safe2CustomMethodZh = "// 这里以增加功能为例\n" +
    "// Controller层\n" +
    "public R safe2( \n" +
    "switch (type) {\n" +
    "    case \"add\":\n" +
    "        //这里插入数据使用MyBatiX插件生成的方法\n" +
    "        rowsAffected = sqliService.customInsert(new Sqli(id, username, password));\n" +
    "        message = (rowsAffected > 0) ? \"数据插入成功 username:\" + username + \" password:\" + password : \"数据插入失败\";\n" +
    "        return R.ok(message);\n" +
    "        ...\n" +
    "}\n" +
    "// Service层\n" +
    "//自定义SQL-使用#{}\n" +
    "@Override\n" +
    "public int customInsert(Sqli user) {\n" +
    "    return sqliMapper.customInsert(user);\n" +
    "}\n" +
    "\n" +
    "// Mapper层\n" +
    "<insert id=\"customInsert\">\n" +
    "    insert into sqli (id,username,password) values (#{id,jdbcType=INTEGER},#{username,jdbcType=VARCHAR},#{password,jdbcType=VARCHAR})\n" +
    "</insert>"

const mybatisSpecial1OrderByZh =
    "// Controller层\n" +
    "public R special1OrderBy() {\n" +
    "  List<Sqli> sqlis = new ArrayList<>();\n" +
    "  switch (type) {\n" +
    "      case \"raw\":\n" +
    "          sqlis = sqliService.orderByVul(field);\n" +
    "          break;\n" +
    "      case \"prepareStatement\":\n" +
    "          sqlis = sqliService.orderByPrepareStatement(field);\n" +
    "          break;\n" +
    "      case \"writeList\":\n" +
    "          if (!checkUserInput.checkSqlWhiteList(field)) {\n" +
    "              return R.error(\"field字段不合法！\");\n" +
    "          }\n" +
    "          sqlis = sqliService.orderByWriteList(field);\n" +
    "      ...\n" +
    "// Service层\n" +
    "//自定义SQL-使用#{}\n" +
    "@Override\n" +
    "public List<Sqli> orderByVul(String field) {\n" +
    "    return sqliMapper.orderByVul(field);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> orderByPrepareStatement(String field) {\n" +
    "    return sqliMapper.orderByPrepareStatement(field);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> orderByWriteList(String field) {\n" +
    "    return sqliMapper.orderByWriteList(field);\n" +
    "}\n" +
    "// Mapper层\n" +
    "<!--    Order by下的${}拼接注入问题：${}只能用于白名单枚举后的受控SQL结构-->\n" +
    "<select id=\"orderByVul\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli\n" +
    "    <if test=\"field != null and field != ''\">\n" +
    "        ORDER BY ${field}\n" +
    "    </if>\n" +
    "</select>\n" +
    "<!--    Order by下的#{}写法：#{}只能绑定值，不能绑定列名，所以排序不生效-->\n" +
    "<select id=\"orderByPrepareStatement\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli\n" +
    "    <if test=\"field != null and field != ''\">\n" +
    "        ORDER BY #{field}\n" +
    "    </if>\n" +
    "</select>\n" +
    "<!--    Order by下的安全写法：列名先做白名单枚举，再进入${}拼接受控SQL结构-->\n" +
    "<select id=\"orderByWriteList\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli\n" +
    "    <if test=\"field != null and field != ''\">\n" +
    "        <choose>\n" +
    "            <!-- 排序列名白名单 -->\n" +
    "            <when test=\"field == 'id' or field == 'username' or field == 'password'\">\n" +
    "                ORDER BY ${field}\n" +
    "            </when>\n" +
    "            <otherwise>\n" +
    "                <!-- 默认使用id进行排序 -->\n" +
    "                ORDER BY id\n" +
    "            </otherwise>\n" +
    "        </choose>\n" +
    "    </if>\n" +
    "</select>"

const mybatisSpecial2LikeZh = "// Controller层\n" +
    "public R special1OrderBy() {\n" +
    "@PostMapping(\"/special2-Like\")\n" +
    "public R special2Like(String type,String keyword) {\n" +
    "    List<Sqli> sqlis = new ArrayList<>();\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            sqlis = sqliService.likeVul(keyword);\n" +
    "            break;\n" +
    "        case \"prepareStatement\":\n" +
    "            sqlis = sqliService.likePrepareStatement(keyword);\n" +
    "            break;\n" +
    "    ...\n" +
    "// Service层\n" +
    "@Override\n" +
    "public List<Sqli> orderByWriteList(String field) {\n" +
    "    return sqliMapper.orderByWriteList(field);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> likeVul(String keyword) {\n" +
    "    return sqliMapper.likeVul(keyword);\n" +
    "}\n" +
    "// Mapper层\n" +
    "<!--  模糊查询-->\n" +
    "<select id=\"likeVul\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli WHERE username LIKE '%${keyword}%'\n" +
    "</select>\n" +
    "<select id=\"likePrepareStatement\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli WHERE username LIKE CONCAT('%', #{keyword}, '%')\n" +
    "</select>"

const mybatisSpecial3InZh = "// Controller层\n" +
    "public R special3In(String type,String scope) {\n" +
    "  switch (type) {\n" +
    "      case \"raw\":\n" +
    "          sqlis = sqliService.inVul(scope);\n" +
    "          break;\n" +
    "      case \"prepareStatement\":\n" +
    "          sqlis = sqliService.inPrepareStatement(scope);\n" +
    "          break;\n" +
    "      case \"Foreach\":\n" +
    "          List<Integer> idList = parseInputToList(scope);\n" +
    "          if (idList.isEmpty()) {\n" +
    "              return R.error(\"scope中没有合法整数ID!\");\n" +
    "          }\n" +
    "          sqlis = sqliService.inSafeForeach(idList);\n" +
    "          break;\n" +
    "  ...\n" +
    "// Service层\n" +
    "@Override\n" +
    "public List<Sqli> inVul(String scope) {\n" +
    "    return sqliMapper.inVul(scope);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> inPrepareStatement(String scope) {\n" +
    "    return sqliMapper.inPrepareStatement(scope);\n" +
    "}\n" +
    "@Override\n" +
    "public List<Sqli> inSafeForeach(List<Integer> scope) {\n" +
    "    return sqliMapper.inSafeForeach(scope);\n" +
    "}\n" +
    "// Mapper层\n" +
    "<select id=\"inVul\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    select * from sqli where id in (${id})\n" +
    "</select>\n" +
    "\n" +
    "<select id=\"inPrepareStatement\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    select * from sqli where id in (#{id})\n" +
    "</select>\n" +
    "<select id=\"inSafeForeach\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli WHERE id IN\n" +
    "    <foreach collection=\"scope\" item=\"id\" open=\"(\" separator=\",\" close=\")\">\n" +
    "        #{id}\n" +
    "    </foreach>\n" +
    "</select>"

const vul1NativeZh = "public R vul1(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String sql = \"SELECT * FROM sqli WHERE username = '\" + username + \"'\";\n" +
    "        Object[] result = (Object[]) hibernateTemplate.execute(session ->\n" +
    "                session.createNativeQuery(sql).uniqueResult()\n" +
    "        );\n" +
    "        message = \"查询成功，用户名：\" + result[1] + \" 密码：\" +result[2];\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        log.error(\"查询失败\", e);\n" +
    "        return R.error(e.getMessage());\n" +
    "    }\n" +
    "}"

const vul2HqlZh = "public R vul2(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String hql = \"FROM Sqli WHERE username = '\" + username + \"'\";\n" +
    "        Sqli result = (Sqli) hibernateTemplate.execute(session ->\n" +
    "                session.createQuery(hql).uniqueResult()\n" +
    "        );\n" +
    "        message = \"查询成功，用户名：\" +result.getUsername()+ \" 密码：\" +result.getPassword();\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        log.error(\"查询失败\", e);\n" +
    "        return R.error(e.getMessage());\n" +
    "    }\n" +
    "}"

const safe1ParamZh = "public R safe(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String hql = \"FROM Sqli WHERE username = :username\";\n" +
    "        Sqli result = hibernateTemplate.execute(session ->\n" +
    "                (Sqli) session.createQuery(hql)\n" +
    "                        .setParameter(\"username\", username)\n" +
    "                        .uniqueResult()\n" +
    "        );\n" +
    "        message = \"查询成功，用户名：\" +result.getUsername()+ \" 密码：\" +result.getPassword();\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        log.error(\"查询失败\", e);\n" +
    "        return R.error(e.getMessage());\n" +
    "    }\n" +
    "}"

const vul1JpaJpqlZh = "public R vul1(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String jpql = \"SELECT s FROM Sqli s WHERE s.username = '\" + username + \"'\";\n" +
    "        Query query = entityManager.createQuery(jpql);\n" +
    "        List<Sqli> results = query.getResultList();\n" +
    "        if (results == null || results.isEmpty()) {\n" +
    "            return R.error(\"未找到记录\");\n" +
    "        }\n" +
    "        StringBuilder sb = new StringBuilder();\n" +
    "        sb.append(\"查询成功，找到 \").append(results.size()).append(\" 条记录\\n\");\n" +
    "        message = sb.toString();\n" +
    "        log.info(message);\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        String errorMsg = e.getMessage();\n" +
    "        log.error(\"查询失败: {}\", errorMsg, e);\n" +
    "        return R.error(errorMsg);\n" +
    "    }\n" +
    "}"

const vul2JpaSortZh = "public R vul2(@RequestParam String orderBy) {\n" +
    "    try {\n" +
    "        String jpql = \"SELECT s FROM Sqli s ORDER BY s.\" + orderBy;\n" +
    "        Query query = entityManager.createQuery(jpql);\n" +
    "        List<Sqli> results = query.getResultList();\n" +
    "        return R.ok(formatResults(results));\n" +
    "    } catch (Exception e) {\n" +
    "        String errorMsg = e.getMessage();\n" +
    "        log.error(\"查询失败: {}\", errorMsg, e);\n" +
    "        return R.error(errorMsg);\n" +
    "    }\n" +
    "}"

const safeJpaParamZh = "public R safe(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String jpql = \"SELECT s FROM Sqli s WHERE s.username = :username\";\n" +
    "        Query query = entityManager.createQuery(jpql)\n" +
    "                .setParameter(\"username\", username);\n" +
    "        List<Sqli> results = query.getResultList();\n" +
    "        if (results == null || results.isEmpty()) {\n" +
    "            return R.error(\"未找到记录\");\n" +
    "        }\n" +
    "        StringBuilder sb = new StringBuilder();\n" +
    "        sb.append(\"查询成功，找到 \").append(results.size()).append(\" 条记录\\n\");\n" +
    "        message = sb.toString();\n" +
    "        log.info(message);\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        String errorMsg = e.getMessage();\n" +
    "        log.error(\"查询失败: {}\", errorMsg, e);\n" +
    "        return R.error(errorMsg);\n" +
    "    }\n" +
    "}"

const safeJpaSortZh = "public R safeOrder(@RequestParam String orderBy) {\n" +
    "    try {\n" +
    "        Map<String, String> orderByMap = new HashMap<>();\n" +
    "        orderByMap.put(\"id\", \"id\");\n" +
    "        orderByMap.put(\"username\", \"username\");\n" +
    "        orderByMap.put(\"password\", \"password\");\n" +
    "\n" +
    "        String safeOrderBy = orderByMap.get(orderBy);\n" +
    "        if (safeOrderBy == null) {\n" +
    "            return R.error(\"排序字段不合法\");\n" +
    "        }\n" +
    "\n" +
    "        CriteriaBuilder cb = entityManager.getCriteriaBuilder();\n" +
    "        CriteriaQuery<Sqli> cq = cb.createQuery(Sqli.class);\n" +
    "        Root<Sqli> root = cq.from(Sqli.class);\n" +
    "        cq.select(root).orderBy(cb.asc(root.get(safeOrderBy)));\n" +
    "\n" +
    "        List<Sqli> results = entityManager.createQuery(cq).getResultList();\n" +
    "        return R.ok(formatResults(results));\n" +
    "    } catch (Exception e) {\n" +
    "        String errorMsg = e.getMessage();\n" +
    "        log.error(\"查询失败: {}\", errorMsg, e);\n" +
    "        return R.error(errorMsg);\n" +
    "    }\n" +
    "}"

// Arbitrary File - upload
const anyFileUploadCode = "// Native vulnerable scenario without restrictions.\n" +
    "public R vul(MultipartFile file, HttpServletRequest request) {\n" +
    "    String res;\n" +
    "    String suffix = FilenameUtils.getExtension(\n" +
    "    // Get the string after the last dot (.) in the file name.\n" +
    "    file.getOriginalFilename()); \n" +
    "    String path = request.getScheme() + \"://\" + request.getServerName() + \":\" + request.getServerPort() + \"/file/\";\n" +
    "    res = uploadUtil.uploadFile(file, suffix, path);\n" +
    "    return R.ok(res);\n" +
    "}\n" +
    "// See the file-upload XSS module for the uploadFile method.\n"
const anyFileUploadWhiteCode = "// Check the file extension with an allowlist.\n" +
    "String suffix = FilenameUtils.getExtension(file.getOriginalFilename());\n" +
    "if (!checkUserInput.checkFileSuffixWhiteList(suffix)){\n" +
    "    return R.error(\"Only image files are allowed.\");\n" +
    "}\n" +
    "if (!isAllowedImageContent(file, suffix)) {\n" +
    "    return R.error(\"The file content does not match the image type.\");\n" +
    "}\n" +
    "\n" +
    "public boolean checkFileSuffixWhiteList(String suffix) {\n" +
    "    if (suffix == null || suffix.isEmpty()) {\n" +
    "        return false;\n" +
    "    }\n" +
    "    String[] white_list = {\"jpg\", \"png\", \"gif\",\"jpeg\",\"bmp\",\"ico\"};\n" +
    "    for (String s : white_list) {\n" +
    "        if (suffix.equalsIgnoreCase(s)) {\n" +
    "            return true;\n" +
    "        }\n" +
    "    }\n" +
    "    return false;\n" +
    "}\n" +
    "\n" +
    "private boolean isAllowedImageContent(MultipartFile file, String suffix) throws IOException {\n" +
    "    if (\"ico\".equalsIgnoreCase(suffix)) {\n" +
    "        // Validate the ICO file header: 00 00 01 00.\n" +
    "    }\n" +
    "    BufferedImage image = ImageIO.read(file.getInputStream());\n" +
    "    return image != null;\n" +
    "    // Return false when ImageIO parsing fails to avoid a 500 caused by a damaged image.\n" +
    "}"

const vul1Native = "public R vul1(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String sql = \"SELECT * FROM sqli WHERE username = '\" + username + \"'\";\n" +
    "        Object[] result = (Object[]) hibernateTemplate.execute(session ->\n" +
    "                session.createNativeQuery(sql).uniqueResult()\n" +
    "        );\n" +
    "        message = \"Query succeeded, username: \" + result[1] + \" password: \" +result[2];\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        log.error(\"Query failed\", e);\n" +
    "        return R.error(e.getMessage());\n" +
    "    }\n" +
    "}"
const vul2Hql = "public R vul2(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String hql = \"FROM Sqli WHERE username = '\" + username + \"'\";\n" +
    "        Sqli result = (Sqli) hibernateTemplate.execute(session ->\n" +
    "                session.createQuery(hql).uniqueResult()\n" +
    "        );\n" +
    "        message = \"Query succeeded, username: \" +result.getUsername()+ \" password: \" +result.getPassword();\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        log.error(\"Query failed\", e);\n" +
    "        return R.error(e.getMessage());\n" +
    "    }\n" +
    "}"
const safe1Param = "public R safe(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String hql = \"FROM Sqli WHERE username = :username\";\n" +
    "        Sqli result = hibernateTemplate.execute(session ->\n" +
    "                (Sqli) session.createQuery(hql)\n" +
    "                        .setParameter(\"username\", username)\n" +
    "                        .uniqueResult()\n" +
    "        );\n" +
    "        message = \"Query succeeded, username: \" +result.getUsername()+ \" password: \" +result.getPassword();\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        log.error(\"Query failed\", e);\n" +
    "        return R.error(e.getMessage());\n" +
    "    }\n" +
    "}"

const vul1JpaJpql = "public R vul1(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String jpql = \"SELECT s FROM Sqli s WHERE s.username = '\" + username + \"'\";\n" +
    "        Query query = entityManager.createQuery(jpql);\n" +
    "        List<Sqli> results = query.getResultList();\n" +
    "        if (results == null || results.isEmpty()) {\n" +
    "            return R.error(\"No records found\");\n" +
    "        }\n" +
    "        StringBuilder sb = new StringBuilder();\n" +
    "        sb.append(\"Query succeeded, found \").append(results.size()).append(\" records\\n\");\n" +
    "        message = sb.toString();\n" +
    "        log.info(message);\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        String errorMsg = e.getMessage();\n" +
    "        log.error(\"Query failed: {}\", errorMsg, e);\n" +
    "        return R.error(errorMsg);\n" +
    "    }\n" +
    "}"
const vul2JpaSort = "public R vul2(@RequestParam String orderBy) {\n" +
    "    try {\n" +
    "        String jpql = \"SELECT s FROM Sqli s ORDER BY s.\" + orderBy;\n" +
    "        Query query = entityManager.createQuery(jpql);\n" +
    "        List<Sqli> results = query.getResultList();\n" +
    "        return R.ok(formatResults(results));\n" +
    "    } catch (Exception e) {\n" +
    "        String errorMsg = e.getMessage();\n" +
    "        log.error(\"Query failed: {}\", errorMsg, e);\n" +
    "        return R.error(errorMsg);\n" +
    "    }\n" +
    "}"
const safeJpaParam = "public R safe(@RequestParam String username) {\n" +
    "    try {\n" +
    "        String jpql = \"SELECT s FROM Sqli s WHERE s.username = :username\";\n" +
    "        Query query = entityManager.createQuery(jpql)\n" +
    "                .setParameter(\"username\", username);\n" +
    "        List<Sqli> results = query.getResultList();\n" +
    "        if (results == null || results.isEmpty()) {\n" +
    "            return R.error(\"No records found\");\n" +
    "        }\n" +
    "        StringBuilder sb = new StringBuilder();\n" +
    "        sb.append(\"Query succeeded, found \").append(results.size()).append(\" records\\n\");\n" +
    "        message = sb.toString();\n" +
    "        log.info(message);\n" +
    "        return R.ok(message);\n" +
    "    } catch (Exception e) {\n" +
    "        String errorMsg = e.getMessage();\n" +
    "        log.error(\"Query failed: {}\", errorMsg, e);\n" +
    "        return R.error(errorMsg);\n" +
    "    }\n" +
    "}"
const safeJpaSort = "public R safeOrder(@RequestParam String orderBy) {\n" +
    "    try {\n" +
    "        Map<String, String> orderByMap = new HashMap<>();\n" +
    "        orderByMap.put(\"id\", \"id\");\n" +
    "        orderByMap.put(\"username\", \"username\");\n" +
    "        orderByMap.put(\"password\", \"password\");\n" +
    "\n" +
    "        String safeOrderBy = orderByMap.get(orderBy);\n" +
    "        if (safeOrderBy == null) {\n" +
    "            return R.error(\"Invalid sort field\");\n" +
    "        }\n" +
    "\n" +
    "        CriteriaBuilder cb = entityManager.getCriteriaBuilder();\n" +
    "        CriteriaQuery<Sqli> cq = cb.createQuery(Sqli.class);\n" +
    "        Root<Sqli> root = cq.from(Sqli.class);\n" +
    "        cq.select(root).orderBy(cb.asc(root.get(safeOrderBy)));\n" +
    "\n" +
    "        List<Sqli> results = entityManager.createQuery(cq).getResultList();\n" +
    "        return R.ok(formatResults(results));\n" +
    "    } catch (Exception e) {\n" +
    "        String errorMsg = e.getMessage();\n" +
    "        log.error(\"Query failed: {}\", errorMsg, e);\n" +
    "        return R.error(errorMsg);\n" +
    "    }\n" +
    "}"

// Arbitrary File - delete
const deleteFile = "public String vul(String filePath) {\n" +
    "    String currentPath = System.getProperty(\"user.dir\");\n" +
    "    File file = new File(filePath);\n" +
    "    boolean deleted = false;\n" +
    "    if (file.exists()) {\n" +
    "        deleted = file.delete();\n" +
    "    }\n" +
    "    if (deleted) {\n" +
    "        return \"Current path:\"+currentPath+\"<br/>File deleted successfully: \" + filePath;\n" +
    "    } else {\n" +
    "        return \"Current path:\"+currentPath+\"<br/>Delete failed or file does not exist: \" + filePath;\n" +
    "    }\n" +
    "}"
const safeDeleteFile = "public String safe(String fileName) {\n" +
    "    String baseDir = sysConstant.getUploadFolder();\n" +
    "    Path basePath = Paths.get(baseDir).toRealPath();\n" +
    "    Path filePath = basePath.resolve(fileName).normalize();\n" +
    "    if (!filePath.startsWith(basePath)) {\n" +
    "        return \"Access denied: invalid file path.\";\n" +
    "    }\n" +
    "    boolean deleted = false;\n" +
    "    if (Files.isRegularFile(filePath)) {\n" +
    "        Path realFilePath = filePath.toRealPath();\n" +
    "        if (!realFilePath.startsWith(basePath)) {\n" +
    "            return \"Access denied: invalid real file path.\";\n" +
    "        }\n" +
    "        deleted = Files.deleteIfExists(filePath);\n" +
    "    }\n" +
    "    if (deleted) {\n" +
    "        return \"File deleted successfully: \" + fileName;\n" +
    "    } else {\n" +
    "        return \"Delete failed or file does not exist: \" + fileName;\n" +
    "    }\n" +
    "}"

// Arbitrary File - read
const readFile = "public String vul(String fileName) throws IOException {\n" +
    "    String currentPath = System.getProperty(\"user.dir\");\n" +
    "    log.info(currentPath);\n" +
    "    File file = new File(fileName);\n" +
    "    if (file.exists() && file.isFile()) {\n" +
    "        Path filePath = file.toPath();\n" +
    "        // Read the file line by line with the stream API.\n" +
    "        try (Stream<String> lines = Files.lines(filePath)) {\n" +
    "            return lines\n" +
    "                    .map(line -> line + \"<br/>\")\n" +
    "                    .collect(Collectors.joining());\n" +
    "        }\n" +
    "    } else {\n" +
    "        return \"Current path: \"+currentPath+\"<br/>The file does not exist or the path is incorrect: \" + fileName;\n" +
    "    }"
const safeReadFile = "public String safe(String fileName) throws IOException {\n" +
    "    String baseDir = sysConstant.getUploadFolder();\n" +
    "    Path basePath = Paths.get(baseDir).toRealPath();\n" +
    "    Path filePath = basePath.resolve(fileName).normalize();\n" +
    "    // Normalize the path first, then ensure the target file remains inside the allowed directory.\n" +
    "    if (!filePath.startsWith(basePath)) {\n" +
    "        return \"Access denied: invalid file path.\";\n" +
    "    }\n" +
    "    if (Files.isRegularFile(filePath)) {\n" +
    "        Path realFilePath = filePath.toRealPath();\n" +
    "        if (!realFilePath.startsWith(basePath)) {\n" +
    "            return \"Access denied: invalid real file path.\";\n" +
    "        }\n" +
    "        return new String(Files.readAllBytes(realFilePath));\n" +
    "    } else {\n" +
    "        return \"The file does not exist or the path is incorrect: \" + fileName;\n" +
    "    }\n" +
    "}"

// Arbitrary File - download
const downloadFile = 'public void vul(String fileName, HttpServletResponse response) throws IOException {\n' +
    '    File file = new File(fileName);\n' +
    '\n' +
    '    if (file.exists() && file.isFile()) {\n' +
    '        response.setContentType("application/octet-stream");\n' +
    '        response.setHeader("Content-Disposition", "attachment; filename=\\"" + file.getName() + "\\"");\n' +
    '        try (FileInputStream fis = new FileInputStream(file);\n' +
    '             OutputStream os = response.getOutputStream()) {\n' +
    '            StreamUtils.copy(fis, os);\n' +
    '            os.flush();\n' +
    '            ...\n' +
    '    } else {\n' +
    '        response.sendError(HttpServletResponse.SC_NOT_FOUND, "File does not exist: " + fileName);\n' +
    '    }\n' +
    '}'
const safeDownloadFile = 'public void safe(String fileName,HttpServletResponse response) throws IOException {\n' +
    '    String baseDir = sysConstant.getUploadFolder();\n' +
    '    if (!isValidFileName(fileName)) {\n' +
    '        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file name: " + fileName);\n' +
    '        return;\n' +
    '    }\n' +
    '    Path basePath = Paths.get(baseDir).toRealPath();\n' +
    '    Path filePath = basePath.resolve(fileName).normalize();\n' +
    '\n' +
    '    if (filePath.startsWith(basePath) && Files.isRegularFile(filePath)) {\n' +
    '        Path realFilePath = filePath.toRealPath();\n' +
    '        if (!realFilePath.startsWith(basePath)) {\n' +
    '            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid real file path: " + fileName);\n' +
    '            return;\n' +
    '        }\n' +
    '        response.setContentType("application/octet-stream");\n' +
    '        response.setHeader("Content-Disposition", "attachment; filename=\\"" + realFilePath.getFileName().toString() + "\\"");\n' +
    '        try (InputStream fis = Files.newInputStream(realFilePath);\n' +
    '             OutputStream os = response.getOutputStream()) {\n' +
    '            StreamUtils.copy(fis, os);\n' +
    '            os.flush();\n' +
    '            ...\n' +
    '    } else {\n' +
    '        response.sendError(HttpServletResponse.SC_NOT_FOUND, "File does not exist: " + fileName);\n' +
    '    }\n' +
    '}'

const anyFileUploadCodeZh = "// 原生漏洞场景，未做任何限制\n" +
    "public R vul(MultipartFile file, HttpServletRequest request) {\n" +
    "    String res;\n" +
    "    String suffix = FilenameUtils.getExtension(\n" +
    "    // 查找文件名中最后一个点（.）之后的字符串\n" +
    "    file.getOriginalFilename()); \n" +
    "    String path = request.getScheme() + \"://\" + request.getServerName() + \":\" + request.getServerPort() + \"/file/\";\n" +
    "    res = uploadUtil.uploadFile(file, suffix, path);\n" +
    "    return R.ok(res);\n" +
    "}\n" +
    "// uploadFile方法详见文件上传导致XSS模块\n"
const anyFileUploadWhiteCodeZh = "// 检测文件后缀，做白名单过滤\n" +
    "String suffix = FilenameUtils.getExtension(file.getOriginalFilename());\n" +
    "if (!checkUserInput.checkFileSuffixWhiteList(suffix)){\n" +
    "    return R.error(\"只能上传图片哦！\");\n" +
    "}\n" +
    "if (!isAllowedImageContent(file, suffix)) {\n" +
    "    return R.error(\"文件内容与图片类型不匹配！\");\n" +
    "}\n" +
    "\n" +
    "public boolean checkFileSuffixWhiteList(String suffix) {\n" +
    "    if (suffix == null || suffix.isEmpty()) {\n" +
    "        return false;\n" +
    "    }\n" +
    "    String[] white_list = {\"jpg\", \"png\", \"gif\",\"jpeg\",\"bmp\",\"ico\"};\n" +
    "    for (String s : white_list) {\n" +
    "        if (suffix.equalsIgnoreCase(s)) {\n" +
    "            return true;\n" +
    "        }\n" +
    "    }\n" +
    "    return false;\n" +
    "}\n" +
    "\n" +
    "private boolean isAllowedImageContent(MultipartFile file, String suffix) throws IOException {\n" +
    "    if (\"ico\".equalsIgnoreCase(suffix)) {\n" +
    "        // 校验 ICO 文件头：00 00 01 00\n" +
    "    }\n" +
    "    BufferedImage image = ImageIO.read(file.getInputStream());\n" +
    "    return image != null;\n" +
    "    // ImageIO 解析异常时返回 false，避免损坏图片导致 500\n" +
    "}"
const deleteFileZh = "public String vul(String filePath) {\n" +
    "    String currentPath = System.getProperty(\"user.dir\");\n" +
    "    File file = new File(filePath);\n" +
    "    boolean deleted = false;\n" +
    "    if (file.exists()) {\n" +
    "        deleted = file.delete();\n" +
    "    }\n" +
    "    if (deleted) {\n" +
    "        return \"当前路径:\"+currentPath+\"<br/>文件删除成功: \" + filePath;\n" +
    "    } else {\n" +
    "        return \"当前路径:\"+currentPath+\"<br/>文件删除失败或文件不存在: \" + filePath;\n" +
    "    }\n" +
    "}"
const safeDeleteFileZh = "public String safe(String fileName) {\n" +
    "    String baseDir = sysConstant.getUploadFolder();\n" +
    "    Path basePath = Paths.get(baseDir).toRealPath();\n" +
    "    Path filePath = basePath.resolve(fileName).normalize();\n" +
    "    if (!filePath.startsWith(basePath)) {\n" +
    "        return \"访问被拒绝：文件路径不合法\";\n" +
    "    }\n" +
    "    boolean deleted = false;\n" +
    "    if (Files.isRegularFile(filePath)) {\n" +
    "        Path realFilePath = filePath.toRealPath();\n" +
    "        if (!realFilePath.startsWith(basePath)) {\n" +
    "            return \"访问被拒绝：文件真实路径不合法\";\n" +
    "        }\n" +
    "        deleted = Files.deleteIfExists(filePath);\n" +
    "    }\n" +
    "    if (deleted) {\n" +
    "        return \"文件删除成功: \" + fileName;\n" +
    "    } else {\n" +
    "        return \"文件删除失败或文件不存在: \" + fileName;\n" +
    "    }\n" +
    "}"
const readFileZh = "public String vul(String fileName) throws IOException {\n" +
    "    String currentPath = System.getProperty(\"user.dir\");\n" +
    "    log.info(currentPath);\n" +
    "    File file = new File(fileName);\n" +
    "    if (file.exists() && file.isFile()) {\n" +
    "        Path filePath = file.toPath();\n" +
    "        // 使用 BufferedReader 和流 API 逐行读取文件\n" +
    "        try (Stream<String> lines = Files.lines(filePath)) {\n" +
    "            return lines\n" +
    "                    .map(line -> line + \"<br/>\")\n" +
    "                    .collect(Collectors.joining());\n" +
    "        }\n" +
    "    } else {\n" +
    "        return \"当前路径：\"+currentPath+\"<br/>文件不存在或路径不正确：\" + fileName;\n" +
    "    }"
const safeReadFileZh = "public String safe(String fileName) throws IOException {\n" +
    "    String baseDir = sysConstant.getUploadFolder();\n" +
    "    Path basePath = Paths.get(baseDir).toRealPath();\n" +
    "    Path filePath = basePath.resolve(fileName).normalize();\n" +
    "    // 先标准化路径，再确认目标文件仍位于允许目录内\n" +
    "    if (!filePath.startsWith(basePath)) {\n" +
    "        return \"访问被拒绝：文件路径不合法\";\n" +
    "    }\n" +
    "    if (Files.isRegularFile(filePath)) {\n" +
    "        Path realFilePath = filePath.toRealPath();\n" +
    "        if (!realFilePath.startsWith(basePath)) {\n" +
    "            return \"访问被拒绝：文件真实路径不合法\";\n" +
    "        }\n" +
    "        return new String(Files.readAllBytes(realFilePath));\n" +
    "    } else {\n" +
    "        return \"文件不存在或路径不正确：\" + fileName;\n" +
    "    }\n" +
    "}"
const downloadFileZh = 'public void vul(String fileName, HttpServletResponse response) throws IOException {\n' +
    '    File file = new File(fileName);\n' +
    '\n' +
    '    if (file.exists() && file.isFile()) {\n' +
    '        response.setContentType("application/octet-stream");\n' +
    '        response.setHeader("Content-Disposition", "attachment; filename=\\"" + file.getName() + "\\"");\n' +
    '        try (FileInputStream fis = new FileInputStream(file);\n' +
    '             OutputStream os = response.getOutputStream()) {\n' +
    '            StreamUtils.copy(fis, os);\n' +
    '            os.flush();\n' +
    '            ...\n' +
    '    } else {\n' +
    '        response.sendError(HttpServletResponse.SC_NOT_FOUND, "文件不存在：" + fileName);\n' +
    '    }\n' +
    '}'
const safeDownloadFileZh = 'public void safe(String fileName,HttpServletResponse response) throws IOException {\n' +
    '    String baseDir = sysConstant.getUploadFolder();\n' +
    '    if (!isValidFileName(fileName)) {\n' +
    '        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "非法文件名：" + fileName);\n' +
    '        return;\n' +
    '    }\n' +
    '    Path basePath = Paths.get(baseDir).toRealPath();\n' +
    '    Path filePath = basePath.resolve(fileName).normalize();\n' +
    '\n' +
    '    if (filePath.startsWith(basePath) && Files.isRegularFile(filePath)) {\n' +
    '        Path realFilePath = filePath.toRealPath();\n' +
    '        if (!realFilePath.startsWith(basePath)) {\n' +
    '            response.sendError(HttpServletResponse.SC_FORBIDDEN, "文件真实路径不合法：" + fileName);\n' +
    '            return;\n' +
    '        }\n' +
    '        response.setContentType("application/octet-stream");\n' +
    '        response.setHeader("Content-Disposition", "attachment; filename=\\"" + realFilePath.getFileName().toString() + "\\"");\n' +
    '        try (InputStream fis = Files.newInputStream(realFilePath);\n' +
    '             OutputStream os = response.getOutputStream()) {\n' +
    '            StreamUtils.copy(fis, os);\n' +
    '            os.flush();\n' +
    '            ...\n' +
    '    } else {\n' +
    '        response.sendError(HttpServletResponse.SC_NOT_FOUND, "文件不存在：" + fileName);\n' +
    '    }\n' +
    '}'

// SSRF - server-side request forgery
const vul1URLConnection = "@GetMapping(\"/internal/metadata\")\n" +
    "public String internalMetadata() {\n" +
    "    return \"instance-id: i-javaseclab-ssrf ...\";\n" +
    "}\n" +
    "\n" +
    "@GetMapping(\"/redirect\")\n" +
    "public void redirect(String target, HttpServletResponse response) throws IOException {\n" +
    "    response.sendRedirect(target);\n" +
    "}\n" +
    "\n" +
    "public String vul(String url) {\n" +
    "    try {\n" +
    "        URL u = new URL(url);\n" +
    "        // URLConnection can request protocols such as file and http by default; HTTP requests may also follow redirects automatically.\n" +
    "        URLConnection conn = u.openConnection();\n" +
    "        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));\n" +
    "        String content;\n" +
    "        StringBuilder html = new StringBuilder();\n" +
    "        html.append(\"<pre>\");\n" +
    "        while ((content = reader.readLine()) != null) {\n" +
    "            html.append(content).append(\"\\n\");\n" +
    "        }\n" +
    "        html.append(\"</pre>\");\n" +
    "        reader.close();\n" +
    "        return html.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}"
const safe1WhiteList = "public String safe(String url) {\n" +
    "    if (!checkUserInput.isHttp(url)) {\n" +
    "        return \"The URL is not an http(s) URL.\";\n" +
    "    } else if (!checkUserInput.ssrfWhiteList(url)) {\n" +
    "        return \"The host is not in the allowlist.\";\n" +
    "    } else {\n" +
    "        URL u = new URL(url);\n" +
    "        HttpURLConnection conn = (HttpURLConnection) u.openConnection();\n" +
    "        // Disable automatic redirects; revalidate protocol, domain, and IP on every hop.\n" +
    "        conn.setInstanceFollowRedirects(false);\n" +
    "        conn.setConnectTimeout(3000);\n" +
    "        conn.setReadTimeout(3000);\n" +
    "        ...\n" +
    "    }\n" +
    "}\n" +
    "// SSRF: parse the URL scheme to validate http(s), avoiding startsWith bypasses with whitespace, case tricks, or malformed URLs.\n" +
    "public boolean isHttp(String url){\n" +
    "    try {\n" +
    "        URI uri = new URI(url);\n" +
    "        String scheme = uri.getScheme();\n" +
    "        return \"http\".equalsIgnoreCase(scheme) || \"https\".equalsIgnoreCase(scheme);\n" +
    "    } catch (URISyntaxException e) {\n" +
    "        return false;\n" +
    "    }\n" +
    "}\n" +
    "// SSRF: apply a request-domain allowlist and validate the resolved IP addresses.\n" +
    "public boolean ssrfWhiteList(String url) {\n" +
    "    List<String> urlList = new ArrayList<>(Arrays.asList(\"baidu.com\", \"www.baidu.com\", \"whgojp.top\"));\n" +
    "    try {\n" +
    "        URI uri = new URI(url);\n" +
    "        String host = uri.getHost();\n" +
    "        if (host == null || uri.getUserInfo() != null) {\n" +
    "            return false;\n" +
    "        }\n" +
    "        return urlList.contains(host.toLowerCase(Locale.ROOT)) && !isInternalHost(host);\n" +
    "    } catch (URISyntaxException | UnknownHostException e) {\n" +
    "        System.out.println(e);\n" +
    "        return false;\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "private boolean isInternalHost(String host) throws UnknownHostException {\n" +
    "    InetAddress[] addresses = InetAddress.getAllByName(host);\n" +
    "    for (InetAddress address : addresses) {\n" +
    "        if (address.isAnyLocalAddress()\n" +
    "                || address.isLoopbackAddress()\n" +
    "                || address.isLinkLocalAddress()\n" +
    "                || address.isSiteLocalAddress()\n" +
    "                || address.isMulticastAddress()) {\n" +
    "            return true;\n" +
    "        }\n" +
    "    }\n" +
    "    return false;\n" +
    "}"

const vul1URLConnectionZh = "@GetMapping(\"/internal/metadata\")\n" +
    "public String internalMetadata() {\n" +
    "    return \"instance-id: i-javaseclab-ssrf ...\";\n" +
    "}\n" +
    "\n" +
    "@GetMapping(\"/redirect\")\n" +
    "public void redirect(String target, HttpServletResponse response) throws IOException {\n" +
    "    response.sendRedirect(target);\n" +
    "}\n" +
    "\n" +
    "public String vul(String url) {\n" +
    "    try {\n" +
    "        URL u = new URL(url);\n" +
    "        // URLConnection默认可请求file/http等协议，HTTP请求还可能自动跟随跳转\n" +
    "        URLConnection conn = u.openConnection();\n" +
    "        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));\n" +
    "        String content;\n" +
    "        StringBuilder html = new StringBuilder();\n" +
    "        html.append(\"<pre>\");\n" +
    "        while ((content = reader.readLine()) != null) {\n" +
    "            html.append(content).append(\"\\n\");\n" +
    "        }\n" +
    "        html.append(\"</pre>\");\n" +
    "        reader.close();\n" +
    "        return html.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}"
const safe1WhiteListZh = "public String safe(String url) {\n" +
    "    if (!checkUserInput.isHttp(url)) {\n" +
    "        return \"检测到不是http(s)协议！\";\n" +
    "    } else if (!checkUserInput.ssrfWhiteList(url)) {\n" +
    "        return \"非白名单域名！\";\n" +
    "    } else {\n" +
    "        URL u = new URL(url);\n" +
    "        HttpURLConnection conn = (HttpURLConnection) u.openConnection();\n" +
    "        // 禁止自动跳转，每一跳都应重新校验协议、域名和IP\n" +
    "        conn.setInstanceFollowRedirects(false);\n" +
    "        conn.setConnectTimeout(3000);\n" +
    "        conn.setReadTimeout(3000);\n" +
    "        ...\n" +
    "    }\n" +
    "}\n" +
    "// SSRF：判断http(s)协议，避免 startsWith 被空白、大小写、畸形URL等绕过\n" +
    "public boolean isHttp(String url){\n" +
    "    try {\n" +
    "        URI uri = new URI(url);\n" +
    "        String scheme = uri.getScheme();\n" +
    "        return \"http\".equalsIgnoreCase(scheme) || \"https\".equalsIgnoreCase(scheme);\n" +
    "    } catch (URISyntaxException e) {\n" +
    "        return false;\n" +
    "    }\n" +
    "}\n" +
    "// SSRF：请求域名白名单，同时校验解析后的IP\n" +
    "public boolean ssrfWhiteList(String url) {\n" +
    "    List<String> urlList = new ArrayList<>(Arrays.asList(\"baidu.com\", \"www.baidu.com\", \"whgojp.top\"));\n" +
    "    try {\n" +
    "        URI uri = new URI(url);\n" +
    "        String host = uri.getHost();\n" +
    "        if (host == null || uri.getUserInfo() != null) {\n" +
    "            return false;\n" +
    "        }\n" +
    "        return urlList.contains(host.toLowerCase(Locale.ROOT)) && !isInternalHost(host);\n" +
    "    } catch (URISyntaxException | UnknownHostException e) {\n" +
    "        System.out.println(e);\n" +
    "        return false;\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "private boolean isInternalHost(String host) throws UnknownHostException {\n" +
    "    InetAddress[] addresses = InetAddress.getAllByName(host);\n" +
    "    for (InetAddress address : addresses) {\n" +
    "        if (address.isAnyLocalAddress()\n" +
    "                || address.isLoopbackAddress()\n" +
    "                || address.isLinkLocalAddress()\n" +
    "                || address.isSiteLocalAddress()\n" +
    "                || address.isMulticastAddress()) {\n" +
    "            return true;\n" +
    "        }\n" +
    "    }\n" +
    "    return false;\n" +
    "}"

// RCE
const vulProcessBuilder = "public R vul1(String payload) throws IOException {\n" +
    "    String[] command = {\"sh\", \"-c\",payload};\n" +
    "\n" +
    "    ProcessBuilder pb = new ProcessBuilder(command);\n" +
    "    pb.redirectErrorStream(true);\n" +
    "    Process process = pb.start();\n" +
    "    InputStream inputStream = process.getInputStream();\n" +
    "    BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));\n" +
    "    String line;\n" +
    "    StringBuilder output = new StringBuilder();\n" +
    "    while ((line = reader.readLine()) != null) {\n" +
    "        output.append(line).append(\"\\n\");\n" +
    "    }\n" +
    "    return R.ok(output.toString());\n" +
    "}"

const vulGetRuntime = "public R vul2(String payload) throws IOException {\n" +
    "    StringBuilder sb = new StringBuilder();\n" +
    "    String line;\n" +
    "    Process proc = Runtime.getRuntime().exec(payload);\n" +
    "    InputStream inputStream = proc.getInputStream();\n" +
    "    InputStreamReader isr = new InputStreamReader(inputStream);\n" +
    "    BufferedReader br = new BufferedReader(isr);\n" +
    "    while ((line = br.readLine()) != null) {\n" +
    "        sb.append(line);\n" +
    "    }\n" +
    "    return R.ok(sb.toString());\n" +
    "}"
const vulProcessImpl = "public R vul3(String payload) throws Exception {\n" +
    "    // Get the ProcessImpl class object.\n" +
    "    Class<?> clazz = Class.forName(\"java.lang.ProcessImpl\");\n" +
    "\n" +
    "    // Get the start method.\n" +
    "    Method method = clazz.getDeclaredMethod(\"start\", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);\n" +
    "    method.setAccessible(true);\n" +
    "\n" +
    "    Process process = (Process) method.invoke(null, new String[]{payload}, null, null, null, false);\n" +
    "    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {\n" +
    "        StringBuilder output = new StringBuilder();\n" +
    "        String line;\n" +
    "        while ((line = reader.readLine()) != null) {\n" +
    "            output.append(line).append(\"\\n\");\n" +
    "        }\n" +
    "        return R.ok(output.toString());\n" +
    "    }\n" +
    "}"
const safeProcessBuilder = "// Map business actions to fixed command arguments. Users cannot directly control command strings.\n" +
    "private static final Map<String, List<String>> ALLOWED_COMMANDS = new HashMap<>();\n" +
    "static {\n" +
    "    ALLOWED_COMMANDS.put(\"list\", Arrays.asList(\"ls\"));\n" +
    "    ALLOWED_COMMANDS.put(\"date\", Arrays.asList(\"date\"));\n" +
    "}\n" +
    "\n" +
    "public R safe(String payload) throws IOException {\n" +
    "    List<String> command = ALLOWED_COMMANDS.get(payload);\n" +
    "    if (command == null) {\n" +
    "        return R.error(\"This action is not allowed.\");\n" +
    "    }\n" +
    "    ProcessBuilder pb = new ProcessBuilder(command);\n" +
    "    pb.redirectErrorStream(true);\n" +
    "    Process process = pb.start();\n" +
    "    try {\n" +
    "        if (!process.waitFor(3, TimeUnit.SECONDS)) {\n" +
    "            process.destroyForcibly();\n" +
    "            return R.error(\"Command execution timed out.\");\n" +
    "        }\n" +
    "    } catch (InterruptedException e) {\n" +
    "        Thread.currentThread().interrupt();\n" +
    "        return R.error(\"Command execution was interrupted.\");\n" +
    "    }\n" +
    "    String output = readProcessOutput(process);\n" +
    "    return R.ok(output);\n" +
    "}"

const vulGroovy = "public R vulGroovy(String payload) {\n" +
    "    try {\n" +
    "        GroovyShell shell = new GroovyShell();\n" +
    "        Object result = shell.evaluate(payload); \n" +
    "        if (result instanceof Process) {\n" +
    "            Process process = (Process) result;\n" +
    "            String output = getProcessOutput(process);\n" +
    "            return R.ok(\"[+] Groovy code executed, result: \" + output);\n" +
    "        } else {\n" +
    "            return R.ok(\"[+] Groovy code executed, result: \" + result.toString());\n" +
    "        }\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(e.getMessage());\n" +
    "    }\n" +
    "}\n" +
    "private String getProcessOutput(Process process) {\n" +
    "    StringBuilder output = new StringBuilder();\n" +
    "    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {\n" +
    "        String line;\n" +
    "        while ((line = reader.readLine()) != null) {\n" +
    "            output.append(line).append(\"\\n\");\n" +
    "        }\n" +
    "    } catch (Exception e) {\n" +
    "        return \"Failed to read output: \" + e.getMessage();\n" +
    "    }\n" +
    "    return output.toString();\n" +
    "}"
const safeGroovy = 'public R safeGroovy(String payload) {\n' +
    '    if ("hello".equals(payload)) {\n' +
    '        return R.ok("[+] Controlled action result: Hello JavaSecLab");\n' +
    '    }\n' +
    '    if ("time".equals(payload)) {\n' +
    '        return R.ok("[+] Controlled action result: " + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));\n' +
    '    }\n' +
    '    if ("sum".equals(payload)) {\n' +
    '        return R.ok("[+] Controlled action result: " + (1 + 2 + 3));\n' +
    '    }\n' +
    '    return R.error("Illegal action input.");\n' +
    '}'

const vulProcessBuilderZh = vulProcessBuilder
const vulGetRuntimeZh = vulGetRuntime
const vulProcessImplZh = "public R vul3(String payload) throws Exception {\n" +
    "    // 获取 ProcessImpl 类对象\n" +
    "    Class<?> clazz = Class.forName(\"java.lang.ProcessImpl\");\n" +
    "\n" +
    "    // 获取 start 方法\n" +
    "    Method method = clazz.getDeclaredMethod(\"start\", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);\n" +
    "    method.setAccessible(true);\n" +
    "\n" +
    "    Process process = (Process) method.invoke(null, new String[]{payload}, null, null, null, false);\n" +
    "    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {\n" +
    "        StringBuilder output = new StringBuilder();\n" +
    "        String line;\n" +
    "        while ((line = reader.readLine()) != null) {\n" +
    "            output.append(line).append(\"\\n\");\n" +
    "        }\n" +
    "        return R.ok(output.toString());\n" +
    "    }\n" +
    "}"
const safeProcessBuilderZh = "// 业务动作到固定命令参数的映射，用户不能直接控制命令字符串\n" +
    "private static final Map<String, List<String>> ALLOWED_COMMANDS = new HashMap<>();\n" +
    "static {\n" +
    "    ALLOWED_COMMANDS.put(\"list\", Arrays.asList(\"ls\"));\n" +
    "    ALLOWED_COMMANDS.put(\"date\", Arrays.asList(\"date\"));\n" +
    "}\n" +
    "\n" +
    "public R safe(String payload) throws IOException {\n" +
    "    List<String> command = ALLOWED_COMMANDS.get(payload);\n" +
    "    if (command == null) {\n" +
    "        return R.error(\"不允许执行该动作！\");\n" +
    "    }\n" +
    "    ProcessBuilder pb = new ProcessBuilder(command);\n" +
    "    pb.redirectErrorStream(true);\n" +
    "    Process process = pb.start();\n" +
    "    try {\n" +
    "        if (!process.waitFor(3, TimeUnit.SECONDS)) {\n" +
    "            process.destroyForcibly();\n" +
    "            return R.error(\"命令执行超时！\");\n" +
    "        }\n" +
    "    } catch (InterruptedException e) {\n" +
    "        Thread.currentThread().interrupt();\n" +
    "        return R.error(\"命令执行被中断！\");\n" +
    "    }\n" +
    "    String output = readProcessOutput(process);\n" +
    "    return R.ok(output);\n" +
    "}"
const vulGroovyZh = "public R vulGroovy(String payload) {\n" +
    "    try {\n" +
    "        GroovyShell shell = new GroovyShell();\n" +
    "        Object result = shell.evaluate(payload); \n" +
    "        if (result instanceof Process) {\n" +
    "            Process process = (Process) result;\n" +
    "            String output = getProcessOutput(process);\n" +
    "            return R.ok(\"[+] Groovy代码执行，结果：\" + output);\n" +
    "        } else {\n" +
    "            return R.ok(\"[+] Groovy代码执行，结果：\" + result.toString());\n" +
    "        }\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(e.getMessage());\n" +
    "    }\n" +
    "}\n" +
    "private String getProcessOutput(Process process) {\n" +
    "    StringBuilder output = new StringBuilder();\n" +
    "    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {\n" +
    "        String line;\n" +
    "        while ((line = reader.readLine()) != null) {\n" +
    "            output.append(line).append(\"\\n\");\n" +
    "        }\n" +
    "    } catch (Exception e) {\n" +
    "        return \"读取输出失败: \" + e.getMessage();\n" +
    "    }\n" +
    "    return output.toString();\n" +
    "}"
const safeGroovyZh = 'public R safeGroovy(String payload) {\n' +
    '    if ("hello".equals(payload)) {\n' +
    '        return R.ok("[+] 受控动作执行结果：Hello JavaSecLab");\n' +
    '    }\n' +
    '    if ("time".equals(payload)) {\n' +
    '        return R.ok("[+] 受控动作执行结果：" + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));\n' +
    '    }\n' +
    '    if ("sum".equals(payload)) {\n' +
    '        return R.ok("[+] 受控动作执行结果：" + (1 + 2 + 3));\n' +
    '    }\n' +
    '    return R.error("非法的动作输入！");\n' +
    '}'

// XXE

const vulXMLReader = "public String vul1(String payload) {\n" +
    "    try {\n" +
    "        XMLReader xmlReader = XMLReaderFactory.createXMLReader();\n" +
    "        StringWriter stringWriter = new StringWriter();\n" +
    "        xmlReader.setContentHandler(new DefaultHandler() {\n" +
    "            public void characters(char[] ch, int start, int length) {\n" +
    "                for (int i = start; i < start + length; i++) {\n" +
    "                    if (ch[i] == '\\n') {\n" +
    "                        stringWriter.write(\"<br/>\");\n" +
    "                    } else {\n" +
    "                        stringWriter.write(ch[i]);\n" +
    "                    }\n" +
    "                }\n" +
    "            }\n" +
    "        });\n" +
    "        xmlReader.parse(new InputSource(new StringReader(payload)));\n" +
    "        return stringWriter.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}"

const vulSAXParser = "public String vul2(String payload) {\n" +
    "    try {\n" +
    "        SAXParserFactory factory = SAXParserFactory.newInstance();\n" +
    "        SAXParser parser = factory.newSAXParser();\n" +
    "        ...\n" +
    "        parser.parse(new InputSource(new StringReader(payload)), handler);\n" +
    "        return stringWriter.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.toString();\n" +
    "    }\n" +
    "}"

const vulDocumentBuilder = "public String vul3(String payload) {\n" +
    "    try {\n" +
    "        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n" +
    "        DocumentBuilder builder = factory.newDocumentBuilder();\n" +
    "        Document document = builder.parse(new InputSource(new StringReader(payload)));\n" +
    "        return document.getDocumentElement().getTextContent();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.toString();\n" +
    "    }\n" +
    "}"

const safeXMLReader = "public String safe1(String payload) {\n" +
    "    try {\n" +
    "        XMLReader xmlReader = XMLReaderFactory.createXMLReader();\n" +
    "        // Disable external entity references to prevent XXE attacks.\n" +
    "        xmlReader.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
    "        xmlReader.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
    "        xmlReader.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
    "        xmlReader.setFeature(\"http://apache.org/xml/features/nonvalidating/load-external-dtd\", false);\n" +
    "        xmlReader.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader(\"\")));\n" +
    "         ...\n" +
    "        xmlReader.parse(new InputSource(new StringReader(payload)));\n" +
    "        return stringWriter.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}"
const safeDocumentBuilder = "public String safe3(String payload) {\n" +
    "    try {\n" +
    "        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n" +
    "        factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
    "        factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
    "        factory.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
    "        factory.setFeature(\"http://apache.org/xml/features/nonvalidating/load-external-dtd\", false);\n" +
    "        factory.setXIncludeAware(false);\n" +
    "        factory.setExpandEntityReferences(false);\n" +
    "        setAttributeIfSupported(factory, XMLConstants.ACCESS_EXTERNAL_DTD, \"\");\n" +
    "        setAttributeIfSupported(factory, XMLConstants.ACCESS_EXTERNAL_SCHEMA, \"\");\n" +
    "        DocumentBuilder builder = factory.newDocumentBuilder();\n" +
    "        builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader(\"\")));\n" +
    "        ...\n" +
    "    } catch (Exception e) {\n" +
    "        return e.toString();\n" +
    "    }\n" +
    "}\n" +
    "private void setAttributeIfSupported(DocumentBuilderFactory factory, String name, String value) {\n" +
    "    try {\n" +
    "        factory.setAttribute(name, value);\n" +
    "    } catch (IllegalArgumentException ignored) {\n" +
    "    }\n" +
    "}"
const safeBlackList = "// A blacklist can only be auxiliary detection and should not replace parser security configuration.\n" +
    "public String safe2(String payload) {\n" +
    "    String[] black_list = {\"ENTITY\", \"DOCTYPE\"};\n" +
    "    for (String keyword : black_list) {\n" +
    "        if (payload.toUpperCase().contains(keyword)) {\n" +
    "            return \"[+] Malicious XML detected.\";\n" +
    "        }\n" +
    "    }\n" +
    "    return \"[-] XML content is safe.\";\n" +
    "}"

const vulXMLReaderZh = vulXMLReader
const vulSAXParserZh = vulSAXParser
const vulDocumentBuilderZh = vulDocumentBuilder
const safeXMLReaderZh = "public String safe1(String payload) {\n" +
    "    try {\n" +
    "        XMLReader xmlReader = XMLReaderFactory.createXMLReader();\n" +
    "        // 禁用外部实体引用，防止XXE攻击\n" +
    "        xmlReader.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
    "        xmlReader.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
    "        xmlReader.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
    "        xmlReader.setFeature(\"http://apache.org/xml/features/nonvalidating/load-external-dtd\", false);\n" +
    "        xmlReader.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader(\"\")));\n" +
    "         ...\n" +
    "        xmlReader.parse(new InputSource(new StringReader(payload)));\n" +
    "        return stringWriter.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}"
const safeDocumentBuilderZh = safeDocumentBuilder
const safeBlackListZh = "// 黑名单只能作为辅助检测，不应替代解析器安全配置\n" +
    "public String safe2(String payload) {\n" +
    "    String[] black_list = {\"ENTITY\", \"DOCTYPE\"};\n" +
    "    for (String keyword : black_list) {\n" +
    "        if (payload.toUpperCase().contains(keyword)) {\n" +
    "            return \"[+]检测到恶意XML！\";\n" +
    "        }\n" +
    "    }\n" +
    "    return \"[-]XML内容安全\";\n" +
    "}"

// 漏洞漏洞

// Captcha security
const vul1Graphic = "public Boolean verifyCaptcha(String captchaInput, HttpSession session) {\n" +
    "    String sessionCaptcha = (String) session.getAttribute(\"vulCaptcha\");\n" +
    "    Long captchaCreationTime = (Long) session.getAttribute(\"captchaCreationTime\");\n" +
    "    // Return false if captcha or creation time is missing.\n" +
    "    if (sessionCaptcha == null || captchaCreationTime == null) {\n" +
    "        return false;\n" +
    "    }\n" +
    "    // Captcha is valid for 300 seconds (5 minutes), allowing repeated attempts within that window.\n" +
    "    long captchaExpiryTime = 300 * 1000; // Convert 300 seconds to milliseconds.\n" +
    "    // Check whether the captcha has expired.\n" +
    "    if (System.currentTimeMillis() - captchaCreationTime > captchaExpiryTime) {\n" +
    "        session.removeAttribute(\"vulCaptcha\");\n" +
    "        session.removeAttribute(\"captchaCreationTime\");\n" +
    "        return false;\n" +
    "    }\n" +
    "    // Validate the submitted captcha; failed validation does not clear the old captcha.\n" +
    "    if (sessionCaptcha.equalsIgnoreCase(captchaInput)) {\n" +
    "        return true;\n" +
    "    } else {\n" +
    "        return false;\n" +
    "    }\n" +
    "}"
const vul2Graphic = "public R vul2(String username, String password, String captcha,HttpSession session) {\n" +
    "\tString sessionCaptcha = (String) session.getAttribute(\"vulCaptcha\");\n" +
    "\t// Universal captcha: 6666.\n" +
    "\tif (\"6666\".equals(captcha) || (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha))) {\n" +
    "\t\t// Clear the old captcha.\n" +
    "\t\tsession.removeAttribute(\"vulCaptcha\");\n" +
    "\t\tif (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {\n" +
    "\t\t\treturn R.ok(\"Account brute force succeeded. Username: \" + username + \", password: \" + password);\n" +
    "\t\t}else return R.error(\"Username or password is incorrect.\");\n" +
    "\t}else {\n" +
    "\t\tsession.removeAttribute(\"vulCaptcha\");\n" +
    "\t\treturn R.error(\"Captcha is incorrect.\");\n" +
    "\t}\n" +
    "}"
const vul3Graphic = "public R vul3(String username, String password, String captcha, HttpSession session) {\n" +
    "\tString sessionCaptcha = (String) session.getAttribute(\"vulCaptcha\");\n" +
    "\tif (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha)) {\n" +
    "\t\tsession.removeAttribute(\"vulCaptcha\");\n" +
    "\t\tif (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {\n" +
    "\t\t\treturn R.ok(\"Account brute force succeeded. Username: \" + username + \", password: \" + password);\n" +
    "\t\t} else return R.error(\"Username or password is incorrect.\");\n" +
    "\t} else {\n" +
    "\t\tsession.removeAttribute(\"vulCaptcha\");\n" +
    "\t\treturn R.error(\"Captcha is incorrect.\");\n" +
    "\t}\n" +
    "}"
const safeGraphic = "public R safe(String username, String password, String captcha, HttpSession session) {\n" +
    "    String sessionCaptcha = (String) session.getAttribute(\"safeCaptcha\");\n" +
    "    Long captchaTimestamp = (Long) session.getAttribute(\"captchaTimestamp\");\n" +
    "    // Check whether the captcha has expired (1-minute lifetime).\n" +
    "    if (captchaTimestamp == null || System.currentTimeMillis() - captchaTimestamp > 60 * 1000) {\n" +
    "        session.removeAttribute(\"safeCaptcha\");\n" +
    "        session.removeAttribute(\"captchaTimestamp\");\n" +
    "        return R.error(\"Captcha has expired. Please get a new one.\");\n" +
    "    }\n" +
    "    if (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha)) {\n" +
    "        session.removeAttribute(\"safeCaptcha\");\n" +
    "        session.removeAttribute(\"captchaTimestamp\");\n" +
    "        if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {\n" +
    "            return R.ok(\"Login successful. Username: \" + username + \", password: \" + password);\n" +
    "        } else {\n" +
    "            return R.error(\"Username or password is incorrect.\");\n" +
    "        }\n" +
    "    } else {\n" +
    "        session.removeAttribute(\"safeCaptcha\");\n" +
    "        session.removeAttribute(\"captchaTimestamp\");\n" +
    "        return R.error(\"Captcha is incorrect. Please try again.\");\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "// Set image captcha length to 6 characters.\n" +
    "ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(90, 30, 6, 3);"

const vul1SMS = "public R code(String phone, HttpSession session) {\n" +
    "    ...\n" +
    "    Random random = new Random();\n" +
    "    // Randomly generate a 6-digit captcha.\n" +
    "    String captcha = String.valueOf(100000 + random.nextInt(900000));\n" +
    "    session.setAttribute(\"phone\", phone);\n" +
    "    session.setAttribute(\"smsCode\", captcha);\n" +
    "    session.setAttribute(\"captchaTimestamp\", System.currentTimeMillis());\n" +
    "    // Incorrectly echoes the SMS captcha in the response body.\n" +
    "    return R.ok(\"Captcha sent successfully: \" + captcha);\n" +
    "}"
const vul2SMS = "public R vul2(String phone, String code, @RequestParam(required = false, defaultValue = \"false\") boolean code_verify, HttpSession session) {\n" +
    "    ...\n" +
    "    // Checks the code_verify field; if true, login verification succeeds.\n" +
    "    if (code_verify){\n" +
    "        return R.ok(\"Verification passed. User: \"+phone);\n" +
    "    }\n" +
    "    if (!sessionCaptcha.equals(code)) {\n" +
    "        return R.error(\"Captcha is incorrect. Please try again.\");\n" +
    "    }\n" +
    "    ...\n" +
    "    return R.ok(\"Verification passed. User: \"+phone);\n" +
    "}"


// Captcha security - Chinese snippets
const vul1GraphicZh = "public Boolean verifyCaptcha(String captchaInput, HttpSession session) {\n" +
    "    String sessionCaptcha = (String) session.getAttribute(\"vulCaptcha\");\n" +
    "    Long captchaCreationTime = (Long) session.getAttribute(\"captchaCreationTime\");\n" +
    "    // 如果没有验证码或生成时间，返回失败\n" +
    "    if (sessionCaptcha == null || captchaCreationTime == null) {\n" +
    "        return false;\n" +
    "    }\n" +
    "    // 验证码有效期为300秒（5分钟）5分钟可以无限制爆破账号密码\n" +
    "    long captchaExpiryTime = 300 * 1000; // 300秒转换为毫秒\n" +
    "    // 检查验证码是否过期\n" +
    "    if (System.currentTimeMillis() - captchaCreationTime > captchaExpiryTime) {\n" +
    "        session.removeAttribute(\"vulCaptcha\");\n" +
    "        session.removeAttribute(\"captchaCreationTime\");\n" +
    "        return false;\n" +
    "    }\n" +
    "    // 验证输入的验证码 这里验证失败后也没有清除旧的验证码\n" +
    "    if (sessionCaptcha.equalsIgnoreCase(captchaInput)) {\n" +
    "        return true;\n" +
    "    } else {\n" +
    "        return false;\n" +
    "    }\n" +
    "}"
const vul2GraphicZh = "public R vul2(String username, String password, String captcha,HttpSession session) {\n" +
    "\tString sessionCaptcha = (String) session.getAttribute(\"vulCaptcha\");\n" +
    "\t// 万能验证码：6666\n" +
    "\tif (\"6666\".equals(captcha) || (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha))) {\n" +
    "\t\t// 及时清除旧验证码\n" +
    "\t\tsession.removeAttribute(\"vulCaptcha\");\n" +
    "\t\tif (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {\n" +
    "\t\t\treturn R.ok(\"账号爆破成功！用户名：\" + username + \",密码：\" + password);\n" +
    "\t\t}else return R.error(\"账号或密码错误!\");\n" +
    "\t}else {\n" +
    "\t\tsession.removeAttribute(\"vulCaptcha\");\n" +
    "\t\treturn R.error(\"验证码错误！\");\n" +
    "\t}\n" +
    "}"
const vul3GraphicZh = "public R vul3(String username, String password, String captcha, HttpSession session) {\n" +
    "\tString sessionCaptcha = (String) session.getAttribute(\"vulCaptcha\");\n" +
    "\tif (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha)) {\n" +
    "\t\tsession.removeAttribute(\"vulCaptcha\");\n" +
    "\t\tif (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {\n" +
    "\t\t\treturn R.ok(\"账号爆破成功！用户名：\" + username + \",密码：\" + password);\n" +
    "\t\t} else return R.error(\"账号或密码错误!\");\n" +
    "\t} else {\n" +
    "\t\tsession.removeAttribute(\"vulCaptcha\");\n" +
    "\t\treturn R.error(\"验证码错误！\");\n" +
    "\t}\n" +
    "}"
const safeGraphicZh = "public R safe(String username, String password, String captcha, HttpSession session) {\n" +
    "    String sessionCaptcha = (String) session.getAttribute(\"safeCaptcha\");\n" +
    "    Long captchaTimestamp = (Long) session.getAttribute(\"captchaTimestamp\");\n" +
    "    // 验证验证码是否已失效（1分钟有效）\n" +
    "    if (captchaTimestamp == null || System.currentTimeMillis() - captchaTimestamp > 60 * 1000) {\n" +
    "        session.removeAttribute(\"safeCaptcha\");\n" +
    "        session.removeAttribute(\"captchaTimestamp\");\n" +
    "        return R.error(\"验证码已失效，请重新获取！\");\n" +
    "    }\n" +
    "    if (sessionCaptcha != null && sessionCaptcha.equalsIgnoreCase(captcha)) {\n" +
    "        session.removeAttribute(\"safeCaptcha\");\n" +
    "        session.removeAttribute(\"captchaTimestamp\");\n" +
    "        if (REAL_USERNAME.equals(username) && REAL_PASSWORD.equals(password)) {\n" +
    "            return R.ok(\"登录成功！用户名：\" + username + \",密码：\" + password);\n" +
    "        } else {\n" +
    "            return R.error(\"账号或密码错误!\");\n" +
    "        }\n" +
    "    } else {\n" +
    "        session.removeAttribute(\"safeCaptcha\");\n" +
    "        session.removeAttribute(\"captchaTimestamp\");\n" +
    "        return R.error(\"验证码错误，请重新输入！\");\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "// 设置图形验证码长度6位\n" +
    "ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(90, 30, 6, 3);"

const vul1SMSZh = "public R code(String phone, HttpSession session) {\n" +
    "    ...\n" +
    "    Random random = new Random();\n" +
    "    // 随机生成6位数验证码\n" +
    "    String captcha = String.valueOf(100000 + random.nextInt(900000));\n" +
    "    session.setAttribute(\"phone\", phone);\n" +
    "    session.setAttribute(\"smsCode\", captcha);\n" +
    "    session.setAttribute(\"captchaTimestamp\", System.currentTimeMillis());\n" +
    "    // 错误的将短信验证码回显在响应包中\n" +
    "    return R.ok(\"发送验证码成功！\" + captcha);\n" +
    "}"
const vul2SMSZh = "public R vul2(String phone, String code, @RequestParam(required = false, defaultValue = \"false\") boolean code_verify, HttpSession session) {\n" +
    "    ...\n" +
    "    // 校验code_verify字段，如果为true则验证登录成功\n" +
    "    if (code_verify){\n" +
    "        return R.ok(\"验证通过！用户：\"+phone);\n" +
    "    }\n" +
    "    if (!sessionCaptcha.equals(code)) {\n" +
    "        return R.error(\"验证码错误，请重新输入！\");\n" +
    "    }\n" +
    "    ...\n" +
    "    return R.ok(\"验证通过！用户：\"+phone);\n" +
    "}"



// IDOR
const vulHorizon = "public R vul(String username){\n" +
    "    User user = userMapper.getAllByUsername(username);\n" +
    "    if (user!=null){\n" +
    "        return R.ok(\"Username: \"+user.getUsername()+\" Password: \"+user.getPassword());\n" +
    "    }else return R.error(\"Username does not exist.\");\n" +
    "}"
const safeHorizon = "public R safe(String username){\n" +
    "    // Get the current logged-in username.\n" +
    "    String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();\n" +
    "    // Check whether the requested username matches the logged-in user.\n" +
    "    if (username == null || !username.equals(currentUsername)) {\n" +
    "        return R.error(\"You do not have permission to view this user's profile. Current user: \"+currentUsername);\n" +
    "    }\n" +
    "    // Query user information.\n" +
    "    User user = userMapper.getAllByUsername(username);\n" +
    "    if (user != null) {\n" +
    "        return R.ok(\"Username: \"+user.getUsername()+\" Password: \"+user.getPassword());\n" +
    "    } else {\n" +
    "        return R.error(\"Username does not exist.\");\n" +
    "    }\n" +
    "}"
const vulVertical = "public String vul() {\n" +
    "    // Vulnerable point: anyone who knows the admin function URL can access it directly, without server-side role validation.\n" +
    "    return \"vul/logic/idor/admin\";\n" +
    "}"
const vulHorizonZh = "public R vul(String username){\n" +
    "    User user = userMapper.getAllByUsername(username);\n" +
    "    if (user!=null){\n" +
    "        return R.ok(\"用户名：\"+user.getUsername()+\" 密码：\"+user.getPassword());\n" +
    "    }else return R.error(\"用户名不存在\");\n" +
    "}"
const safeHorizonZh = "public R safe(String username){\n" +
    "    // 获取当前登录的用户名\n" +
    "    String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();\n" +
    "    // 检查当前请求的用户名是否和登录用户名一致\n" +
    "    if (username == null || !username.equals(currentUsername)) {\n" +
    "        return R.error(\"您没有权限查看该用户的资料,当前登录用户：\"+currentUsername);\n" +
    "    }\n" +
    "    // 查询用户信息\n" +
    "    User user = userMapper.getAllByUsername(username);\n" +
    "    if (user != null) {\n" +
    "        return R.ok(\"用户名：\"+user.getUsername()+\" 密码：\"+user.getPassword());\n" +
    "    } else {\n" +
    "        return R.error(\"用户名不存在\");\n" +
    "    }\n" +
    "}"
const vulVerticalZh = "public String vul() {\n" +
    "    // 漏洞点：只要知道管理员功能地址即可直接访问，没有做服务端角色校验。\n" +
    "    return \"vul/logic/idor/admin\";\n" +
    "}"

// Payment vulnerabilities
const vul1Pay = "public R vul1(@RequestParam String count, @RequestParam String price) {\n" +
    "    try {\n" +
    "        double totalPrice = Integer.parseInt(count) * Double.parseDouble(price);\n" +
    "        log.info(\"amount to pay: \" + totalPrice);\n" +
    "        \n" +
    "        // Directly uses the client-submitted price without checking it against the server-side product price.\n" +
    "        BigDecimal currentMoney = userMoney.get();\n" +
    "        if (currentMoney.compareTo(BigDecimal.valueOf(totalPrice)) < 0) {\n" +
    "            return R.error(\"Insufficient payment amount. Payment failed.\");\n" +
    "        }\n" +
    "        userMoney.set(currentMoney.subtract(BigDecimal.valueOf(totalPrice)));\n" +
    "        return R.ok(\"Payment successful. Remaining balance: \" + userMoney.get());\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(e.toString());\n" +
    "    }\n" +
    "}";

const vul2Pay = "public R vul2(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    // Does not check whether the order has been paid.\n" +
    "    // This should use paymentStatusMap, but the check is intentionally omitted for the vulnerable demo.\n" +
    "    BigDecimal currentMoney = userMoney.get();\n" +
    "    if (currentMoney.compareTo(BigDecimal.valueOf(amount)) < 0) {\n" +
    "        return R.error(\"Insufficient balance.\");\n" +
    "    }\n" +
    "    userMoney.set(currentMoney.subtract(BigDecimal.valueOf(amount)));\n" +
    "    return R.ok(\"Payment successful. Remaining balance: \" + userMoney.get());\n" +
    "}";

const  vul3Pay = "public R vul3(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    // Simulate processing delay.\n" +
    "    try {\n" +
    "        Thread.sleep(1000);\n" +
    "    } catch (InterruptedException e) {\n" +
    "        Thread.currentThread().interrupt();\n" +
    "    }\n" +
    "\n" +
    "    BigDecimal currentMoney = userMoney.get();\n" +
    "    if (currentMoney.compareTo(BigDecimal.valueOf(amount)) < 0) {\n" +
    "        return R.error(\"Insufficient balance.\");\n" +
    "    }\n" +
    "    userMoney.set(currentMoney.subtract(BigDecimal.valueOf(amount)));\n" +
    "    return R.ok(\"Payment successful. Remaining balance: \" + userMoney.get());\n" +
    "}";

const vulConcurrent = "public R vul(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    // Simulate business processing time to widen the concurrency window.\n" +
    "    Thread.sleep(1000);\n" +
    "\n" +
    "    BigDecimal currentMoney = userMoney.get();\n" +
    "    BigDecimal payAmount = BigDecimal.valueOf(amount);\n" +
    "    if (currentMoney.compareTo(payAmount) < 0) {\n" +
    "        return R.error(\"Insufficient balance.\");\n" +
    "    }\n" +
    "    // Vulnerable point: reading and writing the balance is not atomic, and the same order has no idempotency check.\n" +
    "    userMoney.set(currentMoney.subtract(payAmount));\n" +
    "    return R.ok(\"Payment successful. Order: \" + orderId + \", remaining balance: \" + userMoney.get());\n" +
    "}";

const safeConcurrent = "public R safe(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    BigDecimal payAmount = BigDecimal.valueOf(amount);\n" +
    "    synchronized (paymentLock) {\n" +
    "        if (paidOrders.contains(orderId)) {\n" +
    "            return R.error(\"Order already paid. Repeated deduction rejected: \" + orderId);\n" +
    "        }\n" +
    "        BigDecimal currentMoney = userMoney.get();\n" +
    "        if (currentMoney.compareTo(payAmount) < 0) {\n" +
    "            return R.error(\"Insufficient balance.\");\n" +
    "        }\n" +
    "        paidOrders.add(orderId);\n" +
    "        userMoney.set(currentMoney.subtract(payAmount));\n" +
    "        return R.ok(\"Payment successful. Order: \" + orderId + \", remaining balance: \" + userMoney.get());\n" +
    "    }\n" +
    "}";

const vul4Pay = "@ApiOperation(\"Payment flow bypass - create order\")\n" +
    "@RequestMapping(\"/vul4/create\")\n" +
    "public R createOrder(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    OrderStatus status = new OrderStatus(orderId, BigDecimal.valueOf(amount));\n" +
    "    orderStatusMap.put(orderId, status);\n" +
    "    Map<String, Object> data = new HashMap<>();\n" +
    "    data.put(\"orderId\", orderId);\n" +
    "    data.put(\"amount\", amount);\n" +
    "    return R.ok(\"Order created successfully.\").put(\"data\", data);\n" +
    "}\n" +
    "\n" +
    "@ApiOperation(\"Payment flow bypass - query order status\")\n" +
    "@RequestMapping(\"/vul4/status\")\n" +
    "public R getOrderStatus(@RequestParam String orderId) {\n" +
    "    OrderStatus status = orderStatusMap.get(orderId);\n" +
    "    if (status == null) {\n" +
    "        return R.error(\"Order does not exist.\");\n" +
    "    }\n" +
    "    Map<String, Object> data = new HashMap<>();\n" +
    "    data.put(\"orderId\", status.orderId);\n" +
    "    data.put(\"amount\", status.amount);\n" +
    "    data.put(\"isPaid\", status.isPaid);\n" +
    "    return R.ok().put(\"data\", data);\n" +
    "}\n" +
    "\n" +
    "@ApiOperation(\"Payment flow bypass - payment notification\")\n" +
    "@RequestMapping(\"/vul4/notify\")\n" +
    "public R paymentNotify(@RequestParam String orderId, @RequestParam boolean success) {\n" +
    "    // Updates the order status directly without validating the notification source.\n" +
    "    OrderStatus status = orderStatusMap.get(orderId);\n" +
    "    if (status == null) {\n" +
    "        return R.error(\"Order does not exist.\");\n" +
    "    }\n" +
    "    status.isPaid = success;\n" +
    "    return R.ok(\"Status updated successfully.\");\n" +
    "}";
const vul5Pay = "public R integerOverflow(@RequestParam String count, @RequestParam String price) {\n" +
    "    try {\n" +
    "        Integer countValue = Integer.valueOf(count);\n" +
    "        Integer priceValue = Integer.valueOf(price);\n" +
    "\n" +
    "        // Integer overflow scenario: overly large count or price values may overflow.\n" +
    "        int totalAmount = countValue * priceValue;\n" +
    "        log.info(\"amount to pay: \" + totalAmount);\n" +
    "\n" +
    "        BigDecimal currentMoney = userMoney.get();\n" +
    "        if (currentMoney.compareTo(BigDecimal.valueOf(totalAmount)) < 0) {\n" +
    "            return R.error(\"Insufficient payment amount. Payment failed.\");\n" +
    "        }\n" +
    "        userMoney.set(currentMoney.subtract(BigDecimal.valueOf(totalAmount)));\n" +
    "        return R.ok(\"Payment successful. Remaining balance: \" + userMoney.get());\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"Invalid input. Please enter a valid quantity and price.\");\n" +
    "    }\n" +
    "}";
const vul6Pay = "public R floatingPointPrecision(@RequestParam String count, @RequestParam String price) {\n" +
    "    try {\n" +
    "        double totalAmount = Double.parseDouble(count) * Double.parseDouble(price);\n" +
    "        // Vulnerable point: converting binary floating-point results directly to money may introduce precision errors.\n" +
    "        BigDecimal amountValue = new BigDecimal(totalAmount);\n" +
    "        log.info(\"amount to pay: \" + amountValue);\n" +
    "\n" +
    "        BigDecimal currentMoney = userMoney.get();\n" +
    "        if (currentMoney.compareTo(amountValue) < 0) {\n" +
    "            return R.error(\"Insufficient payment amount. Payment failed.\");\n" +
    "        }\n" +
    "        userMoney.set(currentMoney.subtract(amountValue));\n" +
    "        return R.ok(\"Payment successful. Actual deducted amount: \" + amountValue + \", remaining balance: \" + userMoney.get());\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"Invalid input. Please enter a valid quantity and price.\");\n" +
    "    }\n" +
    "}";

// Payment vulnerabilities - Chinese snippets
const vul1PayZh = "public R vul1(@RequestParam String count, @RequestParam String price) {\n" +
    "    try {\n" +
    "        double totalPrice = Integer.parseInt(count) * Double.parseDouble(price);\n" +
    "        log.info(\"用户需支付金额：\" + totalPrice);\n" +
    "        \n" +
    "        // 直接使用客户端传入的价格，未与服务端商品实际价格进行校验\n" +
    "        BigDecimal currentMoney = userMoney.get();\n" +
    "        if (currentMoney.compareTo(BigDecimal.valueOf(totalPrice)) < 0) {\n" +
    "            return R.error(\"支付金额不足，支付失败！\");\n" +
    "        }\n" +
    "        userMoney.set(currentMoney.subtract(BigDecimal.valueOf(totalPrice)));\n" +
    "        return R.ok(\"支付成功！剩余余额：\" + userMoney.get());\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(e.toString());\n" +
    "    }\n" +
    "}";

const vul2PayZh = "public R vul2(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    // 未检查订单是否已支付\n" +
    "    // 这里应该使用paymentStatusMap检查订单是否已支付，但为了演示漏洞，故意不检查\n" +
    "    BigDecimal currentMoney = userMoney.get();\n" +
    "    if (currentMoney.compareTo(BigDecimal.valueOf(amount)) < 0) {\n" +
    "        return R.error(\"余额不足\");\n" +
    "    }\n" +
    "    userMoney.set(currentMoney.subtract(BigDecimal.valueOf(amount)));\n" +
    "    return R.ok(\"支付成功！剩余余额：\" + userMoney.get());\n" +
    "}";

const vul3PayZh = "public R vul3(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    // 模拟处理延迟\n" +
    "    try {\n" +
    "        Thread.sleep(1000);\n" +
    "    } catch (InterruptedException e) {\n" +
    "        Thread.currentThread().interrupt();\n" +
    "    }\n" +
    "\n" +
    "    BigDecimal currentMoney = userMoney.get();\n" +
    "    if (currentMoney.compareTo(BigDecimal.valueOf(amount)) < 0) {\n" +
    "        return R.error(\"余额不足\");\n" +
    "    }\n" +
    "    userMoney.set(currentMoney.subtract(BigDecimal.valueOf(amount)));\n" +
    "    return R.ok(\"支付成功！剩余余额：\" + userMoney.get());\n" +
    "}";

const vulConcurrentZh = "public R vul(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    // 模拟业务处理耗时，扩大并发窗口\n" +
    "    Thread.sleep(1000);\n" +
    "\n" +
    "    BigDecimal currentMoney = userMoney.get();\n" +
    "    BigDecimal payAmount = BigDecimal.valueOf(amount);\n" +
    "    if (currentMoney.compareTo(payAmount) < 0) {\n" +
    "        return R.error(\"余额不足\");\n" +
    "    }\n" +
    "    // 漏洞点：读取余额和写回余额不是一个原子操作，相同订单也没有幂等校验\n" +
    "    userMoney.set(currentMoney.subtract(payAmount));\n" +
    "    return R.ok(\"支付成功！订单：\" + orderId + \"，剩余余额：\" + userMoney.get());\n" +
    "}";

const safeConcurrentZh = "public R safe(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    BigDecimal payAmount = BigDecimal.valueOf(amount);\n" +
    "    synchronized (paymentLock) {\n" +
    "        if (paidOrders.contains(orderId)) {\n" +
    "            return R.error(\"订单已支付，拒绝重复扣款：\" + orderId);\n" +
    "        }\n" +
    "        BigDecimal currentMoney = userMoney.get();\n" +
    "        if (currentMoney.compareTo(payAmount) < 0) {\n" +
    "            return R.error(\"余额不足\");\n" +
    "        }\n" +
    "        paidOrders.add(orderId);\n" +
    "        userMoney.set(currentMoney.subtract(payAmount));\n" +
    "        return R.ok(\"支付成功！订单：\" + orderId + \"，剩余余额：\" + userMoney.get());\n" +
    "    }\n" +
    "}";

const vul4PayZh = "@ApiOperation(\"支付流程绕过漏洞 - 创建订单\")\n" +
    "@RequestMapping(\"/vul4/create\")\n" +
    "public R createOrder(@RequestParam String orderId, @RequestParam double amount) {\n" +
    "    OrderStatus status = new OrderStatus(orderId, BigDecimal.valueOf(amount));\n" +
    "    orderStatusMap.put(orderId, status);\n" +
    "    Map<String, Object> data = new HashMap<>();\n" +
    "    data.put(\"orderId\", orderId);\n" +
    "    data.put(\"amount\", amount);\n" +
    "    return R.ok(\"订单创建成功\").put(\"data\", data);\n" +
    "}\n" +
    "\n" +
    "@ApiOperation(\"支付流程绕过漏洞 - 查询订单状态\")\n" +
    "@RequestMapping(\"/vul4/status\")\n" +
    "public R getOrderStatus(@RequestParam String orderId) {\n" +
    "    OrderStatus status = orderStatusMap.get(orderId);\n" +
    "    if (status == null) {\n" +
    "        return R.error(\"订单不存在\");\n" +
    "    }\n" +
    "    Map<String, Object> data = new HashMap<>();\n" +
    "    data.put(\"orderId\", status.orderId);\n" +
    "    data.put(\"amount\", status.amount);\n" +
    "    data.put(\"isPaid\", status.isPaid);\n" +
    "    return R.ok().put(\"data\", data);\n" +
    "}\n" +
    "\n" +
    "@ApiOperation(\"支付流程绕过漏洞 - 支付通知\")\n" +
    "@RequestMapping(\"/vul4/notify\")\n" +
    "public R paymentNotify(@RequestParam String orderId, @RequestParam boolean success) {\n" +
    "    // 未验证通知来源，直接更新订单状态\n" +
    "    OrderStatus status = orderStatusMap.get(orderId);\n" +
    "    if (status == null) {\n" +
    "        return R.error(\"订单不存在\");\n" +
    "    }\n" +
    "    status.isPaid = success;\n" +
    "    return R.ok(\"状态更新成功\");\n" +
    "}";
const vul5PayZh = "public R integerOverflow(@RequestParam String count, @RequestParam String price) {\n" +
    "    try {\n" +
    "        Integer countValue = Integer.valueOf(count);\n" +
    "        Integer priceValue = Integer.valueOf(price);\n" +
    "\n" +
    "        // 整数溢出场景：当 count 或 price 数值过大时，可能会导致溢出\n" +
    "        int totalAmount = countValue * priceValue;\n" +
    "        log.info(\"用户需支付金额：\" + totalAmount);\n" +
    "\n" +
    "        BigDecimal currentMoney = userMoney.get();\n" +
    "        if (currentMoney.compareTo(BigDecimal.valueOf(totalAmount)) < 0) {\n" +
    "            return R.error(\"支付金额不足，支付失败！\");\n" +
    "        }\n" +
    "        userMoney.set(currentMoney.subtract(BigDecimal.valueOf(totalAmount)));\n" +
    "        return R.ok(\"支付成功！剩余余额：\" + userMoney.get());\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"无效的输入，请输入有效的数量和价格！\");\n" +
    "    }\n" +
    "}";
const vul6PayZh = "public R floatingPointPrecision(@RequestParam String count, @RequestParam String price) {\n" +
    "    try {\n" +
    "        double totalAmount = Double.parseDouble(count) * Double.parseDouble(price);\n" +
    "        // 漏洞点：把二进制浮点计算结果直接转成金额，可能引入精度误差\n" +
    "        BigDecimal amountValue = new BigDecimal(totalAmount);\n" +
    "        log.info(\"用户需支付金额：\" + amountValue);\n" +
    "\n" +
    "        BigDecimal currentMoney = userMoney.get();\n" +
    "        if (currentMoney.compareTo(amountValue) < 0) {\n" +
    "            return R.error(\"支付金额不足，支付失败！\");\n" +
    "        }\n" +
    "        userMoney.set(currentMoney.subtract(amountValue));\n" +
    "        return R.ok(\"支付成功！实际扣款金额：\" + amountValue + \"，剩余余额：\" + userMoney.get());\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"无效的输入，请输入有效的数量和价格！\");\n" +
    "    }\n" +
    "}";


// 其他漏洞
const vul1SpringMvcRedirect = "// Spring MVC based redirect\n" +
    "// Redirect by returning a string with the redirect: prefix.\n" +
    "public String vul1(@RequestParam(\"url\") String url) {\n" +
    "    return \"redirect:\" + url;   // Spring MVC style, 302 temporary redirect\n" +
    "}\n" +
    "\n" +
    "// Redirect by returning a ModelAndView object with the redirect: prefix.\n" +
    "public ModelAndView vul2(@RequestParam(\"url\") String url) {\n" +
    "    return new ModelAndView(\"redirect:\" + url); // Spring MVC ModelAndView style, 302 temporary redirect\n" +
    "}";
const vul1SpringMvcRedirectZh = "// 基于Spring MVC的重定向方式\n" +
    "// 通过返回带有 redirect: 前缀的字符串来实现重定向。\n" +
    "public String vul1(@RequestParam(\"url\") String url) {\n" +
    "    return \"redirect:\" + url;   // Spring MVC写法 302临时重定向\n" +
    "}\n" +
    "\n" +
    "// 通过返回 ModelAndView 对象并指定 redirect: 前缀来实现重定向。\n" +
    "public ModelAndView vul2(@RequestParam(\"url\") String url) {\n" +
    "    return new ModelAndView(\"redirect:\" + url); // Spring MVC写法 使用ModelAndView 302临时重定向\n" +
    "}";

const vul2ServletRedirect = "// Servlet standard redirect\n" +
    "// Redirect by setting the response status code and header.\n" +
    "public static void vul2(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String url = request.getParameter(\"url\");\n" +
    "    response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 permanent redirect\n" +
    "    response.setHeader(\"Location\", url);\n" +
    "}\n" +
    "\n" +
    "// Redirect by calling HttpServletResponse.sendRedirect().\n" +
    "public static void vul3(HttpServletRequest request, HttpServletResponse response) throws IOException {\n" +
    "    String url = request.getParameter(\"url\");\n" +
    "    response.sendRedirect(url); // 302 temporary redirect\n" +
    "}";
const vul2ServletRedirectZh = "// 基于Servlet标准的重定向方式\n" +
    "// 通过设置响应状态码和头部信息实现重定向。\n" +
    "public static void vul2(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String url = request.getParameter(\"url\");\n" +
    "    response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301永久重定向\n" +
    "    response.setHeader(\"Location\", url);\n" +
    "}\n" +
    "\n" +
    "// 通过调用 HttpServletResponse.sendRedirect() 实现重定向。\n" +
    "public static void vul3(HttpServletRequest request, HttpServletResponse response) throws IOException {\n" +
    "    String url = request.getParameter(\"url\");\n" +
    "    response.sendRedirect(url); // 302临时重定向\n" +
    "}";

const vul3SpringRedirect = "// Spring annotation and status-code based redirect\n" +
    "// Redirect by setting the status code with ResponseEntity.\n" +
    "public ResponseEntity<Void> vul5(@RequestParam(\"url\") String url) {\n" +
    "    HttpHeaders headers = new HttpHeaders();\n" +
    "    headers.setLocation(URI.create(url));\n" +
    "    return new ResponseEntity<>(headers, HttpStatus.FOUND); // 302 temporary redirect\n" +
    "}\n" +
    "\n" +
    "// Redirect by setting the status code through an annotation.\n" +
    "@ResponseStatus(HttpStatus.FOUND) // 302 temporary redirect\n" +
    "public void vul6(HttpServletRequest request, HttpServletResponse response) throws IOException {\n" +
    "    String url = request.getParameter(\"url\");\n" +
    "    response.setHeader(\"Location\", url);\n" +
    "}";
const vul3SpringRedirectZh = "// 基于Spring注解和状态码的重定向方式\n" +
    "// 使用ResponseEntity设置状态码实现重定向\n" +
    "public ResponseEntity<Void> vul5(@RequestParam(\"url\") String url) {\n" +
    "    HttpHeaders headers = new HttpHeaders();\n" +
    "    headers.setLocation(URI.create(url));\n" +
    "    return new ResponseEntity<>(headers, HttpStatus.FOUND); // 302临时重定向\n" +
    "}\n" +
    "\n" +
    "// 通过注解设置状态码实现重定向\n" +
    "@ResponseStatus(HttpStatus.FOUND) // 302临时重定向\n" +
    "public void vul6(HttpServletRequest request, HttpServletResponse response) throws IOException {\n" +
    "    String url = request.getParameter(\"url\");\n" +
    "    response.setHeader(\"Location\", url);\n" +
    "}";
const safe1Forward = "// Internal forward\n" +
    "public static void safe1(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String url = request.getParameter(\"url\");\n" +
    "    RequestDispatcher rd = request.getRequestDispatcher(url);\n" +
    "    try {\n" +
    "        // Forward internally on the server side.\n" +
    "        rd.forward(request, response);\n" +
    "    } catch (Exception e) {\n" +
    "        e.printStackTrace();\n" +
    "    }\n" +
    "}";
const safe1ForwardZh = "// 内部跳转\n" +
    "public static void safe1(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String url = request.getParameter(\"url\");\n" +
    "    RequestDispatcher rd = request.getRequestDispatcher(url);\n" +
    "    try {\n" +
    "        // 做了内部转发\n" +
    "        rd.forward(request, response);\n" +
    "    } catch (Exception e) {\n" +
    "        e.printStackTrace();\n" +
    "    }\n" +
    "}";
const safe2CheckUrl = '// Define the URL allowlist.\n' +
    'private static final List<String> WhiteUrlList = new ArrayList<>();\n' +
    '\n' +
    'static {\n' +
    '//        WhiteUrlList.add("baidu.com");\n' +
    '//        WhiteUrlList.add("bilibili.com");\n' +
    '    WhiteUrlList.add("csdn.net");\n' +
    '}\n' +
    '/**\n' +
    ' * URL redirect filter.\n' +
    ' */\n' +
    'public boolean checkURL(String url) {\n' +
    '    for (String blackUrl : WhiteUrlList) {\n' +
    '        if (url.toLowerCase().contains(blackUrl.toLowerCase())) {\n' +
    '            return false;\n' +
    '        }\n' +
    '    }\n' +
    '    return true;\n' +
    '}\n';
const safe2CheckUrlZh = '// 定义 URL 白名单\n' +
    'private static final List<String> WhiteUrlList = new ArrayList<>();\n' +
    '\n' +
    'static {\n' +
    '//        WhiteUrlList.add("baidu.com");\n' +
    '//        WhiteUrlList.add("bilibili.com");\n' +
    '    WhiteUrlList.add("csdn.net");\n' +
    '}\n' +
    '/**\n' +
    ' * URL跳转过滤\n' +
    ' */\n' +
    'public boolean checkURL(String url) {\n' +
    '    for (String blackUrl : WhiteUrlList) {\n' +
    '        if (url.toLowerCase().contains(blackUrl.toLowerCase())) {\n' +
    '            return false;\n' +
    '        }\n' +
    '    }\n' +
    '    return true;\n' +
    '}\n';
const vulXffforgery = "public String vul1(HttpServletRequest request, Model model) {\n" +
    "    // Non-separated frontend/backend: use request.getRemoteHost() to obtain the client IP.\n" +
    "    final String remoteHost = request.getRemoteHost();\n" +
    "    boolean isClientIP8888 = \"8.8.8.8\".equals(remoteHost);\n" +
    "    model.addAttribute(\"clientIP\", remoteHost);\n" +
    "    // Add sensitive information.\n" +
    "    if (isClientIP8888) {\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"username:admin,password:Admin123\");\n" +
    "    }\n" +
    "    return \"vul/other/onlyForGoogle\";\n" +
    "}\n" +
    "\n" +
    "public String vul2(HttpServletRequest request, HttpServletResponse response, Model model, String xff) {\n" +
    "    // Simulate separated frontend/backend by trusting the X-Forwarded-For header.\n" +
    "    String remoteHost = \"\";\n" +
    "    if (xff.equals(\"true\")) {\n" +
    "        remoteHost = request.getHeader(\"X-Forwarded-For\");\n" +
    "    }\n" +
    "    if (remoteHost.isEmpty()) {\n" +
    "        remoteHost = request.getRemoteHost();\n" +
    "    }\n" +
    "    boolean isClientIP8888 = \"8.8.8.8\".equals(remoteHost);\n" +
    "    // Add sensitive information.\n" +
    "    model.addAttribute(\"clientIP\", remoteHost);\n" +
    "    if (isClientIP8888) {\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"username:admin,password:Admin123\");\n" +
    "    }\n" +
    "    return \"vul/other/onlyForGoogle\";\n" +
    "}";
const vulXffforgeryZh = "public String vul1(HttpServletRequest request, Model model) {\n" +
    "    // 前后端不分离 使用request.getRemoteHost()获取客户端IP\n" +
    "    final String remoteHost = request.getRemoteHost();\n" +
    "    boolean isClientIP8888 = \"8.8.8.8\".equals(remoteHost);\n" +
    "    model.addAttribute(\"clientIP\", remoteHost);\n" +
    "    // 添加敏感信息\n" +
    "    if (isClientIP8888) {\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"username:admin,password:Admin123\");\n" +
    "    }\n" +
    "    return \"vul/other/onlyForGoogle\";\n" +
    "}\n" +
    "\n" +
    "public String vul2(HttpServletRequest request, HttpServletResponse response, Model model, String xff) {\n" +
    "    // 前后端分离 模拟通过X-Forwarded-For头获取客户端IP\n" +
    "    String remoteHost = \"\";\n" +
    "    if (xff.equals(\"true\")) {\n" +
    "        remoteHost = request.getHeader(\"X-Forwarded-For\");\n" +
    "    }\n" +
    "    if (remoteHost.isEmpty()) {\n" +
    "        remoteHost = request.getRemoteHost();\n" +
    "    }\n" +
    "    boolean isClientIP8888 = \"8.8.8.8\".equals(remoteHost);\n" +
    "    // 添加敏感信息\n" +
    "    model.addAttribute(\"clientIP\", remoteHost);\n" +
    "    if (isClientIP8888) {\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"username:admin,password:Admin123\");\n" +
    "    }\n" +
    "    return \"vul/other/onlyForGoogle\";\n" +
    "}";

const safeXffforgery = "public String safe(HttpServletRequest request, HttpServletResponse response, Model model, String xff){\n" +
    "    String proxyIp = request.getRemoteAddr();\n" +
    "    String remoteHost = proxyIp;\n" +
    "    if (\"true\".equals(xff)) {\n" +
    "        if (!isTrustedProxy(proxyIp)){\n" +
    "            model.addAttribute(\"clientIP\", proxyIp);\n" +
    "            model.addAttribute(\"sensitiveInfo\", \"Untrusted proxy source. Ignored XFF header: \" + proxyIp);\n" +
    "            return \"vul/other/onlyForGoogle\";\n" +
    "        }\n" +
    "        remoteHost = getFirstForwardedIp(request.getHeader(\"X-Forwarded-For\"));\n" +
    "    }\n" +
    "    if (remoteHost == null || remoteHost.isEmpty()) {\n" +
    "        model.addAttribute(\"clientIP\", proxyIp);\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"XFF header is empty or malformed.\");\n" +
    "        return \"vul/other/onlyForGoogle\";\n" +
    "    }\n" +
    "    boolean isClientIP8888 = \"8.8.8.8\".equals(remoteHost);\n" +
    "    model.addAttribute(\"clientIP\", remoteHost);\n" +
    "    if (isClientIP8888) {\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"username:admin,password:Admin123\");\n" +
    "    }\n" +
    "    return \"vul/other/onlyForGoogle\";\n" +
    "}\n" +
    "// Check whether the request comes from a trusted proxy.\n" +
    "private boolean isTrustedProxy(String ip) {\n" +
    "    return Arrays.asList(\"192.168.1.1\", \"10.0.0.1\").contains(ip);\n" +
    "}";
const safeXffforgeryZh = "public String safe(HttpServletRequest request, HttpServletResponse response, Model model, String xff){\n" +
    "    String proxyIp = request.getRemoteAddr();\n" +
    "    String remoteHost = proxyIp;\n" +
    "    if (\"true\".equals(xff)) {\n" +
    "        if (!isTrustedProxy(proxyIp)){\n" +
    "            model.addAttribute(\"clientIP\", proxyIp);\n" +
    "            model.addAttribute(\"sensitiveInfo\", \"非可信代理来源，忽略XFF头：\" + proxyIp);\n" +
    "            return \"vul/other/onlyForGoogle\";\n" +
    "        }\n" +
    "        remoteHost = getFirstForwardedIp(request.getHeader(\"X-Forwarded-For\"));\n" +
    "    }\n" +
    "    if (remoteHost == null || remoteHost.isEmpty()) {\n" +
    "        model.addAttribute(\"clientIP\", proxyIp);\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"XFF头为空或格式异常！\");\n" +
    "        return \"vul/other/onlyForGoogle\";\n" +
    "    }\n" +
    "    boolean isClientIP8888 = \"8.8.8.8\".equals(remoteHost);\n" +
    "    model.addAttribute(\"clientIP\", remoteHost);\n" +
    "    if (isClientIP8888) {\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"username:admin,password:Admin123\");\n" +
    "    }\n" +
    "    return \"vul/other/onlyForGoogle\";\n" +
    "}\n" +
    "// 判断是否来自可信代理\n" +
    "private boolean isTrustedProxy(String ip) {\n" +
    "    return Arrays.asList(\"192.168.1.1\", \"10.0.0.1\").contains(ip);\n" +
    "}"

const vulCsrf = "public R vul(String receiver, String amount, @AuthenticationPrincipal UserDetails userDetails){\n" +
    "    String currentUser = userDetails.getUsername();\n" +
    "    Map<String, Object> result = new HashMap<>();\n" +
    "    result.put(\"currentUser\", currentUser);\n" +
    "    result.put(\"receiver\", receiver);\n" +
    "    result.put(\"amount\", amount);\n" +
    "    return R.ok(result);\n" +
    "}"
const safeCsrfToken = "public Map<String, Object> safeCsrf(String receiver,String amount,@AuthenticationPrincipal UserDetails userDetails,String csrfToken,HttpSession session) {\n" +
    "    String currentUser = userDetails.getUsername();\n" +
    "\n" +
    "    String sessionToken = (String) session.getAttribute(\"csrfToken\");\n" +
    "    Map<String, Object> result = new HashMap<>();\n" +
    "    if (!constantTimeEquals(csrfToken, sessionToken)) {\n" +
    "        result.put(\"success\", false);\n" +
    "        result.put(\"message\", \"Token is invalid or expired.\");\n" +
    "        return result;\n" +
    "    }\n" +
    "    result.put(\"currentUser\", currentUser);\n" +
    "    result.put(\"receiver\", receiver);\n" +
    "    result.put(\"amount\", amount);\n" +
    "    result.put(\"csrfToken\", csrfToken);\n" +
    "    return result;\n" +
    "}\n" +
    "\n" +
    "private boolean constantTimeEquals(String requestToken, String sessionToken) {\n" +
    "    if (requestToken == null || sessionToken == null) {\n" +
    "        return false;\n" +
    "    }\n" +
    "    return MessageDigest.isEqual(\n" +
    "            requestToken.getBytes(StandardCharsets.UTF_8),\n" +
    "            sessionToken.getBytes(StandardCharsets.UTF_8)\n" +
    "    );\n" +
    "}"
const safeCsrfReferer = "public Map<String, Object> safe2(HttpServletRequest request,String receiver,String amount, @AuthenticationPrincipal UserDetails userDetails, HttpSession session) {\n" +
    "    String currentUser = userDetails.getUsername();\n" +
    "    Map<String, Object> result = new HashMap<>();\n" +
    "    String originOrReferer = request.getHeader(\"Origin\");\n" +
    "    if (originOrReferer == null) {\n" +
    "        originOrReferer = request.getHeader(\"Referer\");\n" +
    "    }\n" +
    "    if (!isTrustedSameOrigin(request, originOrReferer)) {\n" +
    "        result.put(\"success\", false);\n" +
    "        result.put(\"message\", \"Origin/Referer is invalid.\");\n" +
    "        return result;\n" +
    "    }\n" +
    "    result.put(\"currentUser\", currentUser);\n" +
    "    result.put(\"receiver\", receiver);\n" +
    "    result.put(\"amount\", amount);\n" +
    "    return result;\n" +
    "}\n" +
    "\n" +
    "private boolean isTrustedSameOrigin(HttpServletRequest request, String originOrReferer) {\n" +
    "    if (originOrReferer == null) {\n" +
    "        return false;\n" +
    "    }\n" +
    "    try {\n" +
    "        URI uri = new URI(originOrReferer);\n" +
    "        int actualPort = uri.getPort() == -1 ? defaultPort(uri.getScheme()) : uri.getPort();\n" +
    "        return request.getScheme().equalsIgnoreCase(uri.getScheme())\n" +
    "                && request.getServerName().equalsIgnoreCase(uri.getHost())\n" +
    "                && request.getServerPort() == actualPort;\n" +
    "    } catch (URISyntaxException e) {\n" +
    "        return false;\n" +
    "    }\n" +
    "}"
const vulCsrfZh = vulCsrf
const safeCsrfTokenZh = "public Map<String, Object> safeCsrf(String receiver,String amount,@AuthenticationPrincipal UserDetails userDetails,String csrfToken,HttpSession session) {\n" +
    "    String currentUser = userDetails.getUsername();\n" +
    "\n" +
    "    String sessionToken = (String) session.getAttribute(\"csrfToken\");\n" +
    "    Map<String, Object> result = new HashMap<>();\n" +
    "    if (!constantTimeEquals(csrfToken, sessionToken)) {\n" +
    "        result.put(\"success\", false);\n" +
    "        result.put(\"message\", \"Token失效！\");\n" +
    "        return result;\n" +
    "    }\n" +
    "    result.put(\"currentUser\", currentUser);\n" +
    "    result.put(\"receiver\", receiver);\n" +
    "    result.put(\"amount\", amount);\n" +
    "    result.put(\"csrfToken\", csrfToken);\n" +
    "    return result;\n" +
    "}\n" +
    "\n" +
    "private boolean constantTimeEquals(String requestToken, String sessionToken) {\n" +
    "    if (requestToken == null || sessionToken == null) {\n" +
    "        return false;\n" +
    "    }\n" +
    "    return MessageDigest.isEqual(\n" +
    "            requestToken.getBytes(StandardCharsets.UTF_8),\n" +
    "            sessionToken.getBytes(StandardCharsets.UTF_8)\n" +
    "    );\n" +
    "}"
const safeCsrfRefererZh = "public Map<String, Object> safe2(HttpServletRequest request,String receiver,String amount, @AuthenticationPrincipal UserDetails userDetails, HttpSession session) {\n" +
    "    String currentUser = userDetails.getUsername();\n" +
    "    Map<String, Object> result = new HashMap<>();\n" +
    "    String originOrReferer = request.getHeader(\"Origin\");\n" +
    "    if (originOrReferer == null) {\n" +
    "        originOrReferer = request.getHeader(\"Referer\");\n" +
    "    }\n" +
    "    if (!isTrustedSameOrigin(request, originOrReferer)) {\n" +
    "        result.put(\"success\", false);\n" +
    "        result.put(\"message\", \"Origin/Referer无效！\");\n" +
    "        return result;\n" +
    "    }\n" +
    "    result.put(\"currentUser\", currentUser);\n" +
    "    result.put(\"receiver\", receiver);\n" +
    "    result.put(\"amount\", amount);\n" +
    "    return result;\n" +
    "}\n" +
    "\n" +
    "private boolean isTrustedSameOrigin(HttpServletRequest request, String originOrReferer) {\n" +
    "    if (originOrReferer == null) {\n" +
    "        return false;\n" +
    "    }\n" +
    "    try {\n" +
    "        URI uri = new URI(originOrReferer);\n" +
    "        int actualPort = uri.getPort() == -1 ? defaultPort(uri.getScheme()) : uri.getPort();\n" +
    "        return request.getScheme().equalsIgnoreCase(uri.getScheme())\n" +
    "                && request.getServerName().equalsIgnoreCase(uri.getHost())\n" +
    "                && request.getServerPort() == actualPort;\n" +
    "    } catch (URISyntaxException e) {\n" +
    "        return false;\n" +
    "    }\n" +
    "}"

// Cross-origin security
const vulCORS = "public R vul(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String origin = request.getHeader(\"Origin\");\n" +
    "\n" +
    "    if (origin != null) {\n" +
    "        response.setHeader(\"Access-Control-Allow-Origin\", origin);\n" +
    "    } else {\n" +
    "        response.setHeader(\"Access-Control-Allow-Origin\", \"http://example.com\");\n" +
    "    }\n" +
    "\n" +
    "    // Allow cookies or other credentials.\n" +
    "    response.setHeader(\"Access-Control-Allow-Credentials\", \"true\");\n" +
    "    response.setHeader(\"Access-Control-Allow-Methods\", \"GET, POST, PUT, DELETE, OPTIONS\");\n" +
    "    response.setHeader(\"Access-Control-Allow-Headers\", \"Content-Type, Authorization, X-Requested-With\");\n" +
    "    response.setHeader(\"Vary\", \"Origin\");\n" +
    "\n" +
    "    return R.ok(\"CORS vulnerability demo: username:admin,password:Admin123\");\n" +
    "}"

const safeCORS = "private static final Set<String> TRUSTED_ORIGINS = new HashSet<>(Arrays.asList(\n" +
    "        \"http://127.0.0.1:8080\",\n" +
    "        \"https://127.0.0.1:8080\"\n" +
    "));\n" +
    "\n" +
    "public R safe(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String origin = request.getHeader(\"Origin\");\n" +
    "    response.setHeader(\"Vary\", \"Origin\");\n" +
    "    if (origin == null) {\n" +
    "        return R.ok(\"Same-origin requests do not need CORS response headers.\");\n" +
    "    }\n" +
    "    if (!TRUSTED_ORIGINS.contains(origin)) {\n" +
    "        response.setStatus(HttpServletResponse.SC_FORBIDDEN);\n" +
    "        return R.error(HttpServletResponse.SC_FORBIDDEN, \"Origin is not in the CORS allowlist.\");\n" +
    "    }\n" +
    "    response.setHeader(\"Access-Control-Allow-Origin\", origin);\n" +
    "    response.setHeader(\"Access-Control-Allow-Credentials\", \"true\");\n" +
    "    response.setHeader(\"Access-Control-Allow-Methods\", \"GET, OPTIONS\");\n" +
    "    response.setHeader(\"Access-Control-Allow-Headers\", \"Content-Type\");\n" +
    "\n" +
    "    return R.ok(\"Configured a trusted CORS origin allowlist.\");\n" +
    "}\n"

const vulJSONP = 'public void vul(HttpServletRequest request, HttpServletResponse response) throws IOException {\n' +
    '    String callback = request.getParameter("callback");\n' +
    '    String sensitiveData = "{\\"username\\":\\"admin\\",\\"password\\":\\"Admin123\\"}";\n' +
    '\n' +
    '    // Wrap data as JSONP without validating the callback parameter.\n' +
    '    String jsonpResponse = callback + "(" + sensitiveData + ");";\n' +
    '\n' +
    '    // Set the response type to JavaScript.\n' +
    '    response.setContentType("application/javascript;charset=UTF-8");\n' +
    '    response.getWriter().write(jsonpResponse);\n' +
    '}\n'

const safeJSONP = "private static final Pattern JSONP_CALLBACK_PATTERN = Pattern.compile(\n" +
    "        \"^[A-Za-z_$][A-Za-z0-9_$]*(\\\\.[A-Za-z_$][A-Za-z0-9_$]*)*$\"\n" +
    ");\n" +
    "\n" +
    "public void safe(HttpServletRequest request, HttpServletResponse response) throws IOException {\n" +
    "    String callback = request.getParameter(\"callback\");\n" +
    "    // Validate the callback function name.\n" +
    "    if (callback == null || !JSONP_CALLBACK_PATTERN.matcher(callback).matches()) {\n" +
    "        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);\n" +
    "        response.getWriter().write(\"Invalid callback\");\n" +
    "        return;\n" +
    "    }\n" +
    "\n" +
    "    String publicData = \"{\\\"message\\\":\\\"public data only\\\"}\";\n" +
    "    response.setContentType(\"application/javascript;charset=UTF-8\");\n" +
    "    response.setHeader(\"X-Content-Type-Options\", \"nosniff\");\n" +
    "    response.getWriter().write(callback + \"(\" + publicData + \");\");\n" +
    "}"
const vulCORSZh = "public R vul(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String origin = request.getHeader(\"Origin\");\n" +
    "\n" +
    "    if (origin != null) {\n" +
    "        response.setHeader(\"Access-Control-Allow-Origin\", origin);\n" +
    "    } else {\n" +
    "        response.setHeader(\"Access-Control-Allow-Origin\", \"http://example.com\");\n" +
    "    }\n" +
    "\n" +
    "    // 允许携带 Cookie 或其他凭证\n" +
    "    response.setHeader(\"Access-Control-Allow-Credentials\", \"true\");\n" +
    "    response.setHeader(\"Access-Control-Allow-Methods\", \"GET, POST, PUT, DELETE, OPTIONS\");\n" +
    "    response.setHeader(\"Access-Control-Allow-Headers\", \"Content-Type, Authorization, X-Requested-With\");\n" +
    "    response.setHeader(\"Vary\", \"Origin\");\n" +
    "\n" +
    "    return R.ok(\"CORS漏洞演示：username:admin,password:Admin123\");\n" +
    "}"

const safeCORSZh = "private static final Set<String> TRUSTED_ORIGINS = new HashSet<>(Arrays.asList(\n" +
    "        \"http://127.0.0.1:8080\",\n" +
    "        \"https://127.0.0.1:8080\"\n" +
    "));\n" +
    "\n" +
    "public R safe(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String origin = request.getHeader(\"Origin\");\n" +
    "    response.setHeader(\"Vary\", \"Origin\");\n" +
    "    if (origin == null) {\n" +
    "        return R.ok(\"同源请求不需要CORS响应头\");\n" +
    "    }\n" +
    "    if (!TRUSTED_ORIGINS.contains(origin)) {\n" +
    "        response.setStatus(HttpServletResponse.SC_FORBIDDEN);\n" +
    "        return R.error(HttpServletResponse.SC_FORBIDDEN, \"Origin不在CORS白名单\");\n" +
    "    }\n" +
    "    response.setHeader(\"Access-Control-Allow-Origin\", origin);\n" +
    "    response.setHeader(\"Access-Control-Allow-Credentials\", \"true\");\n" +
    "    response.setHeader(\"Access-Control-Allow-Methods\", \"GET, OPTIONS\");\n" +
    "    response.setHeader(\"Access-Control-Allow-Headers\", \"Content-Type\");\n" +
    "\n" +
    "    return R.ok(\"配置CORS可信源白名单\");\n" +
    "}\n"

const vulJSONPZh = 'public void vul(HttpServletRequest request, HttpServletResponse response) throws IOException {\n' +
    '    String callback = request.getParameter("callback");\n' +
    '    String sensitiveData = "{\\"username\\":\\"admin\\",\\"password\\":\\"Admin123\\"}";\n' +
    '\n' +
    '    // 返回数据包装成 JSONP 格式，并没有对 callback 参数进行安全验证\n' +
    '    String jsonpResponse = callback + "(" + sensitiveData + ");";\n' +
    '\n' +
    '    // 设置响应类型为 JavaScript 脚本\n' +
    '    response.setContentType("application/javascript;charset=UTF-8");\n' +
    '    response.getWriter().write(jsonpResponse);\n' +
    '}\n'

const safeJSONPZh = "private static final Pattern JSONP_CALLBACK_PATTERN = Pattern.compile(\n" +
    "        \"^[A-Za-z_$][A-Za-z0-9_$]*(\\\\.[A-Za-z_$][A-Za-z0-9_$]*)*$\"\n" +
    ");\n" +
    "\n" +
    "public void safe(HttpServletRequest request, HttpServletResponse response) throws IOException {\n" +
    "    String callback = request.getParameter(\"callback\");\n" +
    "    // 校验回调函数名是否合法\n" +
    "    if (callback == null || !JSONP_CALLBACK_PATTERN.matcher(callback).matches()) {\n" +
    "        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);\n" +
    "        response.getWriter().write(\"Invalid callback\");\n" +
    "        return;\n" +
    "    }\n" +
    "\n" +
    "    String publicData = \"{\\\"message\\\":\\\"public data only\\\"}\";\n" +
    "    response.setContentType(\"application/javascript;charset=UTF-8\");\n" +
    "    response.setHeader(\"X-Content-Type-Options\", \"nosniff\");\n" +
    "    response.getWriter().write(callback + \"(\" + publicData + \");\");\n" +
    "}"

const vulDos = "public void vul(Integer width,Integer height,HttpServletResponse response) throws IOException {\n" +
    "    response.setContentType(\"image/jpeg\");\n" +
    "    response.setHeader(\"Pragma\", \"no-cache\");\n" +
    "    response.setHeader(\"Cache-Control\", \"no-cache\");\n" +
    "    // Captcha parameters are controllable, causing denial of service.\n" +
    "    ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(width, height,4,3);\n" +
    "    try {\n" +
    "        shearCaptcha.write(response.getOutputStream());\n" +
    "    } catch (IOException e) {\n" +
    "        throw new RuntimeException(e);\n" +
    "    }\n" +
    "}"
const safeDos = "public void safe(Integer width,Integer height,HttpServletResponse response) throws IOException {\n" +
    "    if (width == null || height == null || width <= 0 || height <= 0\n" +
    "            || width > MAX_IMAGE_WIDTH || height > MAX_IMAGE_HEIGHT\n" +
    "            || (long) width * height > MAX_IMAGE_PIXELS) {\n" +
    "        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);\n" +
    "        response.setContentType(\"text/plain;charset=UTF-8\");\n" +
    "        response.getWriter().write(\"Image dimensions exceed the limit.\");\n" +
    "        return;\n" +
    "    }\n" +
    "    response.setContentType(\"image/jpeg\");\n" +
    "    ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(width, height, 4, 3);\n" +
    "    shearCaptcha.write(response.getOutputStream());\n" +
    "}"
const vul2Dos = "// Recursively decompress ZIP files found inside the archive.\n" +
    "if (entry.getName().endsWith(\".zip\")) {\n" +
    "    // Create a temporary file to store this ZIP.\n" +
    "    File tempFile = File.createTempFile(\"unzip\", \".zip\");\n" +
    "    try (FileOutputStream fos = new FileOutputStream(tempFile)) {\n" +
    "        byte[] buffer = new byte[1024];\n" +
    "        int length;\n" +
    "        while ((length = zipInputStream.read(buffer)) != -1) {\n" +
    "            fos.write(buffer, 0, length);\n" +
    "        }\n" +
    "    }\n" +
    "    // Recursively decompress the new ZIP file.\n" +
    "    unzip(tempFile, currentDepth + 1, maxDepth);\n" +
    "    // Delete the temporary file after decompression.\n" +
    "    tempFile.delete();\n" +
    "} "

const vulDosZh = "public void vul(Integer width,Integer height,HttpServletResponse response) throws IOException {\n" +
    "    response.setContentType(\"image/jpeg\");\n" +
    "    response.setHeader(\"Pragma\", \"no-cache\");\n" +
    "    response.setHeader(\"Cache-Control\", \"no-cache\");\n" +
    "    // 验证码参数可控 造成拒绝服务攻击\n" +
    "    ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(width, height,4,3);\n" +
    "    try {\n" +
    "        shearCaptcha.write(response.getOutputStream());\n" +
    "    } catch (IOException e) {\n" +
    "        throw new RuntimeException(e);\n" +
    "    }\n" +
    "}"
const safeDosZh = "public void safe(Integer width,Integer height,HttpServletResponse response) throws IOException {\n" +
    "    if (width == null || height == null || width <= 0 || height <= 0\n" +
    "            || width > MAX_IMAGE_WIDTH || height > MAX_IMAGE_HEIGHT\n" +
    "            || (long) width * height > MAX_IMAGE_PIXELS) {\n" +
    "        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);\n" +
    "        response.setContentType(\"text/plain;charset=UTF-8\");\n" +
    "        response.getWriter().write(\"图片尺寸超出限制\");\n" +
    "        return;\n" +
    "    }\n" +
    "    response.setContentType(\"image/jpeg\");\n" +
    "    ShearCaptcha shearCaptcha = CaptchaUtil.createShearCaptcha(width, height, 4, 3);\n" +
    "    shearCaptcha.write(response.getOutputStream());\n" +
    "}"
const vul2DosZh = "// 如果解压出的文件是ZIP文件，则递归解压\n" +
    "if (entry.getName().endsWith(\".zip\")) {\n" +
    "    // 创建临时文件来存储这个ZIP\n" +
    "    File tempFile = File.createTempFile(\"unzip\", \".zip\");\n" +
    "    try (FileOutputStream fos = new FileOutputStream(tempFile)) {\n" +
    "        byte[] buffer = new byte[1024];\n" +
    "        int length;\n" +
    "        while ((length = zipInputStream.read(buffer)) != -1) {\n" +
    "            fos.write(buffer, 0, length);\n" +
    "        }\n" +
    "    }\n" +
    "    // 递归解压这个新的ZIP文件\n" +
    "    unzip(tempFile, currentDepth + 1, maxDepth);\n" +
    "    // 解压完成后删除临时文件\n" +
    "    tempFile.delete();\n" +
    "} "


const vulXpath = "public R vul(String username,String password) {\n" +
    "    try {\n" +
    "        // Build XML data.\n" +
    "        String xmlData = \"<users><user><username>admin</username><password>password</password></user></users>\";\n" +
    "        \n" +
    "\t\t// Parse the XML document.\n" +
    "        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();\n" +
    "        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));\n" +
    "\n" +
    "        // Build an XPath expression by concatenating user input. This is injectable.\n" +
    "        XPath xpath = XPathFactory.newInstance().newXPath();\n" +
    "        String expression = \"/users/user[username='\" + username + \"' and password='\" + password + \"']\";\n" +
    "        NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);\n" +
    "        if (nodes.getLength() > 0) {\n" +
    "            return R.ok(\"Username and password verified.\");\n" +
    "        } else {\n" +
    "            return R.ok(\"Username or password is incorrect.\");\n" +
    "        }\n" +
    "        ...\n" +
    "}"
const vulXpathZh = "public R vul(String username,String password) {\n" +
    "    try {\n" +
    "        // 构造XML数据\n" +
    "        String xmlData = \"<users><user><username>admin</username><password>password</password></user></users>\";\n" +
    "        \n" +
    "\t\t// 解析XML文档\n" +
    "        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();\n" +
    "        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));\n" +
    "\n" +
    "        // 构造XPath表达式（存在注入漏洞）\n" +
    "        XPath xpath = XPathFactory.newInstance().newXPath();\n" +
    "        String expression = \"/users/user[username='\" + username + \"' and password='\" + password + \"']\";\n" +
    "        NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);\n" +
    "        if (nodes.getLength() > 0) {\n" +
    "            return R.ok(\"用户名和密码验证通过！\");\n" +
    "        } else {\n" +
    "            return R.ok(\"用户名或密码错误！\");\n" +
    "        }\n" +
    "        ...\n" +
    "}"
const safeXpath = "public R safe(String username,String password) {\n" +
    "    try {\n" +
    "        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n" +
    "        DocumentBuilder builder = factory.newDocumentBuilder();\n" +
    "        String xml = \"<users><user><username>admin</username><password>password</password></user></users>\";\n" +
    "        Document doc = builder.parse(new InputSource(new StringReader(xml)));\n" +
    "\n" +
    "        XPath xpath = XPathFactory.newInstance().newXPath();\n" +
    "        xpath.setXPathVariableResolver(variableName -> resolveXPathVariable(variableName, username, password));\n" +
    "        String expression = \"/users/user[username=$username and password=$password]\";\n" +
    "        NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);\n" +
    "\n" +
    "        if (nodes.getLength() > 0) {\n" +
    "            return R.ok(\"Username and password verified. Welcome: \" + username);\n" +
    "        } else {\n" +
    "            return R.error(\"Authentication failed: username or password is incorrect.\");\n" +
    "        }\n" +
    "        ...\n" +
    "}\n"
const safeXpathZh = "public R safe(String username,String password) {\n" +
    "    try {\n" +
    "        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n" +
    "        DocumentBuilder builder = factory.newDocumentBuilder();\n" +
    "        String xml = \"<users><user><username>admin</username><password>password</password></user></users>\";\n" +
    "        Document doc = builder.parse(new InputSource(new StringReader(xml)));\n" +
    "\n" +
    "        XPath xpath = XPathFactory.newInstance().newXPath();\n" +
    "        xpath.setXPathVariableResolver(variableName -> resolveXPathVariable(variableName, username, password));\n" +
    "        String expression = \"/users/user[username=$username and password=$password]\";\n" +
    "        NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);\n" +
    "\n" +
    "        if (nodes.getLength() > 0) {\n" +
    "            return R.ok(\"用户名和密码验证通过！欢迎：\" + username);\n" +
    "        } else {\n" +
    "            return R.error(\"认证失败：用户名或密码错误\");\n" +
    "        }\n" +
    "        ...\n" +
    "}\n"

// JS leak - hardcoded credentials
const hardCoding = "function login() {\n" +
    "    // Hardcoded username and password.\n" +
    "    const hardcodedUsername = \"superadmin\";\n" +
    "    const hardcodedPassword = \"Admin@1024.com\";\n" +
    "\n" +
    "    const username = document.getElementById(\"username\").value;\n" +
    "    const password = document.getElementById(\"password\").value;\n" +
    "    if (username === hardcodedUsername && password === hardcodedPassword) {\n" +
    "        window.location.href = \"/infoLeak/js/loginSuccess\";\n" +
    "    } else {\n" +
    "        document.getElementById(\"error\").textContent = \"Username or password is incorrect.\";\n" +
    "    }\n" +
    "}"
const hardCodingZh = "function login() {\n" +
    "    // 硬编码的用户名和密码\n" +
    "    const hardcodedUsername = \"superadmin\";\n" +
    "    const hardcodedPassword = \"Admin@1024.com\";\n" +
    "\n" +
    "    const username = document.getElementById(\"username\").value;\n" +
    "    const password = document.getElementById(\"password\").value;\n" +
    "    if (username === hardcodedUsername && password === hardcodedPassword) {\n" +
    "        window.location.href = \"/infoLeak/js/loginSuccess\";\n" +
    "    } else {\n" +
    "        document.getElementById(\"error\").textContent = \"用户名或密码错误！\";\n" +
    "    }\n" +
    "}"

// JS leak - webpack bundle
const infoLeakJs = "var r = new i({\n" +
    "    SecretId: \"AKID4xax3skP8jyDs6SZS5SZR5TcfSyC9p9H\",\n" +
    "    SecretKey: \"vaz81e2B5j89iYB5FtIRJvHPIvJRJvHO\"\n" +
    "});\n" +
    "r.uploadFile({\n" +
    "    Bucket: \"official-website-1305607643\",\n" +
    "    Region: \"ap-beijing\",\n" +
    "    Key: o,\n" +
    "    Body: t,\n" +
    "    SliceSize: 5242880\n" +
    "}, (function (t, r) {\n" +
    "    t ? n(\"Upload failed\") : e({\n" +
    "        code: 200,\n" +
    "        data: {path: \"https://official-website-1305887643.cos.ap-beijing.myqcloud.com/\".concat(o)}\n" +
    "    })\n" +
    "})";
const infoLeakJsZh = "var r = new i({\n" +
    "    SecretId: \"AKID4xax3skP8jyDs6SZS5SZR5TcfSyC9p9H\",\n" +
    "    SecretKey: \"vaz81e2B5j89iYB5FtIRJvHPIvJRJvHO\"\n" +
    "});\n" +
    "r.uploadFile({\n" +
    "    Bucket: \"official-website-1305607643\",\n" +
    "    Region: \"ap-beijing\",\n" +
    "    Key: o,\n" +
    "    Body: t,\n" +
    "    SliceSize: 5242880\n" +
    "}, (function (t, r) {\n" +
    "    t ? n(\"上传失败\") : e({\n" +
    "        code: 200,\n" +
    "        data: {path: \"https://official-website-1305887643.cos.ap-beijing.myqcloud.com/\".concat(o)}\n" +
    "    })\n" +
    "})";
const infoLeakBackUp = "root@MacBook ~/www/JavaSecLab tree -L 4 -h -t\n" +
    "[ 320]  .\n" +
    "├── [  76]  deploy.sh\n" +
    "├── [ 281]  Dockerfile\n" +
    "├── [ 818]  docker-compose.yml\n" +
    "├── [ 11K]  LICENSE\n" +
    "├── [5.7K]  pom.xml\n" +
    "├── [  96]  sql\n" +
    "│   └── [2.9K]  JavaSecLab.sql\n" +
    "└── [ 128]  src\n" +
    "    └── [ 128]  main\n" +
    "        ├── [  96]  java\n" +
    "        │   └── [  96]  top\n" +
    "        └── [ 320]  resources\n" +
    "            ├── [ 273]  banner.txt\n" +
    "            ├── [ 427]  application-docker.yml\n" +
    "            ├── [9.4K]  logback-spring.xml\n" +
    "            ├── [ 421]  application-dev.yml\n" +
    "            ├── [ 420]  application-prod.yml\n" +
    "            ├── [1.2K]  application.yml\n" +
    "            └── [ 160]  mapper\n" +
    "\n" +
    "8 directories, 12 files"
const infoLeakLog = "// Debug mode is enabled, SQL execution records are printed, and SessionId is exposed.\n" +
    "JDBC Connection [com.alibaba.druid.proxy.jdbc.ConnectionProxyImpl@784bb5e2] will not be managed by Spring\n" +
    "==>  Preparing: SELECT username,password FROM user WHERE (username = ?)\n" +
    "==> Parameters: admin(String)\n" +
    "2024-11-18 16:24:18 DEBUG Statement:136 - {conn-10006, pstmt-20183} Parameters : [admin]\n" +
    "2024-11-18 16:24:18 DEBUG Statement:136 - {conn-10006, pstmt-20183} Types : [VARCHAR]\n" +
    "2024-11-18 16:24:18 DEBUG Statement:136 - {conn-10006, pstmt-20183} executed. 2.459148 millis. SELECT  username,password  FROM user \n" +
    " \n" +
    " WHERE (username = ?)\n" +
    "2024-11-18 16:24:18 DEBUG ResultSet:141 - {conn-10006, pstmt-20183, rs-50764} open\n" +
    "2024-11-18 16:24:18 DEBUG ResultSet:141 - {conn-10006, pstmt-20183, rs-50764} Header: [username, password]\n" +
    "2024-11-18 16:24:18 DEBUG ResultSet:141 - {conn-10006, pstmt-20183, rs-50764} Result: [admin, admin]\n" +
    "<==    Columns: username, password\n" +
    "<==        Row: admin, admin\n" +
    "<==      Total: 1\n" +
    "Closing non transactional SqlSession [org.apache.ibatis.session.defaults.DefaultSqlSession@23f938fe]\n" +
    "2024-11-18 16:24:18.822  INFO 1 --- [-nio-80-exec-41] RequestAwareAuthenticationSuccessHandler : username:admin logged in successfully at 2024-11-18 16:24:18 IP:123.118.108.249 session:WebAuthenticationDetails [RemoteIpAddress=123.118.108.249, SessionId=0170B66882476E34F35BC232051F63E0]\n" +
    "2024-11-18 16:24:32.737  INFO 1 --- [-nio-80-exec-41] t.w.m.system.controller.LoginController  : session id E3C352C378552D29E10BDF42647B6864, generated captcha o1kY\n" +
    "2024-11-18 16:24:44.127  INFO 1 --- [-nio-80-exec-34] t.w.m.system.controller.LoginController  : session id E3C352C378552D29E10BDF42647B6864, generated captcha 7Cwn"
const infoLeakLogZh = "// 开启了调试模式，打印了sql执行记录 并且输出了SessionId\n" +
    "JDBC Connection [com.alibaba.druid.proxy.jdbc.ConnectionProxyImpl@784bb5e2] will not be managed by Spring\n" +
    "==>  Preparing: SELECT username,password FROM user WHERE (username = ?)\n" +
    "==> Parameters: admin(String)\n" +
    "2024-11-18 16:24:18 DEBUG Statement:136 - {conn-10006, pstmt-20183} Parameters : [admin]\n" +
    "2024-11-18 16:24:18 DEBUG Statement:136 - {conn-10006, pstmt-20183} Types : [VARCHAR]\n" +
    "2024-11-18 16:24:18 DEBUG Statement:136 - {conn-10006, pstmt-20183} executed. 2.459148 millis. SELECT  username,password  FROM user \n" +
    " \n" +
    " WHERE (username = ?)\n" +
    "2024-11-18 16:24:18 DEBUG ResultSet:141 - {conn-10006, pstmt-20183, rs-50764} open\n" +
    "2024-11-18 16:24:18 DEBUG ResultSet:141 - {conn-10006, pstmt-20183, rs-50764} Header: [username, password]\n" +
    "2024-11-18 16:24:18 DEBUG ResultSet:141 - {conn-10006, pstmt-20183, rs-50764} Result: [admin, admin]\n" +
    "<==    Columns: username, password\n" +
    "<==        Row: admin, admin\n" +
    "<==      Total: 1\n" +
    "Closing non transactional SqlSession [org.apache.ibatis.session.defaults.DefaultSqlSession@23f938fe]\n" +
    "2024-11-18 16:24:18.822  INFO 1 --- [-nio-80-exec-41] RequestAwareAuthenticationSuccessHandler : 用户名:admin,于2024-11-18 16:24:18 成功登录系统 IP:123.118.108.249 session:WebAuthenticationDetails [RemoteIpAddress=123.118.108.249, SessionId=0170B66882476E34F35BC232051F63E0]\n" +
    "2024-11-18 16:24:32.737  INFO 1 --- [-nio-80-exec-41] t.w.m.system.controller.LoginController  : session id E3C352C378552D29E10BDF42647B6864， 生成的验证码 o1kY\n" +
    "2024-11-18 16:24:44.127  INFO 1 --- [-nio-80-exec-34] t.w.m.system.controller.LoginController  : session id E3C352C378552D29E10BDF42647B6864， 生成的验证码 7Cwn"

const springBootSwagger = "return new Docket(DocumentationType.OAS_30)\n" +
    "        .pathMapping(\"/\")\n" +
    "        .enable(swaggerProperties.getEnable()) // Disable in production.\n" +
    "        .apiInfo(apiInfo())\n" +
    "        .select()\n" +
    "        .apis(RequestHandlerSelectors.basePackage(\"top.whgojp\")) // Scan the application package.\n" +
    "        .paths(PathSelectors.any())\n" +
    "        .build();\n" +
    "}\n" +
    "/**\n" +
    " * API page header information.\n" +
    " */\n" +
    "private ApiInfo apiInfo() {\n" +
    "return new ApiInfoBuilder()\n" +
    "        .title(swaggerProperties.getTitle()) // Title.\n" +
    "        .description(swaggerProperties.getDescription()) // Description.\n" +
    "        .contact(new Contact(swaggerProperties.getAuthor(), swaggerProperties.getUrl(), swaggerProperties.getEmail())) // Author info.\n" +
    "        .version(swaggerProperties.getVersion()) // Version.\n" +
    "        .build();\n" +
    "}";
const springBootSwaggerZh = "return new Docket(DocumentationType.OAS_30)\n" +
    "        .pathMapping(\"/\")\n" +
    "        .enable(swaggerProperties.getEnable())//生产禁用\n" +
    "        .apiInfo(apiInfo())\n" +
    "        .select()\n" +
    "        .apis(RequestHandlerSelectors.basePackage(\"top.whgojp\"))//按包扫描,也可以扫描共同的父包，不会显示basic-error-controller\n" +
    "        .paths(PathSelectors.any())\n" +
    "        .build();\n" +
    "}\n" +
    "/**\n" +
    " * API 页面上半部分展示信息\n" +
    " */\n" +
    "private ApiInfo apiInfo() {\n" +
    "return new ApiInfoBuilder()\n" +
    "        .title(swaggerProperties.getTitle())//标题\n" +
    "        .description(swaggerProperties.getDescription())//描述\n" +
    "        .contact(new Contact(swaggerProperties.getAuthor(), swaggerProperties.getUrl(), swaggerProperties.getEmail()))//作者信息\n" +
    "        .version(swaggerProperties.getVersion())//版本号\n" +
    "        .build();\n" +
    "}";

const springBootActuator = "management:\n" +
    "  # Port used by management endpoints, separated from the main application when needed.\n" +
    "  server:\n" +
    "    port: 80\n" +
    "  # Health details. The default is \"never\"; \"always\" exposes disk and thread details.\n" +
    "  endpoint:\n" +
    "    health:\n" +
    "      show-details: always\n" +
    "  # Exposed endpoints. Default is [\"health\",\"info\"]; \"*\" exposes every accessible endpoint.\n" +
    "  endpoints:\n" +
    "    web:\n" +
    "      exposure:\n" +
    "        include: '*'\n" +
    "      base-path: /sys/actuator\n" +
    "\n" +
    "// Related endpoint information\n" +
    "Path          Description          Enabled by default\n" +
    "auditevents  Shows audit event information for the current application  Yes\n" +
    "beans  Shows a complete list of Spring Beans in the application  Yes\n" +
    "env  Shows properties from Spring ConfigurableEnvironment  Yes\n" +
    "health  Shows application health information  Yes\n" +
    "metrics  Shows metrics for the current application  Yes\n" +
    "mappings  Shows all @RequestMapping paths  Yes\n" +
    "threaddump  Performs a thread dump  Yes\n" +
    "heapdump  Returns a GZip-compressed hprof heap dump file  Yes\n" +
    "logfile  Returns log file content when logging.file or logging.path is configured  Yes\n" +
    "prometheus  Exposes metrics in Prometheus scrape format  Yes";
const springBootActuatorZh = "management:\n" +
    "  # 端点信息接口使用的端口，为了和主系统接口使用的端口进行分离\n" +
    "  server:\n" +
    "    port: 80\n" +
    "  # 端点健康情况，默认值\"never\"，设置为\"always\"可以显示硬盘使用情况和线程情况\n" +
    "  endpoint:\n" +
    "    health:\n" +
    "      show-details: always\n" +
    "  # 设置端点暴露的哪些内容，默认[\"health\",\"info\"]，设置\"*\"代表暴露所有可访问的端点\n" +
    "  endpoints:\n" +
    "    web:\n" +
    "      exposure:\n" +
    "        include: '*'\n" +
    "      base-path: /sys/actuator\n" +
    "\n" +
    "// 相关端点信息\n" +
    "路径          描述          默认启用\n" +
    "auditevents  显示当前应用程序的审计事件信息  Yes\n" +
    "beans  显示一个应用中所有Spring Beans的完整列表  Yes\n" +
    "env  显示来自Spring的 ConfigurableEnvironment的属性  Yes\n" +
    "health  显示应用的健康信息  Yes\n" +
    "metrics  展示当前应用的metrics信息  Yes\n" +
    "mappings  显示一个所有@RequestMapping路径的集合列表  Yes\n" +
    "threaddump  执行一个线程dump  Yes\n" +
    "heapdump  返回一个GZip压缩的hprof堆dump文件  Yes\n" +
    "logfile  返回日志文件内容  Yes\n" +
    "prometheus  以可以被Prometheus服务器抓取的格式显示metrics信息  Yes";
const springBootDruid = "@Configuration\n" +
    "public class DruidMonitorConfig {\n" +
    "    @Bean\n" +
    "    public ServletRegistrationBean<StatViewServlet> druidStatViewServlet() {\n" +
    "        ServletRegistrationBean<StatViewServlet> registrationBean =\n" +
    "                new ServletRegistrationBean<>(new StatViewServlet(), \"/druid/*\");\n" +
    "        registrationBean.addInitParameter(\"resetEnable\", \"false\");\n" +
    "        return registrationBean;\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "// SecurityConfigurer allows /druid/** and no login username/password is configured, exposing the Druid console.";
const springBootDruidZh = "@Configuration\n" +
    "public class DruidMonitorConfig {\n" +
    "    @Bean\n" +
    "    public ServletRegistrationBean<StatViewServlet> druidStatViewServlet() {\n" +
    "        ServletRegistrationBean<StatViewServlet> registrationBean =\n" +
    "                new ServletRegistrationBean<>(new StatViewServlet(), \"/druid/*\");\n" +
    "        registrationBean.addInitParameter(\"resetEnable\", \"false\");\n" +
    "        return registrationBean;\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "// SecurityConfigurer 中放行 /druid/**，且未设置登录账号密码，会导致Druid监控台暴露。";

const dirTraversal = 'public String listDirectory(String dir) {\n' +
    '    String staticFolderPath = sysConstant.getStaticFolder();\n' +
    '    File baseDir = new File(staticFolderPath);\n' +
    '    File requestedDir = new File(baseDir, dir);\n' +
    '\n' +
    '    // Generate HTML output.\n' +
    '    StringBuilder response = new StringBuilder();\n' +
    '    response.append("<!DOCTYPE HTML>");\n' +
    '    ...\n' +
    '\n' +
    '    File[] files = requestedDir.listFiles();\n' +
    '    if (files != null) {\n' +
    '        for (File file : files) {\n' +
    '            response.append("<li>");\n' +
    '            if (file.isDirectory()) {\n' +
    '                response.append("<a href=\\"?dir=").append(dir);\n' +
    '                if (!dir.endsWith("/")) {\n' +
    '                    response.append("/");\n' +
    '                }\n' +
    '                response.append(file.getName()).append("/\\">").append(file.getName()).append("/</a>");\n' +
    '    ...\n' +
    '    return response.toString();\n' +
    '}'
const dirTraversalZh = 'public String listDirectory(String dir) {\n' +
    '    String staticFolderPath = sysConstant.getStaticFolder();\n' +
    '    File baseDir = new File(staticFolderPath);\n' +
    '    File requestedDir = new File(baseDir, dir);\n' +
    '\n' +
    '    // 生成HTML输出\n' +
    '    StringBuilder response = new StringBuilder();\n' +
    '    response.append("<!DOCTYPE HTML>");\n' +
    '    ...\n' +
    '\n' +
    '    File[] files = requestedDir.listFiles();\n' +
    '    if (files != null) {\n' +
    '        for (File file : files) {\n' +
    '            response.append("<li>");\n' +
    '            if (file.isDirectory()) {\n' +
    '                response.append("<a href=\\"?dir=").append(dir);\n' +
    '                if (!dir.endsWith("/")) {\n' +
    '                    response.append("/");\n' +
    '                }\n' +
    '                response.append(file.getName()).append("/\\">").append(file.getName()).append("/</a>");\n' +
    '    ...\n' +
    '    return response.toString();\n' +
    '}'

const safe1ListDirectory = 'public String safe1(String dir) {\n' +
    '    String staticFolderPath = sysConstant.getStaticFolder();\n' +
    '    File baseDir = new File(staticFolderPath);\n' +
    '\n' +
    '    String decodedDir = URLDecoder.decode(dir, StandardCharsets.UTF_8.name());\n' +
    '\n' +
    '    // Filter sensitive characters.\n' +
    '    if (decodedDir.contains(".") || decodedDir.contains(";") || decodedDir.contains("\\\\") || decodedDir.contains("%")) {\n' +
    '        return "Illegal character.";\n' +
    '    }\n' +
    '    File requestedDir = new File(baseDir, dir);\n' +
    '    ...\n' +
    '}'
const safe1ListDirectoryZh = 'public String safe1(String dir) {\n' +
    '    String staticFolderPath = sysConstant.getStaticFolder();\n' +
    '    File baseDir = new File(staticFolderPath);\n' +
    '\n' +
    '    String decodedDir = URLDecoder.decode(dir, StandardCharsets.UTF_8.name());\n' +
    '\n' +
    '    // 进行敏感字符过滤\n' +
    '    if (decodedDir.contains(".") || decodedDir.contains(";") || decodedDir.contains("\\\\") || decodedDir.contains("%")) {\n' +
    '        return "非法字符！";\n' +
    '    }\n' +
    '    File requestedDir = new File(baseDir, dir);\n' +
    '    ...\n' +
    '}'

const safe2ListDirectory = "public String safe2(String dir) {\n" +
    "    File baseDir = resolveStaticBaseDir();\n" +
    "    String relativeDir = normalizeRelativeDir(dir);\n" +
    "\n" +
    "    // Check whether the requested directory stays inside the configured root.\n" +
    "try {\n" +
    "    Path basePath = baseDir.getCanonicalFile().toPath();\n" +
    "    File requestedDir = new File(baseDir, relativeDir);\n" +
    "    Path requestedPath = requestedDir.getCanonicalFile().toPath();\n" +
    "    if (!requestedPath.startsWith(basePath) || !requestedDir.isDirectory()) {\n" +
    "        return \"Directory not found or access denied.\";\n" +
    "    }\n" +
    "    return renderDirectoryListing(dir, requestedDir, true);\n" +
    "} catch (IOException e) {\n" +
    "    return \"Error resolving directory path.\";\n" +
    "}\n" +
    "...";
const safe2ListDirectoryZh = "public String safe2(String dir) {\n" +
    "    File baseDir = resolveStaticBaseDir();\n" +
    "    String relativeDir = normalizeRelativeDir(dir);\n" +
    "\n" +
    "    // 检查请求的目录是否在规定目录内\n" +
    "try {\n" +
    "    Path basePath = baseDir.getCanonicalFile().toPath();\n" +
    "    File requestedDir = new File(baseDir, relativeDir);\n" +
    "    Path requestedPath = requestedDir.getCanonicalFile().toPath();\n" +
    "    if (!requestedPath.startsWith(basePath) || !requestedDir.isDirectory()) {\n" +
    "        return \"Directory not found or access denied.\";\n" +
    "    }\n" +
    "    return renderDirectoryListing(dir, requestedDir, true);\n" +
    "} catch (IOException e) {\n" +
    "    return \"Error resolving directory path.\";\n" +
    "}\n" +
    "...";
const infoLeakCeShi = "public String ping(String ip, Model model) {\n" +
    "    String result = \"\";\n" +
    "    if (ip != null && !ip.isEmpty()) {\n" +
    "        try {\n" +
    "            // Command injection risk: user input is concatenated into a shell command without filtering.\n" +
    "            log.info(\"Ping test command input: {}\", ip);\n" +
    "            String command = \"ping -c 4 \" + ip;\n" +
    "//                Process process = Runtime.getRuntime().exec(command);\n" +
    "            Process process = Runtime.getRuntime().exec(new String[]{\"/bin/sh\", \"-c\", command});\n" +
    "            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));\n" +
    "            String line;\n" +
    "            StringBuilder output = new StringBuilder();\n" +
    "            while ((line = reader.readLine()) != null) {\n" +
    "                output.append(line).append(\"\\n\");\n" +
    "            }\n" +
    "            reader.close();\n" +
    "            result = output.toString();\n" +
    "        } catch (Exception e) {\n" +
    "            result = \"Error: \" + e.getMessage();\n" +
    "    ...\n" +
    "}\n";
const infoLeakCeShiZh = "public String ping(String ip, Model model) {\n" +
    "    String result = \"\";\n" +
    "    if (ip != null && !ip.isEmpty()) {\n" +
    "        try {\n" +
    "            // 这里存在命令注入漏洞，用户输入没有经过过滤直接拼接到命令中执行\n" +
    "            log.info(\"测试命令：\"+ip);\n" +
    "            String command = \"ping -c 4 \" + ip;\n" +
    "//                Process process = Runtime.getRuntime().exec(command);\n" +
    "            Process process = Runtime.getRuntime().exec(new String[]{\"/bin/sh\", \"-c\", command});\n" +
    "            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));\n" +
    "            String line;\n" +
    "            StringBuilder output = new StringBuilder();\n" +
    "            while ((line = reader.readLine()) != null) {\n" +
    "                output.append(line).append(\"\\n\");\n" +
    "            }\n" +
    "            reader.close();\n" +
    "            result = output.toString();\n" +
    "        } catch (Exception e) {\n" +
    "            result = \"Error: \" + e.getMessage();\n" +
    "    ...\n" +
    "}\n";

// 登录对抗
const vul1Account = "public class CustomUserDetailsService implements UserDetailsService {\n" +
    "    @Autowired\n" +
    "    private UserService userService;\n" +
    "\t\n" +
    "    @Override\n" +
    "    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {\n" +
    "        User sysUser = userService.getOne(Wrappers.<User>query().lambda().eq(User::getUsername, username));\n" +
    "        if (ObjectUtil.isNull(sysUser)) {\n" +
    "            throw new UsernameNotFoundException(\"User does not exist.\");\n" +
    "        // Safe approach: return a unified ambiguous error message.\n" +
    "\t\t// throw new UsernameNotFoundException(\"Username or password is incorrect.\");\n" +
    "        }\n" +
    "\n" +
    "        // If the user exists, return the UserDetails object directly without role handling.\n" +
    "        return new org.springframework.security.core.userdetails.User(sysUser.getUsername(), sysUser.getPassword(), new ArrayList<>());\n" +
    "    }\n" +
    "}"
const vul1AccountZh = "public class CustomUserDetailsService implements UserDetailsService {\n" +
    "    @Autowired\n" +
    "    private UserService userService;\n" +
    "\t\n" +
    "    @Override\n" +
    "    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {\n" +
    "        User sysUser = userService.getOne(Wrappers.<User>query().lambda().eq(User::getUsername, username));\n" +
    "        if (ObjectUtil.isNull(sysUser)) {\n" +
    "            throw new UsernameNotFoundException(\"用户不存在\");\n" +
    "        // 安全写法：统一返回模糊错误信息\n" +
    "\t\t// throw new UsernameNotFoundException(\"用户或密码错误\");\n" +
    "        }\n" +
    "\n" +
    "        // 用户存在，直接返回 UserDetails 对象，不处理角色信息\n" +
    "        return new org.springframework.security.core.userdetails.User(sysUser.getUsername(), sysUser.getPassword(), new ArrayList<>());\n" +
    "    }\n" +
    "}"
const vul2Account = "public R vul2(String username, String password) {\n" +
    "\t\n" +
    "\t// Simulate a database query.\n" +
    "\t// User user = UserService.getAllByUsernameAndPassword(username,password)\n" +
    "\tif (\"admin\".equalsIgnoreCase(username) && \"admin\".equalsIgnoreCase(password)) {\n" +
    "\t\treturn R.ok(\"Login succeeded. Username: \" + username + \", password: \" + password);\n" +
    "\t} else {\n" +
    "\t\treturn R.ok(\"Account or password is incorrect.\");\n" +
    "\t}\n" +
    "}"
const vul2AccountZh = "public R vul2(String username, String password) {\n" +
    "\t\n" +
    "\t// 这里简单模拟下数据库查询操作\n" +
    "\t// User user = UserService.getAllByUsernameAndPassword(username,password)\n" +
    "\tif (\"admin\".equalsIgnoreCase(username) && \"admin\".equalsIgnoreCase(password)) {\n" +
    "\t\treturn R.ok(\"登录成功！用户名：\" + username + \", 密码：\" + password);\n" +
    "\t} else {\n" +
    "\t\treturn R.ok(\"账号或密码错误！\");\n" +
    "\t}\n" +
    "}"

const vul1Bypass = "$.ajax({\n" +
    "type: 'POST',\n" +
    "url: '/loginconfront/bypass/vul1step1',\n" +
    "data: data.field,\n" +
    "success: function (response) {\n" +
    "\t// After step 1 account verification passes, simulate the next verification step.\n" +
    "    if (response.code === 0) {\n" +
    "    $(\"#vul1-bypass-result\").text(response.msg);\n" +
    "    setTimeout(() => {\n" +
    "        $.ajax({\n" +
    "            type: 'POST',\n" +
    "            url: '/loginconfront/bypass/vul1step2',\n" +
    "            data: {code: response.code},\n" +
    "            ..."
const vul1BypassZh = "$.ajax({\n" +
    "type: 'POST',\n" +
    "url: '/loginconfront/bypass/vul1step1',\n" +
    "data: data.field,\n" +
    "success: function (response) {\n" +
    "\t// 步骤一账号校验通过后，模拟进行下一步校验\n" +
    "    if (response.code === 0) {\n" +
    "    $(\"#vul1-bypass-result\").text(response.msg);\n" +
    "    setTimeout(() => {\n" +
    "        $.ajax({\n" +
    "            type: 'POST',\n" +
    "            url: '/loginconfront/bypass/vul1step2',\n" +
    "            data: {code: response.code},\n" +
    "            ..."
const vul2Bypass = "// step1: verify the username and switch to step 2.\n" +
    "$('#next1').on('click', function () {\n" +
    "    $.post('/loginconfront/bypass/step1', { username: username }, function (res) {\n" +
    "        if (res.code === 0) currentStep = 2;\n" +
    "    });\n" +
    "});\n" +
    "\n" +
    "// step2: verify the old password and switch to step 3.\n" +
    "$('#next2').on('click', function () {\n" +
    "    $.post('/loginconfront/bypass/step2', { oldPassword: oldPassword }, function (res) {\n" +
    "        if (res.code === 0) currentStep = 3;\n" +
    "    });\n" +
    "});\n" +
    "\n" +
    "// step3: submit the new password.\n" +
    "$('#reset-password-form').on('submit', function (e) {\n" +
    "    $.post('/loginconfront/bypass/step3', { newPassword: newPassword });\n" +
    "});"
const vul2BypassZh = "// step1：验证用户名并切换到步骤2\n" +
    "$('#next1').on('click', function () {\n" +
    "    $.post('/loginconfront/bypass/step1', { username: username }, function (res) {\n" +
    "        if (res.code === 0) currentStep = 2;\n" +
    "    });\n" +
    "});\n" +
    "\n" +
    "// step2：验证旧密码并切换到步骤3\n" +
    "$('#next2').on('click', function () {\n" +
    "    $.post('/loginconfront/bypass/step2', { oldPassword: oldPassword }, function (res) {\n" +
    "        if (res.code === 0) currentStep = 3;\n" +
    "    });\n" +
    "});\n" +
    "\n" +
    "// step3：提交新密码\n" +
    "$('#reset-password-form').on('submit', function (e) {\n" +
    "    $.post('/loginconfront/bypass/step3', { newPassword: newPassword });\n" +
    "});"
const vul1Reverse = "// Same as the server-side key, used to generate the Sign value.\n" +
    "const key = \"FF38DC304A1D74B19F24A36C09FD6B72\";\n" +
    "function generateSign(params) {\n" +
    "    const query = Object.keys(params)\n" +
    "        .sort()\n" +
    "        .map(k => `${k}=${params[k]}`)\n" +
    "        .join(\"&\");\n" +
    "    // Generate a signature with MD5.\n" +
    "    return md5(query + key);\n" +
    "}\n" +
    "const params = {\n" +
    "    username: data.field.username,\n" +
    "    password: data.field.password,\n" +
    "    timestamp: Date.now(),\n" +
    "};\n" +
    "const sign = generateSign(params);\n" +
    "\n" +
    "{\"username\":\"admin\",\"password\":\"123456\",\"timestamp\":1732373468477,\"sign\":\"1a56f2b3de87c435be816341d9bcf6fe\"}"
const vul1ReverseZh = "// 与服务端密钥一致 用于生产签名Sign\n" +
    "const key = \"FF38DC304A1D74B19F24A36C09FD6B72\";\n" +
    "function generateSign(params) {\n" +
    "    const query = Object.keys(params)\n" +
    "        .sort()\n" +
    "        .map(k => `${k}=${params[k]}`)\n" +
    "        .join(\"&\");\n" +
    "    // 使用 MD5 加密生成签名\n" +
    "    return md5(query + key);\n" +
    "}\n" +
    "const params = {\n" +
    "    username: data.field.username,\n" +
    "    password: data.field.password,\n" +
    "    timestamp: Date.now(),\n" +
    "};\n" +
    "const sign = generateSign(params);\n" +
    "\n" +
    "{\"username\":\"admin\",\"password\":\"123456\",\"timestamp\":1732373468477,\"sign\":\"1a56f2b3de87c435be816341d9bcf6fe\"}"
const vul2Reverse = "const publicKey = `-----BEGIN PUBLIC KEY-----\n" +
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx6Iq6tBvjNHqczQmJJAo\n" +
    "otsBfKM/9yJCuTV87ZlI0Y1EFG65Jo89aLHW7BqBUJepcKC9kcA5PJaWSF5BYElt\n" +
    "Y2NPnIfGkHamKeFywWh4aYy66MlBqr91Fw0Wyx8PQlp0CJKfiPEQmzwUobpimAvK\n" +
    "...\n" +
    "-----END PUBLIC KEY-----\n" +
    "`;\n" +
    "\n" +
    "const encryptField = (field) => {\n" +
    "    const encryptor = new JSEncrypt();\n" +
    "    encryptor.setPublicKey(publicKey); // Set the public key.\n" +
    "    return encryptor.encrypt(field); // Return the encrypted Base64 string.\n" +
    "};\n" +
    "\n" +
    "const encryptedUsername = encryptField(data.field.username);\n" +
    "const encryptedPassword = encryptField(data.field.password);\n" +
    "\n" +
    "{\"encryptedUsername\":\"iDF5BNv1zaM0V9qog0qzlUES3sCGYqmvrKiqPIvUgP5qE0pYn9XN3btW3PbRwLuySeruK2i8lem+L67w5+fFQBuRrpettLrHl8izIRp2W+nq9o9Kg/LSa3/+JynFoUHxrvQ2taNM1nustROpkBjJMbTOK52S6ZBa0quMw+wjfR1XExlzc99U1WJQfRAqj7Gsl9EPydRIh8vs4S/Nen5kf/dL3ZikfMbCUUBonRlYy6a3nWJ412P+hxRbSl80Z8aQKw9lH4+Iju80oFmQ6DuS6Ce70h88z/Va+xzXHDzM8w6h5iqQLzq3Kj/E+b/wsn6eM7v+LEC8LwLQ/t8z8tki9g==\",\n" +
    "\"encryptedPassword\":\"nDI0/PBwsFHnRRw7Z4gHZ6G8Uaq7BUjUxnTDw7bkR9nrTkoHfcDLKUddj2JS7WWbOyuwsUFce3/tXJYQWNMFQqGRtf6jXxFAlvTvBkRdsZXOIU+Abb4EqYw670xd5UTeAQ0lI5KNXtw6e/VbnXyX+STJdN2SO7FLbvZ4sM6gLQSVWLo/+pZsYxKlEUNxew2svlzDZtqKnyF12bzakWfzaWuovLnYCCEXV1oAJCErjgfoOS2wJADdgU0wE6KlFDMNjsCvONmO6KZpmJQ1GOq3MpyqySq8eyJkYG3cDSRo5nDo2YOcevOHifzMnKbrU9gh4/RUj8sxrykdqgLmzX3rhw==\"}"
const vul2ReverseZh = "const publicKey = `-----BEGIN PUBLIC KEY-----\n" +
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx6Iq6tBvjNHqczQmJJAo\n" +
    "otsBfKM/9yJCuTV87ZlI0Y1EFG65Jo89aLHW7BqBUJepcKC9kcA5PJaWSF5BYElt\n" +
    "Y2NPnIfGkHamKeFywWh4aYy66MlBqr91Fw0Wyx8PQlp0CJKfiPEQmzwUobpimAvK\n" +
    "...\n" +
    "-----END PUBLIC KEY-----\n" +
    "`;\n" +
    "\n" +
    "const encryptField = (field) => {\n" +
    "    const encryptor = new JSEncrypt();\n" +
    "    encryptor.setPublicKey(publicKey); // 设置公钥\n" +
    "    return encryptor.encrypt(field); // 返回加密后的 Base64 字符串\n" +
    "};\n" +
    "\n" +
    "const encryptedUsername = encryptField(data.field.username);\n" +
    "const encryptedPassword = encryptField(data.field.password);\n" +
    "\n" +
    "{\"encryptedUsername\":\"iDF5BNv1zaM0V9qog0qzlUES3sCGYqmvrKiqPIvUgP5qE0pYn9XN3btW3PbRwLuySeruK2i8lem+L67w5+fFQBuRrpettLrHl8izIRp2W+nq9o9Kg/LSa3/+JynFoUHxrvQ2taNM1nustROpkBjJMbTOK52S6ZBa0quMw+wjfR1XExlzc99U1WJQfRAqj7Gsl9EPydRIh8vs4S/Nen5kf/dL3ZikfMbCUUBonRlYy6a3nWJ412P+hxRbSl80Z8aQKw9lH4+Iju80oFmQ6DuS6Ce70h88z/Va+xzXHDzM8w6h5iqQLzq3Kj/E+b/wsn6eM7v+LEC8LwLQ/t8z8tki9g==\",\n" +
    "\"encryptedPassword\":\"nDI0/PBwsFHnRRw7Z4gHZ6G8Uaq7BUjUxnTDw7bkR9nrTkoHfcDLKUddj2JS7WWbOyuwsUFce3/tXJYQWNMFQqGRtf6jXxFAlvTvBkRdsZXOIU+Abb4EqYw670xd5UTeAQ0lI5KNXtw6e/VbnXyX+STJdN2SO7FLbvZ4sM6gLQSVWLo/+pZsYxKlEUNxew2svlzDZtqKnyF12bzakWfzaWuovLnYCCEXV1oAJCErjgfoOS2wJADdgU0wE6KlFDMNjsCvONmO6KZpmJQ1GOq3MpyqySq8eyJkYG3cDSRo5nDo2YOcevOHifzMnKbrU9gh4/RUj8sxrykdqgLmzX3rhw==\"}"

const vul1Credential = "public R generateJWT(String username, String role) {\n" +
    "    String jwt = Jwts.builder()\n" +
    "            .setSubject(username)\n" +
    "            .claim(\"role\", role)\n" +
    "            .signWith(jwtKey())\n" +
    "            .compact();\n" +
    "    return R.ok(jwt);\n" +
    "}\n" +
    "\n" +
    "public R vul1(String jwt) {\n" +
    "    String user = Jwts.parser()\n" +
    "            .setSigningKey(jwtKey())\n" +
    "            .parseClaimsJws(jwt)\n" +
    "            .getBody()\n" +
    "            .getSubject();\n" +
    "    String role = Jwts.parserBuilder()\n" +
    "            .setSigningKey(jwtKey())\n" +
    "            .build()\n" +
    "            .parseClaimsJws(jwt)\n" +
    "            .getBody()\n" +
    "            .get(\"role\", String.class);\n" +
    "    return R.ok(\"JWT parsed successfully. user: \" + user + \", role: \" + role);\n" +
    "}"
const vul1CredentialZh = "public R generateJWT(String username, String role) {\n" +
    "    String jwt = Jwts.builder()\n" +
    "            .setSubject(username)\n" +
    "            .claim(\"role\", role)\n" +
    "            .signWith(jwtKey())\n" +
    "            .compact();\n" +
    "    return R.ok(jwt);\n" +
    "}\n" +
    "\n" +
    "public R vul1(String jwt) {\n" +
    "    String user = Jwts.parser()\n" +
    "            .setSigningKey(jwtKey())\n" +
    "            .parseClaimsJws(jwt)\n" +
    "            .getBody()\n" +
    "            .getSubject();\n" +
    "    String role = Jwts.parserBuilder()\n" +
    "            .setSigningKey(jwtKey())\n" +
    "            .build()\n" +
    "            .parseClaimsJws(jwt)\n" +
    "            .getBody()\n" +
    "            .get(\"role\", String.class);\n" +
    "    return R.ok(\"JWT解析成功，user：\" + user + \",role：\" + role);\n" +
    "}"

const vul2Credential = "vul2Credential"


// java专题 SPEL注入
const spelVul = "public R vul(String ex) {\n" +
    "    try {\n" +
    "        ExpressionParser parser = new SpelExpressionParser();\n" +
    "        EvaluationContext evaluationContext = new StandardEvaluationContext();\n" +
    "        Expression exp = parser.parseExpression(ex);\n" +
    "        Object result = exp.getValue(evaluationContext);\n" +
    "        return R.ok(String.valueOf(result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"SpEL expression execution failed: \" + e.getMessage());\n" +
    "    }\n" +
    "}"
const spelVulZh = "public R vul(String ex) {\n" +
    "    try {\n" +
    "        ExpressionParser parser = new SpelExpressionParser();\n" +
    "        EvaluationContext evaluationContext = new StandardEvaluationContext();\n" +
    "        Expression exp = parser.parseExpression(ex);\n" +
    "        Object result = exp.getValue(evaluationContext);\n" +
    "        return R.ok(String.valueOf(result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"SPEL表达式执行失败：\" + e.getMessage());\n" +
    "    }\n" +
    "}"

const spelSafe = "public R safe(String ex) {\n" +
    "    try {\n" +
    "        ExpressionParser parser = new SpelExpressionParser();\n" +
    "        // Use SimpleEvaluationContext to restrict dangerous capabilities such as Java type references, constructor calls, and Bean references.\n" +
    "        EvaluationContext simpleContext = SimpleEvaluationContext.forReadOnlyDataBinding().build();\n" +
    "        Expression exp = parser.parseExpression(ex);\n" +
    "        Object result = exp.getValue(simpleContext);\n" +
    "        return R.ok(String.valueOf(result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"Expression blocked by the safe context: \" + e.getMessage());\n" +
    "    }\n" +
    "}\n"
const spelSafeZh = "public R safe(String ex) {\n" +
    "    try {\n" +
    "        ExpressionParser parser = new SpelExpressionParser();\n" +
    "        // 使用 SimpleEvaluationContext 限制 Java 类型引用、构造函数调用、Bean 引用等危险能力\n" +
    "        EvaluationContext simpleContext = SimpleEvaluationContext.forReadOnlyDataBinding().build();\n" +
    "        Expression exp = parser.parseExpression(ex);\n" +
    "        Object result = exp.getValue(simpleContext);\n" +
    "        return R.ok(String.valueOf(result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"表达式被安全上下文限制：\" + e.getMessage());\n" +
    "    }\n" +
    "}\n"

const sstiVul = "public String vul1(@RequestParam String para, Model model) {\n" +
    "    // User input is concatenated into the template path. Thymeleaf preprocesses __${...}__ in view names.\n" +
    "    return \"vul/ssti/\" + para;\n" +
    "}\n" +
    "\n" +
    "public String vul2(@PathVariable String path) {\n" +
    "    // URL path variables are concatenated into template paths and trigger the same preprocessing path.\n" +
    "    log.info(\"SSTI injection: {}\", path);\n" +
    "    return \"vul/ssti/\" + path;\n" +
    "}\n" +
    "\n" +
    "// Vulnerable dependency version reference\n" +
    "<parent>\n" +
    "    <groupId>org.springframework.boot</groupId>\n" +
    "    <artifactId>spring-boot-starter-parent</artifactId>\n" +
    "<!--        <version>2.7.14</version>-->\n" +
    "    <version>2.4.1</version>\n" +
    "    <relativePath/>\n" +
    "</parent>\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.springframework.boot</groupId>\n" +
    "    <artifactId>spring-boot-starter-thymeleaf</artifactId>\n" +
    "    <version>2.4.1</version>\n" +
    "</dependency>\n"
const sstiVulZh = "public String vul1(@RequestParam String para, Model model) {\n" +
    "    // 用户输入直接拼接到模板路径，Thymeleaf 会对视图名中的 __${...}__ 做预处理\n" +
    "    return \"vul/ssti/\" + para;\n" +
    "}\n" +
    "\n" +
    "public String vul2(@PathVariable String path) {\n" +
    "    // URL 路径变量直接拼接到模板路径，同样会触发 Thymeleaf 视图名预处理\n" +
    "    log.info(\"SSTI注入：\" + path);\n" +
    "    return \"vul/ssti/\" + path;\n" +
    "}\n" +
    "\n" +
    "// 缺陷组件版本参考\n" +
    "<parent>\n" +
    "    <groupId>org.springframework.boot</groupId>\n" +
    "    <artifactId>spring-boot-starter-parent</artifactId>\n" +
    "<!--        <version>2.7.14</version>-->\n" +
    "    <version>2.4.1</version>\n" +
    "    <relativePath/>\n" +
    "</parent>\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.springframework.boot</groupId>\n" +
    "    <artifactId>spring-boot-starter-thymeleaf</artifactId>\n" +
    "    <version>2.4.1</version>\n" +
    "</dependency>\n"
const sstiSafe = "public String safe1(String para, Model model) {\n" +
    "    List<String> white_list = new ArrayList<>(Arrays.asList(\"vul\", \"ssti\"));\n" +
    "    if (white_list.contains(para)){\n" +
    "        return \"vul/ssti/\" + para;\n" +
    "    } else{\n" +
    "        return \"common/401\";\n" +
    "    }\n" +
    "}\n" +
    "@GetMapping(\"/safe2/{path}\")\n" +
    "public void safe2(@PathVariable String path, HttpServletResponse response) throws IOException {\n" +
    "    log.info(\"SSTI injection: {}\", path);\n" +
    "    response.setContentType(\"text/plain;charset=UTF-8\");\n" +
    "    response.getWriter().write(msg(\"ssti.result.skip\", path));\n" +
    "}"
const sstiSafeZh = "public String safe1(String para, Model model) {\n" +
    "    List<String> white_list = new ArrayList<>(Arrays.asList(\"vul\", \"ssti\"));\n" +
    "    if (white_list.contains(para)){\n" +
    "        return \"vul/ssti/\" + para;\n" +
    "    } else{\n" +
    "        return \"common/401\";\n" +
    "    }\n" +
    "}\n" +
    "@GetMapping(\"/safe2/{path}\")\n" +
    "public void safe2(@PathVariable String path, HttpServletResponse response) throws IOException {\n" +
    "    log.info(\"SSTI注入：\" + path);\n" +
    "    response.setContentType(\"text/plain;charset=UTF-8\");\n" +
    "    response.getWriter().write(msg(\"ssti.result.skip\", path));\n" +
    "}"

const vulReadObject = "public R vul(String payload) {\n" +
    "    try {\n" +
    "        byte[] bytes = decodePayload(payload);\n" +
    "        Object obj;\n" +
    "        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {\n" +
    "            obj = in.readObject();\n" +
    "        }\n" +
    "        return R.ok(msg(\"deserialize.readObject.result.vul\", obj));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"deserialize.result.invalidPayload\", e.getMessage()));\n" +
    "    }\n" +
"}"
const vulReadObjectZh = vulReadObject
const safeReadObject1 = "public R safe1(String payload) {\n" +
    "    // Disable unsafe Commons Collections deserialization.\n" +
    "    System.setProperty(\"org.apache.commons.collections.enableUnsafeSerialization\", \"false\");\n" +
    "    try {\n" +
    "        byte[] bytes = decodePayload(payload);\n" +
    "        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {\n" +
    "            in.readObject();\n" +
    "        }\n" +
    "        return R.ok(msg(\"deserialize.readObject.result.safeSwitch\"));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"deserialize.result.invalidPayload\", e.getMessage()));\n" +
    "    }\n" +
    "}"
const safeReadObject1Zh = "public R safe1(String payload) {\n" +
    "    // 禁用 Commons Collections 不安全反序列化开关\n" +
    "    System.setProperty(\"org.apache.commons.collections.enableUnsafeSerialization\", \"false\");\n" +
    "    try {\n" +
    "        byte[] bytes = decodePayload(payload);\n" +
    "        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {\n" +
    "            in.readObject();\n" +
    "        }\n" +
    "        return R.ok(msg(\"deserialize.readObject.result.safeSwitch\"));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"deserialize.result.invalidPayload\", e.getMessage()));\n" +
    "    }\n" +
    "}"
const safeReadObject2 = "public R safe2(String payload) {\n" +
    "    try {\n" +
    "        byte[] bytes = decodePayload(payload);\n" +
    "        // Create ValidatingObjectInputStream and constrain allowed classes.\n" +
    "        try (ValidatingObjectInputStream ois = new ValidatingObjectInputStream(new ByteArrayInputStream(bytes))) {\n" +
    "            ois.reject(java.lang.Runtime.class);\n" +
    "            ois.reject(java.lang.ProcessBuilder.class);\n" +
    "            // Only allow the Sqli class in this demo.\n" +
    "            ois.accept(Sqli.class);\n" +
    "            ois.readObject();\n" +
    "        }\n" +
    "        return R.ok(msg(\"deserialize.readObject.result.safeAllowlist\"));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"deserialize.result.invalidPayload\", e.getMessage()));\n" +
    "    }\n" +
    "}"
const safeReadObject2Zh = "public R safe2(String payload) {\n" +
    "    try {\n" +
    "        byte[] bytes = decodePayload(payload);\n" +
    "        // 创建 ValidatingObjectInputStream 对象\n" +
    "        try (ValidatingObjectInputStream ois = new ValidatingObjectInputStream(new ByteArrayInputStream(bytes))) {\n" +
    "            ois.reject(java.lang.Runtime.class);\n" +
    "            ois.reject(java.lang.ProcessBuilder.class);\n" +
    "            // 只允许反序列化Sqli类\n" +
    "            ois.accept(Sqli.class);\n" +
    "            ois.readObject();\n" +
    "        }\n" +
    "        return R.ok(msg(\"deserialize.readObject.result.safeAllowlist\"));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"deserialize.result.invalidPayload\", e.getMessage()));\n" +
    "    }\n" +
    "}"
const safeReadObject3 = "safeReadObject3"

const vulSnakeYaml = "public R vul(String payload) {\n" +
    "    if (payload == null || payload.trim().isEmpty()) {\n" +
    "        return R.error(msg(\"common.payload.empty\"));\n" +
    "    }\n" +
    "    Yaml y = new Yaml();\n" +
    "    Object result = y.load(payload);\n" +
    "    return R.ok(msg(\"deserialize.snakeYaml.result.vul\", result));\n" +
    "}\n" +
    "\n" +
    "// Sample payload\n" +
    "payload=!!top.whgojp.modules.sqli.entity.Sqli {id: 1, username: test, password: pass}\n"
const vulSnakeYamlZh = "public R vul(String payload) {\n" +
    "    if (payload == null || payload.trim().isEmpty()) {\n" +
    "        return R.error(msg(\"common.payload.empty\"));\n" +
    "    }\n" +
    "    Yaml y = new Yaml();\n" +
    "    Object result = y.load(payload);\n" +
    "    return R.ok(msg(\"deserialize.snakeYaml.result.vul\", result));\n" +
    "}\n" +
    "\n" +
    "// payload示例\n" +
    "payload=!!top.whgojp.modules.sqli.entity.Sqli {id: 1, username: test, password: pass}\n"
const safeSnakeYaml = "public R safe(String payload) {\n" +
    "    try {\n" +
    "        Yaml y = new Yaml(new SafeConstructor());\n" +
    "        Object result = y.load(payload);\n" +
    "        return R.ok(msg(\"deserialize.snakeYaml.result.safe\", result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"deserialize.snakeYaml.result.failed\", e.getMessage()));\n" +
    "    }\n" +
"}"
const safeSnakeYamlZh = "public R safe(String payload) {\n" +
    "    try {\n" +
    "        Yaml y = new Yaml(new SafeConstructor());\n" +
    "        Object result = y.load(payload);\n" +
    "        return R.ok(msg(\"deserialize.snakeYaml.result.safe\", result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"deserialize.snakeYaml.result.failed\", e.getMessage()));\n" +
    "    }\n" +
"}"

const vulXmlDecoder = 'public R vul(String payload) {\n' +
    '    String[] strCmd = payload.split(" ");\n' +
    '    StringBuilder xml = new StringBuilder()\n' +
    '            .append("<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>")\n' +
    '            .append("<java version=\\"1.8.0_151\\" class=\\"java.beans.XMLDecoder\\">")\n' +
    '            .append("<object class=\\"java.lang.ProcessBuilder\\">")\n' +
    '            .append("<array class=\\"java.lang.String\\" length=\\"").append(strCmd.length).append("\\">");\n' +
    '    for (int i = 0; i < strCmd.length; i++) {\n' +
    '        xml.append("<void index=\\"").append(i).append("\\"><string>")\n' +
    '                .append(strCmd[i]).append("</string></void>");\n' +
    '    }\n' +
    '    xml.append("</array><void method=\\"start\\" /></object></java>");\n' +
    '    try {\n' +
    '        new java.beans.XMLDecoder(new ByteArrayInputStream(xml.toString().getBytes(StandardCharsets.UTF_8)))\n' +
    '                .readObject().toString();\n' +
    '        return R.ok(msg("deserialize.xmlDecoder.result.executed"));\n' +
    '    } catch (Exception e) {\n' +
    '        return R.error(msg("deserialize.xmlDecoder.result.executeFailed", e.getMessage()));\n' +
    '    }\n' +
    '}'
const vulXmlDecoderZh = vulXmlDecoder

const safeXmlDecoder = 'public R safe(@RequestParam String payload) {\n' +
    '    try {\n' +
    '        // Build XML as text, then parse it with a normal SAX parser.\n' +
    '        ...\n' +
    '        SAXParserFactory factory = SAXParserFactory.newInstance();\n' +
    '        SAXParser saxParser = factory.newSAXParser();\n' +
    '        CommandHandler handler = new CommandHandler();\n' +
    '        InputSource inputSource = new InputSource(new ByteArrayInputStream(xml.toString().getBytes(StandardCharsets.UTF_8)));\n' +
    '        saxParser.parse(inputSource, handler);\n' +
    '        List<String> args = handler.getArgs();\n' +
    '        System.out.println("Parsed command: " + String.join(" ", args));\n' +
    '        return R.ok(msg("deserialize.xmlDecoder.result.parsed", String.join(" ", args)));\n' +
    '    } catch (Exception e) {\n' +
    '        return R.error(msg("deserialize.xmlDecoder.result.parseFailed", e.getMessage()));\n' +
    '    }\n' +
    '}'
const safeXmlDecoderZh = 'public R safe(@RequestParam String payload) {\n' +
    '    try {\n' +
    '        // 构建 XML 字符串\n' +
    '        ...\n' +
    '        // 使用 SAX 解析器解析 XML\n' +
    '        SAXParserFactory factory = SAXParserFactory.newInstance();\n' +
    '        SAXParser saxParser = factory.newSAXParser();\n' +
    '        CommandHandler handler = new CommandHandler();\n' +
    '        InputSource inputSource = new InputSource(new ByteArrayInputStream(xml.toString().getBytes(StandardCharsets.UTF_8)));\n' +
    '        saxParser.parse(inputSource, handler);\n' +
    '        List<String> args = handler.getArgs();\n' +
    '        return R.ok(msg("deserialize.xmlDecoder.result.parsed", String.join(" ", args)));\n' +
    '    } catch (Exception e) {\n' +
    '        return R.error(msg("deserialize.xmlDecoder.result.parseFailed", e.getMessage()));\n' +
    '    }\n' +
    '}'

const vulFastjson = "public String vul(@RequestBody String content) {\n" +
    "    try {\n" +
    "        JSONObject jsonObject = JSON.parseObject(content);\n" +
    "        return jsonObject.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>com.alibaba</groupId>\n" +
    "    <artifactId>fastjson</artifactId>\n" +
    "    <version>1.2.37</version>\n" +
    "</dependency>"
const vulFastjsonZh = "public String vul(@RequestBody String content) {\n" +
    "    try {\n" +
    "        JSONObject jsonObject = JSON.parseObject(content);\n" +
    "        return jsonObject.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>com.alibaba</groupId>\n" +
    "    <artifactId>fastjson</artifactId>\n" +
    "    <version>1.2.37</version>\n" +
    "</dependency>"
const safeFastjson = "public String safe(@RequestBody String content) {\n" +
    "    try {\n" +
    "        // 1. Disable AutoType.\n" +
    "        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);\n" +
    "        // 2. Prefer an allowlist when AutoType is required.\n" +
    "//      ParserConfig.getGlobalInstance().setAutoTypeSupport(true);\n" +
    "//      ParserConfig.getGlobalInstance().addAccept(\"top.whgojp.WhiteListClass\");\n" +
    "        // 3. Fastjson 1.2.68+ supports SafeMode.\n" +
    "//      ParserConfig.getGlobalInstance().setSafeMode(true);\n" +
    "        JSONObject jsonObject = JSON.parseObject(content);\n" +
    "        return jsonObject.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}\n" +
    "<dependency>\n" +
    "    <groupId>com.alibaba</groupId>\n" +
    "    <artifactId>fastjson</artifactId>\n" +
    "    <version>1.2.83 or later</version>\n" +
    "</dependency>"
const safeFastjsonZh = "public String safe(@RequestBody String content) {\n" +
    "    try {\n" +
    "        // 1、禁用 AutoType\n" +
    "        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);\n" +
    "        // 2、使用 AutoType 白名单机制\n" +
    "//      ParserConfig.getGlobalInstance().setAutoTypeSupport(true);\n" +
    "//      ParserConfig.getGlobalInstance().addAccept(\"top.whgojp.WhiteListClass\");\n" +
    "        // 3、1.2.68 之后 Fastjson 增加了 SafeMode 支持\n" +
    "//      ParserConfig.getGlobalInstance().setSafeMode(true);\n" +
    "        JSONObject jsonObject = JSON.parseObject(content);\n" +
    "        return jsonObject.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}\n" +
    "<dependency>\n" +
    "    <groupId>com.alibaba</groupId>\n" +
    "    <artifactId>fastjson</artifactId>\n" +
    "    <version>1.2.83 及以上</version>\n" +
    "</dependency>"

const vulJackson = "public R vul(@RequestBody String content) {\n" +
    "    try {\n" +
    "        ObjectMapper mapper = new ObjectMapper();\n" +
    "        mapper.enableDefaultTyping(); // Enable polymorphic type handling.\n" +
    "        Object obj = mapper.readValue(content, Object.class);\n" +
    "        return R.ok(msg(\"component.jackson.result.vul\", obj.toString()));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.jackson.result.failed\"));\n" +
    "    }\n" +
    "}"
const vulJacksonZh = "public R vul(@RequestBody String content) {\n" +
    "    try {\n" +
    "        ObjectMapper mapper = new ObjectMapper();\n" +
    "        mapper.enableDefaultTyping(); // 启用多态类型处理\n" +
    "        Object obj = mapper.readValue(content, Object.class);\n" +
    "        return R.ok(msg(\"component.jackson.result.vul\", obj.toString()));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.jackson.result.failed\"));\n" +
    "    }\n" +
    "}"

const safeJackson = "public R safe(@RequestBody String payload) {\n" +
    "    try {\n" +
    "        ObjectMapper mapper = new ObjectMapper();\n" +
    "        mapper.activateDefaultTyping(\n" +
    "                LaissezFaireSubTypeValidator.instance,\n" +
    "                ObjectMapper.DefaultTyping.NON_FINAL\n" +
    "        );\n" +
    "        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);\n" +
    "        Map<String, Object> safePayload = mapper.readValue(payload, Map.class);\n" +
    "        return R.ok(mapper.writeValueAsString(safePayload));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.jackson.result.safeFailed\"));\n" +
    "    }\n" +
    "}"
const safeJacksonZh = "public R safe(@RequestBody String payload) {\n" +
    "    try {\n" +
    "        ObjectMapper mapper = new ObjectMapper();\n" +
    "        mapper.activateDefaultTyping(\n" +
    "                LaissezFaireSubTypeValidator.instance,\n" +
    "                ObjectMapper.DefaultTyping.NON_FINAL\n" +
    "        );\n" +
    "        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);\n" +
    "        Map<String, Object> safePayload = mapper.readValue(payload, Map.class);\n" +
    "        return R.ok(mapper.writeValueAsString(safePayload));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.jackson.result.safeFailed\"));\n" +
    "    }\n" +
    "}"

const vulXstream = "public R vul(@RequestBody String content) {\n" +
    "    try {\n" +
    "        XStream xs = new XStream();\n" +
    "        Object result = xs.fromXML(content);\n" +
    "        return R.ok(msg(\"component.xstream.result.vul\", result.toString()));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.xstream.result.vulFailed\", e.getMessage()));\n" +
    "    }\n" +
    "}"
const vulXstreamZh = "public R vul(@RequestBody String content) {\n" +
    "    try {\n" +
    "        XStream xs = new XStream();\n" +
    "        Object result = xs.fromXML(content); // 反序列化得到对象\n" +
    "        return R.ok(msg(\"component.xstream.result.vul\", result.toString()));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.xstream.result.vulFailed\", e.getMessage()));\n" +
    "    }\n" +
    "}"

const safeXstreamBlackList = "public R safe1(@RequestBody String content) {\n" +
    "    try {\n" +
    "        XStream xstream = new XStream();\n" +
    "        xstream.addPermission(NoTypePermission.NONE);\n" +
    "        xstream.denyPermission(new ExplicitTypePermission(new Class[]{ImageIO.class}));\n" +
    "        Object result = xstream.fromXML(content);\n" +
    "        return R.ok(msg(\"component.xstream.result.blacklist\", result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.xstream.result.blacklistFailed\", e.getMessage()));\n" +
    "    }\n" +
    "}"
const safeXstreamBlackListZh = "public R safe1(@RequestBody String content) {\n" +
    "    try {\n" +
    "        XStream xstream = new XStream();\n" +
    "        xstream.addPermission(NoTypePermission.NONE); // 清除默认权限\n" +
    "        xstream.denyPermission(new ExplicitTypePermission(new Class[]{ImageIO.class}));\n" +
    "        Object result = xstream.fromXML(content);\n" +
    "        return R.ok(msg(\"component.xstream.result.blacklist\", result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.xstream.result.blacklistFailed\", e.getMessage()));\n" +
    "    }\n" +
    "}"

const safeXstreamWhiteList = "public R safe2(@RequestBody String content) {\n" +
    "    try {\n" +
    "        XStream xstream = new XStream();\n" +
    "        xstream.addPermission(NoTypePermission.NONE);\n" +
    "        xstream.addPermission(ArrayTypePermission.ARRAYS);\n" +
    "        xstream.addPermission(NullPermission.NULL);\n" +
    "        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);\n" +
    "        xstream.addPermission(new ExplicitTypePermission(new Class[]{Date.class}));\n" +
    "        Object result = xstream.fromXML(content);\n" +
    "        return R.ok(msg(\"component.xstream.result.allowlist\", result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.xstream.result.allowlistFailed\", e.getMessage()));\n" +
    "    }\n" +
    "}"
const safeXstreamWhiteListZh = "public R safe2(@RequestBody String content) {\n" +
    "    try {\n" +
    "        XStream xstream = new XStream();\n" +
    "        xstream.addPermission(NoTypePermission.NONE); // 清除默认权限\n" +
    "        xstream.addPermission(ArrayTypePermission.ARRAYS);\n" +
    "        xstream.addPermission(NullPermission.NULL);\n" +
    "        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);\n" +
    "        xstream.addPermission(new ExplicitTypePermission(new Class[]{Date.class}));\n" +
    "        Object result = xstream.fromXML(content);\n" +
    "        return R.ok(msg(\"component.xstream.result.allowlist\", result));\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(msg(\"component.xstream.result.allowlistFailed\", e.getMessage()));\n" +
    "    }\n" +
    "}"

const vulLog4j2 = "public R vul(String payload) {\n" +
    "    logger.error(payload); // Log4j2 resolves ${} lookups here.\n" +
    "    return R.ok(msg(\"component.log4j2.result.vul\", payload));\n" +
    "}\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.apache.logging.log4j</groupId>\n" +
    "    <artifactId>log4j-core</artifactId>\n" +
    "    <version>2.8.2</version>\n" +
    "</dependency>"
const vulLog4j2Zh = "public R vul(String payload) {\n" +
    "    logger.error(payload); // 此处解析 ${} 从而触发漏洞\n" +
    "    return R.ok(msg(\"component.log4j2.result.vul\", payload));\n" +
    "}\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.apache.logging.log4j</groupId>\n" +
    "    <artifactId>log4j-core</artifactId>\n" +
    "    <version>2.8.2</version>\n" +
    "</dependency>"
const safeLog4j2 = "public R safe(String payload) {\n" +
    "    logger.error(\"User input: {}\", payload);\n" +
    "    return R.ok(msg(\"component.log4j2.result.safe\", payload));\n" +
    "}"
const safeLog4j2Zh = "public R safe(String payload) {\n" +
    "    logger.error(\"用户输入：{}\", payload);\n" +
    "    return R.ok(msg(\"component.log4j2.result.safe\", payload));\n" +
    "}"

const vulShiro = "public R getShiroKey() {\n" +
    "    try {\n" +
    "        byte[] key = new CookieRememberMeManager().getCipherKey();\n" +
    "        String encodedKey = new String(Base64.getEncoder().encode(key));\n" +
    "        return R.ok(msg(\"component.shiro.result.key\", encodedKey));\n" +
    "    } catch (Exception ignored) {\n" +
    "        return R.error(msg(\"component.shiro.result.keyFailed\"));\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.apache.shiro</groupId>\n" +
    "    <artifactId>shiro-spring</artifactId>\n" +
    "    <version>1.2.4</version>\n" +
    "</dependency>"
const vulShiroZh = "public R getShiroKey() {\n" +
    "    try {\n" +
    "        byte[] key = new CookieRememberMeManager().getCipherKey();\n" +
    "        String encodedKey = new String(Base64.getEncoder().encode(key));\n" +
    "        return R.ok(msg(\"component.shiro.result.key\", encodedKey));\n" +
    "    } catch (Exception ignored) {\n" +
    "        return R.error(msg(\"component.shiro.result.keyFailed\"));\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.apache.shiro</groupId>\n" +
    "    <artifactId>shiro-spring</artifactId>\n" +
    "    <version>1.2.4</version>\n" +
    "</dependency>"
if (typeof window !== "undefined") {
    window.componentCodeSnippets = Object.assign(window.componentCodeSnippets || {}, {
        vulFastjson,
        vulFastjsonZh,
        safeFastjson,
        safeFastjsonZh,
        vulJackson,
        vulJacksonZh,
        safeJackson,
        safeJacksonZh,
        vulXstream,
        vulXstreamZh,
        safeXstreamBlackList,
        safeXstreamBlackListZh,
        safeXstreamWhiteList,
        safeXstreamWhiteListZh,
        vulLog4j2,
        vulLog4j2Zh,
        safeLog4j2,
        safeLog4j2Zh,
        vulShiro,
        vulShiroZh
    });
}
const JdbcDeserial = "public R jdbc() {\n" +
    "    try (Connection conn = DriverManager.getConnection(url, username, password);\n" +
    "         Statement stmt = conn.createStatement()) {\n" +
    "        ResultSet rs = stmt.executeQuery(\"SELECT malicious_object FROM objects WHERE id = 1\");\n" +
    "        if (rs.next()) {\n" +
    "            byte[] bytes = rs.getBytes(\"malicious_object\");\n" +
    "            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {\n" +
    "                // Trigger the deserialization vulnerability.\n" +
    "                ois.readObject();\n" +
    "            }\n" +
    "        }\n" +
    "        return R.ok(\"MySQL JDBC deserialization vulnerability triggered.\");\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"Failed to trigger MySQL JDBC deserialization vulnerability: \" + e.getMessage());\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {\n" +
    "    in.defaultReadObject();\n" +
    "    Runtime.getRuntime().exec(command);\n" +
    "}"
const JdbcDeserialZh = "public R jdbc() {\n" +
    "    try (Connection conn = DriverManager.getConnection(url, username, password);\n" +
    "         Statement stmt = conn.createStatement()) {\n" +
    "        ResultSet rs = stmt.executeQuery(\"SELECT malicious_object FROM objects WHERE id = 1\");\n" +
    "        if (rs.next()) {\n" +
    "            byte[] bytes = rs.getBytes(\"malicious_object\");\n" +
    "            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {\n" +
    "                // 触发反序列化漏洞\n" +
    "                ois.readObject();\n" +
    "            }\n" +
    "        }\n" +
    "        return R.ok(\"触发MYSQL-JDBC反序列化漏洞！\");\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"触发MYSQL-JDBC反序列化漏洞失败：\" + e.getMessage());\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {\n" +
    "    in.defaultReadObject();\n" +
    "    Runtime.getRuntime().exec(command);\n" +
    "}"
