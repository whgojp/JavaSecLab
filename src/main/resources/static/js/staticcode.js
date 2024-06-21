/**
 * @description 存放静态代码
 * @author:  whgojp
 * @email:  whgojp@foxmail.com
 * @Date: 2024/5/19 19:03
 */
const vul1ReflectRaw = "// 原生漏洞环境,未加任何过滤，Controller接口返回Json类型结果\n" +
    "@RequestMapping(\"/a-vul1-reflect-raw\")  // 可接收各种请求类型\n" +
    "public R vul1ReflectRaw(@ApiParam(name = \"type\", value = \"请求参数\", required = true) @RequestParam String content) {\n" +
    "\n" +
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
    "public String vul1ReflectRawString(@ApiParam(name = \"type\", value = \"请求参数\", required = true) @RequestParam String content) {\n" +
    "\n" +
    "    return content;\n" +
    "}"
const vul2ReflectContentType = "// Tomcat内置HttpServletResponse，Content-Type导致反射XSS\n" +
    "public void vul2ReflectContentType(@ApiParam(name = \"type\", value = \"类型\", required = true) @RequestParam String type, @ApiParam(name = \"content\", value = \"请求参数\", required = true) @RequestParam String content, HttpServletResponse response) {\n" +
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
const safe1CheckUserInput = "// 前端校验代码\n" +
    "\n" +
    "\n" +
    "// 后端校验代码"
const safe2CSP = "// 内容安全策略（Content Security Policy）是一种由浏览器实施的安全机制，旨在减少和防范跨站脚本攻击（XSS）等安全威胁。它通过允许网站管理员定义哪些内容来源是可信任的，从而防止恶意内容的加载和执行\n" +
    "@ApiImplicitParam(name = \"content\", value = \"请求参数\", dataType = \"String\", paramType = \"query\", dataTypeClass = String.class)\n" +
    "public String safe2CSP(@ApiParam(name = \"content\", value = \"请求参数\", required = true) @RequestParam String content,HttpServletResponse response) {\n" +
    "    response.setHeader(\"Content-Security-Policy\",\"default-src self\");\n" +
    "    return content;\n" +
    "}"

const safe1EntityEscape = ""

const vul1StoreRaw = ""

const xssOther = "test"

const vul1RawJoint = "// 原生sql语句动态拼接 参数未进行任何处理\n" +
    "public R vul1RawJoint(@ApiParam(name = \"type\", value = \"操作类型\", required = true) @RequestParam String type,@ApiParam(name = \"id\", value = \"用户ID\") @RequestParam(required = false) String id,@ApiParam(name = \"username\", value = \"用户名\") @RequestParam(required = false) String username,@ApiParam(name = \"password\", value = \"密码\") @RequestParam(required = false) String password) {\n" +
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
    "            sql = \"INSERT INTO users (user, pass) VALUES ('\" + username + \"', '\" + password + \"')\"; //这里没有标识id id自增长\n" +
    "            //通过Statement对象执行SQL语句，得到ResultSet对象-查询结果集\n" +
    "            rowsAffected = stmt.executeUpdate(sql);         // 这里注意一下 insert、update、delete 语句应使用executeUpdate()\n" +
    "            //关闭ResultSet结果集 Statement对象 以及数据库Connection对象 释放资源\n" +
    "            stmt.close();\n" +
    "            conn.close();\n" +
    "            return R.ok(message);\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM users WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE users SET pass = '\" + password + \"', user = '\" + username + \"' WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = \" + id;\n" +
    "            ResultSet rs = stmt.executeQuery(sql);\n" +
    "            ...\n" +
    "        }\n" +
    "}"

const vul2prepareStatementJoint = "// 虽然使用了 conn.prepareStatement(sql) 创建了一个 PreparedStatement 对象，但在执行 stmt.executeUpdate(sql) 时，却是传递了完整的 SQL 语句作为参数，而不是使用了预编译的功能\n" +
    "public R vul2prepareStatementJoint(@ApiParam(name = \"type\", value = \"操作类型\", required = true) @RequestParam String type,@ApiParam(name = \"id\", value = \"用户ID\") @RequestParam(required = false) String id,@ApiParam(name = \"username\", value = \"用户名\") @RequestParam(required = false) String username,@ApiParam(name = \"password\", value = \"密码\") @RequestParam(required = false) String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement stmt;\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO users (user, pass) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM users WHERE id = '\" + id + \"'\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            rowsAffected = stmt.executeUpdate(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE users set pass = '\" + password + \"' where id = '\" + id + \"'\";\n" +
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
    "public R vul3JdbcTemplateJoint(@ApiParam(name = \"type\", value = \"操作类型\", required = true) @RequestParam String type,@ApiParam(name = \"id\", value = \"用户ID\") @RequestParam(required = false) String id,@ApiParam(name = \"username\", value = \"用户名\") @RequestParam(required = false) String username,@ApiParam(name = \"password\", value = \"密码\") @RequestParam(required = false) String password) {\n" +
    "    DriverManagerDataSource dataSource = new DriverManagerDataSource();\n" +
    "    dataSource.setDriverClassName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    dataSource.setUrl(dbUrl);\n" +
    "    dataSource.setUsername(dbUser);\n" +
    "    dataSource.setPassword(dbPass);\n" +
    "    JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO users (user, pass) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);        //Spring的JdbcTemplate会自动管理连接的获取和释放，不需要手动关闭连接\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM users WHERE id = '\" + id + \"'\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE users set pass = '\" + password + \"' where id = '\" + id + \"'\";\n" +
    "            rowsAffected = jdbctemplate.update(sql);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = \" + id;\n" +
    "            stringObjectMap = jdbctemplate.queryForMap(sql);\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const safe1PrepareStatementParametric = "// 采用预编译的方法，使用?占位，也叫参数化的SQL\n" +
    "public R safe1PrepareStatementParametric(@ApiParam(name = \"type\", value = \"操作类型\", required = true) @RequestParam String type,@ApiParam(name = \"id\", value = \"用户ID\") @RequestParam(required = false) String id,@ApiParam(name = \"username\", value = \"用户名\") @RequestParam(required = false) String username,@ApiParam(name = \"password\", value = \"密码\") @RequestParam(required = false) String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement stmt;\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO users (user, pass) VALUES (?, ?)\"; // 这里可以看到使用了?占位符 sql语句和参数进行分离\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, username); // 参数化处理\n" +
    "            stmt.setString(2, password);\n" +
    "            rowsAffected = stmt.executeUpdate(); // 使用预编译时 不需要传递sql语句\n" +
    "\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM users WHERE id = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, id);\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE users set pass = ? where id = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, password);\n" +
    "            stmt.setString(2, id);\n" +
    "            rowsAffected = stmt.executeUpdate();\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = ?\";\n" +
    "            stmt = conn.prepareStatement(sql);\n" +
    "            stmt.setString(1, id);\n" +
    "            ResultSet rs = stmt.executeQuery();\n" +
    "            ...\n" +
    "   }\n" +
    "}"
const safe2JdbcTemplatePrepareStatementParametric = "// JDBCTemplate预编译 此时在常规DML场景有效的防止了SQL注入攻击的发生\n" +
    "public R safe2JdbcTemplatePrepareStatementParametric(@ApiParam(name = \"type\", value = \"操作类型\", required = true) @RequestParam String type,@ApiParam(name = \"id\", value = \"用户ID\") @RequestParam(required = false) String id,@ApiParam(name = \"username\", value = \"用户名\") @RequestParam(required = false) String username,@ApiParam(name = \"password\", value = \"密码\") @RequestParam(required = false) String password) {\n" +
    "    DriverManagerDataSource dataSource = new DriverManagerDataSource();\n" +
    "    dataSource.setDriverClassName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    dataSource.setUrl(dbUrl);\n" +
    "    dataSource.setUsername(dbUser);\n" +
    "    dataSource.setPassword(dbPass);\n" +
    "    JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            sql = \"INSERT INTO users (user, pass) VALUES (?,?)\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, username, password);\n" +
    "            ...\n" +
    "        case \"delete\":\n" +
    "            sql = \"DELETE FROM users WHERE id = ?\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, id);\n" +
    "            ...\n" +
    "        case \"update\":\n" +
    "            sql = \"UPDATE users set pass = ? where id = ?\";\n" +
    "            rowsAffected = jdbctemplate.update(sql, username, id);\n" +
    "            ...\n" +
    "        case \"select\":\n" +
    "            sql = \"SELECT * FROM users WHERE id  = ?\";\n" +
    "            stringObjectMap = jdbctemplate.queryForMap(sql, id);\n" +
    "            ...\n" +
    "    }\n" +
    "}"
const safe3BlacklistcheckSqlBlackList = "// 检测用户输入是否存在敏感字符：'、;、--、+、,、%、=、>、<、*、(、)、and、or、exeinsert、select、delete、update、count、drop、chr、midmaster、truncate、char、declare\n" +
    "public R safe3BlacklistcheckSqlBlackList(@ApiParam(name = \"type\", value = \"操作类型\", required = true) @RequestParam String type,\n" +
    "    @ApiParam(name = \"id\", value = \"用户ID\") @RequestParam(required = false) String id,@ApiParam(name = \"username\", value = \"用户名\") @RequestParam(required = false) String username,@ApiParam(name = \"password\", value = \"密码\") @RequestParam(required = false) String password) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    switch (type) {\n" +
    "        case \"add\":\n" +
    "            if (checkUserInput.checkSqlBlackList(username) || checkUserInput.checkSqlBlackList(password)) {\n" +
    "                return R.error(\"黑名单检测到非法SQL注入!\");\n" +
    "            } else {\n" +
    "                sql = \"INSERT INTO users (user, pass) VALUES ('\" + username + \"', '\" + password + \"')\";\n" +
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
    "                sql = \"UPDATE users SET pass = '\" + password + \"', user = '\" + username + \"' WHERE id = '\" + id + \"'\";\n" +
    "                log.info(\"当前执行数据更新操作:\" + sql);\n" +
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
    "}"
const safe4RequestRarameterValidate = "// 强制类型转换 对用户请求参数进行校验\n" +
    "public R safe4RequestRarameterValidate(@ApiParam(name = \"id\", value = \"用户ID\") @RequestParam(required = false) Integer id) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    message = checkUserInput.checkUser(id);\n" +
    "    if (!message.isEmpty()) return R.error(message);\n" +
    "    sql = \"SELECT * FROM users WHERE id  = \" + id;\n" +
    "    log.info(\"当前执行数据查询操作:\" + sql);\n" +
    "    ResultSet rs = stmt.executeQuery(sql);\n" +
    "    ...\n" +
    "}"
const safe4EASAPIFilter = "// ESAPI提供了多种输入验证API，提供对XSS攻击和SQL注入攻击等的防护\n" +
    "public R safe4EASAPIFilter(@ApiParam(name = \"id\", value = \"用户ID\") @RequestParam(required = false) String id) {\n" +
    "    Codec<Character> oracleCodec = new OracleCodec();\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "\n" +
    "    Statement stmt = conn.createStatement();\n" +
    "    // 使用了 Oracle 的编解码器 OracleCodec 和 ESAPI 库来对 ID 进行编码，以防止 SQL 注入攻击。\n" +
    "//            String sql = \"select * from users where id = '\" + ESAPI.encoder().encodeForSQL(oracleCodec, id) + \"'\";\n" +
    "    String sql = \"select * from users where id = '\" + id + \"'\";\n" +
    "    log.info(\"当前执行数据查询操作:\" + sql);\n" +
    "    ResultSet rs = stmt.executeQuery(sql);\n" +
    "   \n" +
    "}"
const special1OrderBy = "// ORDER BY关键字用于按升序或降序对结果集进行排序。 由于order by后面需要紧跟column_name，而预编译是参数化字符串，而order by后面紧跟字符串就会不支持原有功能 使用默认排序，因此通常防御order by注入需要使用白名单的方式\n" +
    "public R special1OrderBy(@ApiParam(name = \"type\", value = \"操作类型\", required = true) @RequestParam String type,@ApiParam(name = \"field\", value = \"字段名\") @RequestParam(required = false) String field) {\n" +
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
    "            preparedStatement.setString(1, field);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "        case \"writeList\":\n" +
    "            sql = \"SELECT * FROM users ORDER BY \" + field;\n" +
    "            if (checkUserInput.chechSqlWhiteList(field)) {\n" +
    "                return R.error(\"field字段不合法！\");\n" +
    "            }\n" +
    "            log.info(\"当前执行数据排序操作：\" + sql + \" 参数：\" + field);\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "   }\n" +
    "}"
const special2Like = "// \n" +
    "public R special2Like(@ApiParam(name = \"type\", value = \"操作类型\", required = true) @RequestParam String type,@ApiParam(name = \"keyword\", value = \"关键词\") @RequestParam(required = false) String keyword) {\n" +
    "    Class.forName(\"com.mysql.cj.jdbc.Driver\");\n" +
    "    Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);\n" +
    "    PreparedStatement preparedStatement;\n" +
    "    switch (type) {\n" +
    "        case \"inside\":\n" +
    "            sql = \"SELECT * FROM users WHERE user LIKE '%?%'\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setString(1, keyword);\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "        case \"outside\":\n" +
    "            sql = \"SELECT * FROM users WHERE user LIKE ?\";\n" +
    "            preparedStatement = conn.prepareStatement(sql);\n" +
    "            preparedStatement.setString(1, \"%\"+keyword+\"%\");\n" +
    "            rs = preparedStatement.executeQuery();\n" +
    "            ...\n" +
    "    }\n" +
    "}"
