# SpringSecurity

## 1.概要

Spring 是非常流行和成功的 Java 应用开发框架，Spring Security 正是 Spring 家族中的成员。Spring Security 基于 Spring 框架，提供了一套 Web 应用安全性的完整解决方案。

正如你可能知道的关于安全方面的两个主要区域是“**认证**”和“**授权**”（或者访问控制），一般来说，Web 应用的安全性包括**用户认证（Authentication）和用户授权(Authorization）**两个部分，这两点也是 Spring Security 重要核心功

**（1）** 用户认证指的是：验证某个用户是否为系统中的合法主体，也就是说用户能否访问该系统。用户认证一般要求用户提供用户名和密码。系统通过校验用户名和密码来完成认证过程。**通俗点说就是系统认为用户是否能登录**

**（2）** 用户授权指的是验证某个用户是否有权限执行某个操作。在一个系统中，不同用户所具有的权限是不同的。比如对一个文件来说，有的用户只能进行读取，而有的用户可以进行修改。一般来说，系统会为不同的用户分配不同的角色，而每个角色则对应一系列的权限。**通俗点讲就是系统判断用户是否有权限去做某些事情。**

**特点:**

- 和 Spring 无缝整合。
- 全面的权限控制。
- 专门为Web 开发而设计。
  - 旧版本不能脱离Web 环境使用。
- 新版本对整个框架进行了分层抽取，分成了核心模块和Web 模块。单独引入核心模块就可以脱离Web 环境。
- 重量级。

## 2.新建项目

![image-20230328202136028](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282021097.png)

![image-20230328203541974](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282035009.png)

编写测试类:

```java
@RestController
@RequestMapping("/test")
public class TestController {
    @GetMapping("hello")
    public String add() {
        return "hello Security";
    }
}
```

修改端口号:避免冲突

![image-20230328203850705](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282038731.png)

访问地址信息出现登录说明起作用了:

![image-20230328204109673](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282041730.png)

账户为:user  :key:为

![image-20230328204304514](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282043567.png)

![image-20230328205351783](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282053815.png)

表示请求成功但是我们没有这个控制器，但是可以访问了

## 3.基本原理

SpringSecurity本质是一个过滤器链：也就是有很多的过滤器

### 3.1 FilterSecurityInterceptor

是一个方法级的权限过滤器, 基本位于过滤链的最底部。

![image-20230328210110108](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282101181.png)

`super.beforeInvocation(filterInvocation) `表示查看之前的`filter`是否通过。

`filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());`表示真正的调用后台的服务。

- `ExceptionTranslationFilter`：是个异常过滤器，用来处理在认证授权过程中抛出的异常

```java
//判断异常类型并抛出异常做处理  
private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            chain.doFilter(request, response);
        } catch (IOException var7) {
            throw var7;
        } catch (Exception var8) {
            Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(var8);
            RuntimeException securityException = (AuthenticationException)this.throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);
            if (securityException == null) {
                securityException = (AccessDeniedException)this.throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
            }

            if (securityException == null) {
                this.rethrow(var8);
            }

            if (response.isCommitted()) {
                throw new ServletException("Unable to handle the Spring Security Exception because the response is already committed.", var8);
            }

            this.handleSpringSecurityException(request, response, chain, (RuntimeException)securityException);
        }

    }
```

- `UsernamePasswordAuthenticationFilter `：对/login 的 POST 请求做拦截，校验表单中用户名，密码。

![image-20230328211124782](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282111861.png)

### 3.2 过滤器是如何进行加载的？

![](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282122630.png)

首先配置过滤器，接着执行doFilter方法初始化**Delegate**，这个是WebApplicationContext 中根据Bean的名字进行匹配得到的过滤器，然后执行将相关的过滤操作送入过滤链中进行执行.

**我们来详细的看看过滤器的信息:**

![image-20230329125524836](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303291255985.png)

主要的过滤器有三个也就是上面讲解的三个，其余的可以看着继承接口进行修改。

### 3.3 UserDetailsService接口讲解

![img](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282125517.png)

当什么也没有配置的时候，账号和密码是由`Spring Security`定义生成的。而在实际项目中账号和密码都是从数据库中查询出来的。 所以我们要通过自定义逻辑控制认证逻辑。

如果需要自定义逻辑时，只需要实现 UserDetailsService 接口即可.

![img](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282126710.png)

**返回值 UserDetails** 这个类是系统默认的用户“**主体**”

```java
// 表示获取登录用户所有权限
Collection<? extends GrantedAuthority> getAuthorities();

// 表示获取密码
String getPassword();

// 表示获取用户名
String getUsername();

// 表示判断账户是否过期
boolean isAccountNonExpired();

// 表示判断账户是否被锁定
boolean isAccountNonLocked();

// 表示凭证{密码}是否过期
boolean isCredentialsNonExpired();

// 表示当前用户是否可用
boolean isEnabled();
```

以下是 `UserDetails `实现类:

![image-20230328213011831](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282130881.png)

- 方法参数`username`

表示用户名。此值是客户端表单传递过来的数据。默认情况下必须叫 username，否则无法接收。

### 3.4 PasswordEncode 接口详解

```java
// 表示把参数按照特定的解析规则进行解析
String encode(CharSequence rawPassword);

// 表示验证从存储中获取的编码密码与编码后提交的原始密码是否匹配。如果密码匹配，则返回 true；如果不匹配，则返回 false。第一个参数表示需要被解析的密码。第二个参数表示存储的密码。
boolean matches(CharSequence rawPassword, String encodedPassword);

// 表示如果解析的密码能够再次进行解析且达到更安全的结果则返回 true，否则返回false。默认返回 false。
default boolean upgradeEncoding(String encodedPassword) {
return false;
}
```

接口实现类

![img](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282131951.png)

`BCryptPasswordEncoder` 是 `Spring Security` 官方推荐的密码解析器，平时多使用这个解析器。

`BCryptPasswordEncoder` 是对bcrypt 强散列方法的具体实现。是基于 Hash 算法实现的单向加密。可以通过 strength 控制加密强度，默认 10.

**查用方法演示**

```java
@Test
public void test01(){
  // 创建密码解析器 
  BCryptPasswordEncoder  bCryptPasswordEncoder = new BCryptPasswordEncoder();
  // 对密码进行加密
  String atguigu = bCryptPasswordEncoder.encode("atguigu");
  // 打印加密之后的数据
  System.out.println("加密之后数据：\t"+atguigu);
  //判断原字符加密后和加密之前是否匹配
  boolean result = bCryptPasswordEncoder.matches("atguigu", atguigu);
  // 打印比较结果
  System.out.println("比较结果：\t"+result);
}
```

## 4.SpringSecurityWeb权限方案

### 4.1 设置登录系统的账号密码;

![image-20230328213937178](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202303282139212.png)

**方式二：**编写类的实现接口

### 4.2 登录认证校验流程

![img](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304031908170.png)

这里的使用 **用户名/用户id生成的jwt**为了保证安全行，不利用id进行生成而是利用 前缀+随机时间生成的token

#### 4.2.1 springSecurity的完整流程图

![img](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304031912605.png)

如后的实现流程均基于当前的过滤链进行实现。

#### 4.2.2 认证流程图详解

![img](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304031914071.png)

- Authentication接口: 它的实现类，表示当前访问系统的用户，封装了用户相关信息。
- AuthenticationManager接口：定义了认证Authentication的方法
- UserDetailsService接口：加载用户特定数据的核心接口。里面定义了一个根据用户名查询用户信息的方法。
- UserDetails接口：提供核心用户信息。通过UserDetailsService根据用户名获取处理的用户信息要封装成UserDetails对象返回。然后将这些信息封装到Authentication对象中。

**首先实现登录以及校验注销功能:**

1. 自定义接口登录
   - 创建`UsernamePasswordAuthenticationToken`
   - 认证并保存认证信息
   - 自定义生成token
   - 放入缓存将结果返回前端

**首先需要准备导入的工具类:**

见代码仓库中的: 

**AcessToken.class** :用于设置登录的token信息

**配置类：**

**RedisConfig.class**、**SecurityConfig.class**

**实体类:**

LoginUser:他需要继承UserDetails类

ResponseResult：结果统一回复类

User

**provider类：**

用于生成JwtToken :头部+负载信息+签名

**工具类:**

```java
FastJsonRedisSerializer.class //用于Redis使用FastJson序列化
RedisCache.class  //用于redis缓存的工具类
WebUtils.class //将字符串渲染到客户端工具类
```

首先我们定义一个LoginController类来进行登录的认证流程

```java
@RestController
public class LoginController {
    @Autowired
    private UserLoginService userLoginService;
    @PostMapping("/user/login")
    public ResponseResult loginUser(@RequestBody User user){
        return  userLoginService.login(user);
    }
}
```

进而编写它的`UserLoginService`接口以及`UserLoginServiceImpl`实现接口类

基本的流程就是：

- 首先创建一个`UsernamePasswordAuthenticationToken`对象这是内部已经封装好的类，我们利用当前登录用户的账户和密码进行初始化
- 接着到了认证的阶段，需要调用``AuthenticationManager`这个类进行相关的认证得到Authentication对象使用这个实现类来把用户的账号密码封装成这个类型的参数
- 保存认证的信息需要调用``SecurityContextHolder`的`getContext().setAuthentication(authenticate);`传入上面得到的Authentication对象
- 接着进行Token的生成可以利用JwtProvider类的creatToken方法传入的参数为一个UserDetails对象可以使用authenticate.getPrincipal()进行强转得到
- 接着可以将authenticate.getPrincipal()强转为LoginUser对象，并且将转后的对象相关的信息存入缓存中
- 最后将生成的token和对应的请求头封装到map中便于前端进行接收相应

```java
@Slf4j
@Service
public class UserLoginServiceImpl implements UserLoginService {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    private RedisCache redisCache;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private JwtProperties jwtProperties;

    @Override
    public ResponseResult login(User user) {
        log.debug("进入login方法");
        //1.创建UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken usernameAuthentication = new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
        //2.认证
        //authenticationManager接口调用authenticate方法，方法返回的是Authentication对象，需要Authentication类型的参数。
        //Authentication是接口，使用这个接口的实现类来把用户的账号密码封装成这个类型的参数。
        //供authenticationManager接口的authenticate方法调用
        Authentication authenticate = authenticationManager.authenticate(usernameAuthentication);
        //如果查询不到用户，就抛出异常
        if (Objects.isNull(authenticate)) {
            throw new RuntimeException("登录失败!");
        }
        //保存认证信息
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        //自定义生成token
        AccessToken accessToken = jwtProvider.createToken((UserDetails) authenticate.getPrincipal());

        //把authenticate对象强转为LoginUser对象
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        redisCache.setCacheObject("login", loginUser);
        //把token响应给前端
        Map<String, String> map = new HashMap<>();
        map.put(jwtProperties.getRequestHeader(), accessToken.getToken());
        return new ResponseResult(200, "登入成功", map);
    }
}

```

当实现了这一步离成功又进了一步,接下来我们需要定义一个过滤链也就是编写一个`JwtAuthenticationTokenFilter`他继承`OncePerRequestFilter`类直接实现相应的接口，这个过滤器的意义是当我们进行接口调用时 先查询缓存中是否已经有登录用户的token而且token未过期有的话直接进行放行，反之就不让其进行查询。

基本流程:

```java
1.先拿到Authorization请求头部信息
2.去掉token的前缀拿到真是的token(因为前面生成token时加了前缀)
3.接着拿到token里面的登录用户账号名称
4.从redis中查询相关的登录缓存 (这里定义的key为login)
5.拿到用户的信息验证用户的信息与token
6.上一步成功的话组装authentication对象，构造参数是Principal Credentials 与 Authorities后面的拦截器里面会用到 grantedAuthorities 方法
7.最后将authentication信息放入到上下文对象中
```

代码实现

```java
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private JwtProperties jwtProperties;
    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JWT过滤器通过校验请求头token进行自动登录...");
        //先拿到Authorization请求头部信息
        String authToken = jwtProvider.getToken(request);
        // 判断一下内容是否为空
        if (!StringUtil.isNullOrEmpty(authToken) && authToken.startsWith(jwtProperties.getTokenPrefix())) {
            //去掉token的前缀拿到真是的token
            authToken = authToken.substring(jwtProperties.getTokenPrefix().length());
            //接着拿到token里面的登录账号
            String loginAccount = jwtProvider.getSubjectFromToken(authToken);
            if (!StringUtil.isNullOrEmpty(loginAccount) && SecurityContextHolder.getContext().getAuthentication() == null) {
                //查询用户
                LoginUser loginUser = redisCache.getCacheObject("login");
                //拿到用户的信息验证用户的信息与token
                if (jwtProvider.validateToken(authToken, loginUser)) {
                    // 组装authentication对象，构造参数是Principal Credentials 与 Authorities
                    // 后面的拦截器里面会用到 grantedAuthorities 方法
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(loginUser, loginUser.getPassword(), loginUser.getAuthorities());
                    // 将authentication信息放入到上下文对象中
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.info("JWT过滤器通过校验请求头token自动登录成功, user : {}", loginUser.getUsername());
                } else {
                    log.info("缓存已经删除或者缓存已过期!");
                }
            }

        } else {
            log.info("token为空或者token格式不正确");
        }
        //如果为空直接放行
        filterChain.doFilter(request, response);
    }
}
```

接着我们需要打开过滤的开关，需要在SecurityConfig进行配置

![image-20230403201429104](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032014181.png)

开始进行测试启动项目:

因为数据库存的信息为 userName:张三  password:1234 所以首先我们进行登录打开postman

![image-20230403201654389](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032016454.png)

接着我们可以看到postman给出的详细的信息:

![image-20230403201829552](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032018604.png)

我们去查询一下后台的日志信息:

![image-20230403201913367](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032019408.png)

说明这个在登录之前走了过滤器:smile: 但是当前我们还没有输入token，token时刚刚生成的

接着我们进行token的验证登录:因为我们拿到了token这就好办了测试另一个接口这次直接调用hello接口 预测能返回hello security

![image-20230403202443016](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032024082.png)

返回结果:

![image-20230403202525967](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032025012.png)

我们在看看后台的控制台打印的信息

![image-20230403202615261](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032026302.png)

说明调用过滤器成功可以通过token进行请求接口:

**注销接口的实现:**

LoginController添加

```java
  @RequestMapping("/user/logout")
    public ResponseResult logoutUser(){
        return userLoginService.logOut();
    }
```

编写相关的service代码和impl代码

这个实现很简单只需要得到当前登录用户的信息直接从redis中删除，这里其实是有问题的因为我们的redisCache内存中存的信息都是定死的所以为了更好的实现动态的效果可以将在loginUser中封装一个随机生成的信息进行验证比如可以使用它的**唯一性**的账户进行不唯一建议不要使用

```java
 @Override
    public ResponseResult logOut() {
        //直接去缓存中删除对应的缓存信息就可以了
        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        redisCache.deleteObject("login");
        return new ResponseResult(200,"注销成功");
    }
```

进行测试:

![image-20230403203451446](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032034514.png)

结果如图：

![image-20230403203516274](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032035310.png)

然后我们在拿着token去访问hello接口看看效果:

![image-20230403203652084](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032036154.png)

接着看看控制台的信息:

![image-20230403203715344](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304032037385.png)

注销完成!！

## 5.SpringSecurity授权实现

### 5.1 权限系统的作用

**不同的用户可以使用不同的功能**。这就是权限系统要去实现的效果,不能只依赖前端去判断用户的权限来选择显示哪些菜单哪些按钮。因为如果只是这样，如果有人知道了对应功能的接口地址就可以不通过前端，直接去发送请求来实现相关功能操作。

 所以我们还需要在后台进行用户权限的判断，判断当前用户是否有相应的权限，必须具有所需权限才能进行相应的操作。

### 5.2 授权的基本流程

在SpringSecurity中，会使用默认的FilterSecurityInterceptor来进行权限校验。在FilterSecurityInterceptor中会从SecurityContextHolder获取其中的Authentication，然后获取其中的权限信息。当前用户是否拥有访问当前资源所需的权限。

所以我们在项目中只需要把当前登录用户的权限信息也存入Authentication。 然后设置我们的资源所需要的权限即可。

### 5.3 授权的实现

**1.开启注解在启动类上:**

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
```

**2.在对应的方法上添加注解@PreAuthorize**

```java
@RestController
public class HelloController {
    @RequestMapping("/hello")
    @PreAuthorize("hasAuthority('system:dept:list')")
    public String hello() {
        return "hello Security";
    }

}
```

**3.封装权限信息**

**首先是数据库表的设计RBAC权限模型:**

![img](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042153345.png)

需要五张表下面是相关的建表语句:

```sql

CREATE DATABASE /*!32312 IF NOT EXISTS*/`my_security` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;

USE `my_security`;

/*Table structure for table `sys_menu` */

DROP TABLE IF EXISTS `sys_menu`;

CREATE TABLE `sys_menu` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `menu_name` varchar(64) NOT NULL DEFAULT 'NULL' COMMENT '菜单名',
  `path` varchar(200) DEFAULT NULL COMMENT '路由地址',
  `component` varchar(255) DEFAULT NULL COMMENT '组件路径',
  `visible` char(1) DEFAULT '0' COMMENT '菜单状态（0显示 1隐藏）',
  `status` char(1) DEFAULT '0' COMMENT '菜单状态（0正常 1停用）',
  `perms` varchar(100) DEFAULT NULL COMMENT '权限标识',
  `icon` varchar(100) DEFAULT '#' COMMENT '菜单图标',
  `create_by` bigint(20) DEFAULT NULL,
  `create_time` datetime DEFAULT NULL,
  `update_by` bigint(20) DEFAULT NULL,
  `update_time` datetime DEFAULT NULL,
  `del_flag` int(11) DEFAULT '0' COMMENT '是否删除（0未删除 1已删除）',
  `remark` varchar(500) DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COMMENT='菜单表';

/*Table structure for table `sys_role` */

DROP TABLE IF EXISTS `sys_role`;

CREATE TABLE `sys_role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) DEFAULT NULL,
  `role_key` varchar(100) DEFAULT NULL COMMENT '角色权限字符串',
  `status` char(1) DEFAULT '0' COMMENT '角色状态（0正常 1停用）',
  `del_flag` int(1) DEFAULT '0' COMMENT 'del_flag',
  `create_by` bigint(200) DEFAULT NULL,
  `create_time` datetime DEFAULT NULL,
  `update_by` bigint(200) DEFAULT NULL,
  `update_time` datetime DEFAULT NULL,
  `remark` varchar(500) DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COMMENT='角色表';

/*Table structure for table `sys_role_menu` */

DROP TABLE IF EXISTS `sys_role_menu`;

CREATE TABLE `sys_role_menu` (
  `role_id` bigint(200) NOT NULL AUTO_INCREMENT COMMENT '角色ID',
  `menu_id` bigint(200) NOT NULL DEFAULT '0' COMMENT '菜单id',
  PRIMARY KEY (`role_id`,`menu_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

/*Table structure for table `sys_user` */

DROP TABLE IF EXISTS `sys_user`;

CREATE TABLE `sys_user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键',
  `user_name` varchar(64) NOT NULL DEFAULT 'NULL' COMMENT '用户名',
  `nick_name` varchar(64) NOT NULL DEFAULT 'NULL' COMMENT '昵称',
  `password` varchar(64) NOT NULL DEFAULT 'NULL' COMMENT '密码',
  `status` char(1) DEFAULT '0' COMMENT '账号状态（0正常 1停用）',
  `email` varchar(64) DEFAULT NULL COMMENT '邮箱',
  `phonenumber` varchar(32) DEFAULT NULL COMMENT '手机号',
  `sex` char(1) DEFAULT NULL COMMENT '用户性别（0男，1女，2未知）',
  `avatar` varchar(128) DEFAULT NULL COMMENT '头像',
  `user_type` char(1) NOT NULL DEFAULT '1' COMMENT '用户类型（0管理员，1普通用户）',
  `create_by` bigint(20) DEFAULT NULL COMMENT '创建人的用户id',
  `create_time` datetime DEFAULT NULL COMMENT '创建时间',
  `update_by` bigint(20) DEFAULT NULL COMMENT '更新人',
  `update_time` datetime DEFAULT NULL COMMENT '更新时间',
  `del_flag` int(11) DEFAULT '0' COMMENT '删除标志（0代表未删除，1代表已删除）',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COMMENT='用户表';

/*Table structure for table `sys_user_role` */

DROP TABLE IF EXISTS `sys_user_role`;

CREATE TABLE `sys_user_role` (
  `user_id` bigint(200) NOT NULL AUTO_INCREMENT COMMENT '用户id',
  `role_id` bigint(200) NOT NULL DEFAULT '0' COMMENT '角色id',
  PRIMARY KEY (`user_id`,`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

为了得到相应的权限我们需要编写SQL语句得到 perms的结果也就是表连接这里提供结果

```sql
SELECT 
	DISTINCT m.`perms`
FROM
	sys_user_role ur
	LEFT JOIN `sys_role` r ON ur.`role_id` = r.`id`
	LEFT JOIN `sys_role_menu` rm ON ur.`role_id` = rm.`role_id`
	LEFT JOIN `sys_menu` m ON m.`id` = rm.`menu_id`
WHERE
	user_id = 2
	AND r.`status` = 0
	AND m.`status` = 0
```

![image-20230404215557142](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042155189.png)

这里面的数据是我提前存入的你也可以手动的添加:smirk:

![image-20230404215825331](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042158383.png)



![image-20230404215848438](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042158489.png)



![image-20230404215909965](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042159019.png)



![image-20230404215946261](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042159314.png)

密码的生成看测试类中的代码:

```java
   @Test
    void passwordEncoder() {
        BCryptPasswordEncoder passwordEncoder=new BCryptPasswordEncoder();
        //加密的方法
        String encode = passwordEncoder.encode("1234");
        String encode1 = passwordEncoder.encode("1234");
        UpdateWrapper<User> updateWrapper=new UpdateWrapper<>();
        updateWrapper.eq("id",2).set("password",encode1);

        userMapper.update(null,updateWrapper);
        System.out.println(passwordEncoder.matches("1234",encode1));
    }
```

![image-20230404220041457](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042200506.png)



**接着需要导入一个菜单表的实体类:见仓库Menu.class**

一切准备就绪开始进行实现，编写相关的MenuMapper类以及MenuMapper.xml类实现上述的SQL语句然后回归代码



在UserDetailsServiceImpl中有一个继承实现权限的函数需要进行修改定义,在代码里也就是那个LoginUser类中的`getAuthorities()`

![image-20230404214859491](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042149592.png)

![image-20230404214917513](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042149574.png)

```java
  //存储权限信息
    private List<String> permissions;
    //存储SpringSecurity所需要的权限信息的集合
    @JSONField(serialize = false)
    private List<GrantedAuthority> authorities;

    public LoginUser(User user, List<String> permissions) {
        this.user = user;
        this.permissions = permissions;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (authorities != null) {
            return authorities;
        }
        //把permissions中字符串类型的权限信息转换成GrantedAuthority对象存入authorities中
        authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return authorities;
    }
```



当我们修改**完成LoginUser后**就可以去UserDetailsServiceImpl中去把权限信息封装到LoginUser中了，代码实现:

![image-20230404220519246](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304042205314.png)

直接调用进行查询即可；结果我就不粘贴了:smirk:

## 6.自定义失败处理

### 6.1 加入两个实现类

我们还希望在认证失败或者是授权失败的情况下也能和我们的接口一样返回相同结构的json，这样可以让前端能对响应进行统一的处理。要实现这个功能我们需要知道SpringSecurity的异常处理机制。

 在SpringSecurity中，如果我们在认证或者授权的过程中出现了异常会被ExceptionTranslationFilter捕获到。在ExceptionTranslationFilter中会去判断是认证失败还是授权失败出现的异常。

 如果是认证过程中出现的异常会被封装成AuthenticationException然后调用**AuthenticationEntryPoint**对象的方法去进行异常处理。

 如果是授权过程中出现的异常会被封装成AccessDeniedException然后调用**AccessDeniedHandler**对象的方法去进行异常处理。

 所以如果我们需要自定义异常处理，我们只需要自定义AuthenticationEntryPoint和AccessDeniedHandler然后配置给SpringSecurity即可。

```java
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ResponseResult result = new ResponseResult(HttpStatus.FORBIDDEN.value(), "权限不足");
        String json = JSON.toJSONString(result);
        WebUtils.renderString(response,json);

    }
}
```

```java
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ResponseResult result = new ResponseResult(HttpStatus.UNAUTHORIZED.value(), "认证失败请重新登录");
        String json = JSON.toJSONString(result);
        WebUtils.renderString(response,json);
    }
}
```

接着配置SpringSecurity

```java
   @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;
```

 然后我们可以使用HttpSecurity对象的方法去配置。

```java
   http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint).
                accessDeniedHandler(accessDeniedHandler);
```

## 7.跨域解决

浏览器出于安全的考虑，使用 XMLHttpRequest对象发起 HTTP请求时必须遵守同源策略，否则就是跨域的HTTP请求，默认情况下是被禁止的。 同源策略要求源相同才能正常进行通信，即协议、域名、端口号都完全一致。

 前后端分离项目，前端项目和后端项目一般都不是同源的，所以肯定会存在跨域请求的问题。

 所以我们就要处理一下，让前端能进行跨域请求。

```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
      // 设置允许跨域的路径
        registry.addMapping("/**")
                // 设置允许跨域请求的域名
                .allowedOriginPatterns("*")
                // 是否允许cookie
                .allowCredentials(true)
                // 设置允许的请求方式
                .allowedMethods("GET", "POST", "DELETE", "PUT")
                // 设置允许的header属性
                .allowedHeaders("*")
                // 跨域允许时间
                .maxAge(3600);
    }
}
```

开启SpringSecurity的跨域访问

```java
 @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口 允许匿名访问
                .antMatchers("/user/login").anonymous()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();

        //添加过滤器
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

        //配置异常处理器
        http.exceptionHandling()
                //配置认证失败处理器
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);

        //允许跨域
        http.cors();   //!!!!!!!!!!!!!!!!!!这个这个
    }
```

## 8.其他权限校验方法

除了@PreAuthorize注解，还可以使用hasAuthority方法进行校验,例如：hasAnyAuthority，hasRole，hasAnyRole等。

就拿hashAuthority进行讲解,它实际是执行了SecurityExpressionRoot的hasAuthority方法，它可以传入多个权限例如:

```java
    @PreAuthorize("hasAnyAuthority('admin','test','system:dept:list')")
    public String hello(){
        return "hello";
    }
```

而hasRole要求有对应的角色才能访问，它内部会把我们传入的参数拼接上 **ROLE_** 后再去比较。所以这种情况下需要用户对应的权限上也有ROLE_这个前缀才行;

### 8.1.自定义权限校验方法

@PreAuthorize注解中使用我们的方法，需要自己定义一个类.并且注入到容器中，带上标识符:

```java
@Component("ex")  //自定义标识符
public class SGExpressionRoot {

    public boolean hasAuthority(String authority){
        //获取当前用户的权限
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        List<String> permissions = loginUser.getPermissions();
        //判断用户权限集合中是否存在authority
        return permissions.contains(authority);
    }
}
```

接着在SPLE表达式中用@ex来获取容器中的bean名字ex对象，然后再调用这个hasAuthority方法:

```java
    @RequestMapping("/hello")
    @PreAuthorize("@ex.hasAuthority('system:dept:list')")
    public String hello(){
        return "hello";
    }
```

**基于配置的方法：**

![image-20230405105836965](https://joker-qaq1-1314468534.cos.ap-beijing.myqcloud.com/learn/202304051058121.png)

