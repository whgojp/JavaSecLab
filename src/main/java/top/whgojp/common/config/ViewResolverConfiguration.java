//package top.whgojp.common.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.ComponentScan;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.servlet.ViewResolver;
//import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
//import org.springframework.web.servlet.config.annotation.EnableWebMvc;
//import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//import org.springframework.web.servlet.view.InternalResourceViewResolver;
//import org.thymeleaf.spring5.SpringTemplateEngine;
//import org.thymeleaf.spring5.templateresolver.SpringResourceTemplateResolver;
//import org.thymeleaf.spring5.view.ThymeleafViewResolver;
//import org.thymeleaf.templatemode.TemplateMode;
//import top.whgojp.common.constant.SysConstant;
//
//@Configuration
//@EnableWebMvc
//@ComponentScan("top.whgojp.modules") // 扫描控制器组件
//public class ViewResolverConfiguration implements WebMvcConfigurer {
//
//    @Autowired
//    private SysConstant sysConstant;
//
//    @Override
//    public void addResourceHandlers(ResourceHandlerRegistry registry) {
//        String uploadFolderPath = sysConstant.getUploadFolder();
//        registry.addResourceHandler("/file/**")
//                .addResourceLocations("file:" + uploadFolderPath + "/");
//        registry.addResourceHandler("/static/**")
//                .addResourceLocations("classpath:/static/");
//    }
//
//    // Thymeleaf视图解析器
//    @Bean
//    public ViewResolver thymeleafViewResolver() {
//        ThymeleafViewResolver resolver = new ThymeleafViewResolver();
//        resolver.setTemplateEngine(templateEngine());
//        resolver.setCharacterEncoding("UTF-8");
//        resolver.setOrder(1); // 优先级较高
//        return resolver;
//    }
//
//    // JSP视图解析器
//    @Bean
//    public ViewResolver jspViewResolver() {
//        InternalResourceViewResolver resolver = new InternalResourceViewResolver();
//        resolver.setPrefix("/WEB-INF/");
//        resolver.setSuffix(".jsp");
//        resolver.setViewNames("jsp/*"); // 只有在视图名称以"jsp/"开头时才使用JSP解析器
//        resolver.setOrder(2); // 优先级较低
//        return resolver;
//    }
//
//
//
//    @Bean
//    public SpringResourceTemplateResolver templateResolver() {
//        SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
//        templateResolver.setPrefix("classpath:/templates/");
//        templateResolver.setSuffix(".html");
//        templateResolver.setTemplateMode(TemplateMode.HTML);
//        templateResolver.setCharacterEncoding("UTF-8");
//        return templateResolver;
//    }
//
//    @Bean
//    public SpringTemplateEngine templateEngine() {
//        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
//        templateEngine.setTemplateResolver(templateResolver());
//        return templateEngine;
//    }
//
//    @Override
//    public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
//        configurer.enable("default");
//    }
//}
