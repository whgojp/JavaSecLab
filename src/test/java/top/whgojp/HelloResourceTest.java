package top.whgojp;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.context.WebApplicationContext;
import top.whgojp.modules.system.entity.AuthenticationRequest;

import java.nio.charset.StandardCharsets;

// SpringBootTest 注解默认使用 webEnvironment = WebEnvironment.MOCK，它是不会对 Filter、Servlet进行初始化的。
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
// 这个注解可以用来自动注入 mockMvc，这里一定要使用这个注解来注入，不然默认的那种写法是没有添加 Filter的
@AutoConfigureMockMvc
class HelloResourceTest {

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;

    private String jwt;
    ObjectMapper objectMapper;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        createAuthenticateToken(); // 生成 Token
    }

    @Test
    void hello() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders.get("/hello")
                                .header("Authorization", "Bearer " + jwt) // 别忘了要加个空格
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("this is resource"))
                .andDo(MockMvcResultHandlers.print());
    }

    void createAuthenticateToken() throws Exception {

        AuthenticationRequest authenticationRequest = new AuthenticationRequest("123", "123");
        String json = objectMapper.writeValueAsString(authenticationRequest);

        mockMvc.perform(
                        MockMvcRequestBuilders.post("/authenticate")
                                .accept(MediaType.APPLICATION_JSON_VALUE)
                                .contentType("application/json;charset=UTF-8")
                                .content(json.getBytes(StandardCharsets.UTF_8))
                )
                .andExpect(MockMvcResultMatchers.status().isOk())
                // .andDo(MockMvcResultHandlers.print())
                .andDo(result -> {
                    String body = result.getResponse().getContentAsString();
                    // 注意：最后这里要用 asText 不要用 toString，否则结果是有 " " 引号的
                    jwt = objectMapper.readTree(body).get("jwt").asText();
                });
    }
}