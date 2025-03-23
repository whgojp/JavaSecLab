package top.whgojp.modules.sqli.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import top.whgojp.modules.sqli.entity.JpaSqli;

import java.util.List;

public interface JpaSqliRepository extends JpaRepository<JpaSqli, Long> {
    
    // 安全的方法：使用方法命名约定
    List<JpaSqli> findByUsername(String username);
    
    // 安全的方法：使用@Query注解和参数绑定
    @Query("SELECT j FROM JpaSqli j WHERE j.username = :username")
    List<JpaSqli> findUsersByUsername(@Param("username") String username);
    
    // 不安全的方法：使用原生SQL
    @Query(value = "SELECT * FROM jpasqli WHERE username = ?1", nativeQuery = true)
    List<JpaSqli> findUsersByUsernameNative(String username);
} 