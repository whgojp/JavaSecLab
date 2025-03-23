package top.whgojp.modules.sqli.entity;

import lombok.Data;
import javax.persistence.*;

@Data
@Entity
@Table(name = "sqli")
public class HibernateSqli {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    
    @Column(name = "username")
    private String username;
    
    @Column(name = "password")
    private String password;
} 