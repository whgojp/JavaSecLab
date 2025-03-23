package top.whgojp.modules.sqli.entity;

import lombok.Data;
import javax.persistence.*;

@Data
@Entity
@Table(name = "sqli")
public class JpaSqli {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String password;
} 