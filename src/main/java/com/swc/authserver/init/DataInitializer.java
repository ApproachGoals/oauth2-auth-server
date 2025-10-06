package com.swc.authserver.init;

import com.swc.authserver.entities.Permission;
import com.swc.authserver.entities.Role;
import com.swc.authserver.entities.User;
import com.swc.authserver.repository.PermissionRepository;
import com.swc.authserver.repository.RoleRepository;
import com.swc.authserver.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;

//@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PermissionRepository permissionRepo;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepo, RoleRepository roleRepo,
                           PermissionRepository permissionRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo; this.roleRepo = roleRepo; this.permissionRepo = permissionRepo; this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        Permission p1 = permissionRepo.findByName("user.read").orElseGet(() -> {
            Permission p = new Permission(); p.setName("user.read"); return permissionRepo.save(p);
        });
        Permission p2 = permissionRepo.findByName("user.write").orElseGet(() -> {
            Permission p = new Permission(); p.setName("user.write"); return permissionRepo.save(p);
        });

        Role admin = roleRepo.findByName("ROLE_ADMIN").orElseGet(() -> {
            Role r = new Role(); r.setName("ROLE_ADMIN"); r.getPermissions().add(p1); r.getPermissions().add(p2); return roleRepo.save(r);
        });

        Role userRole = roleRepo.findByName("ROLE_USER").orElseGet(() -> {
            Role r = new Role(); r.setName("ROLE_USER"); r.getPermissions().add(p1); return roleRepo.save(r);
        });

        userRepo.findByUsername("user").orElseGet(() -> {
            User u = new User();
            u.setUsername("user");
            u.setPassword(passwordEncoder.encode("password"));
            u.setEmail("user@swc.org");
            u.getRoles().add(userRole);
            return userRepo.save(u);
        });

        userRepo.findByUsername("admin").orElseGet(() -> {
            User u = new User();
            u.setUsername("admin");
            u.setPassword(passwordEncoder.encode("adminpass"));
            u.setEmail("admin@swc.org");
            u.getRoles().add(admin);
            return userRepo.save(u);
        });
    }
}
