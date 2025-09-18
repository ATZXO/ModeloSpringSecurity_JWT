package com.atz.security.repository;

import com.atz.security.entities.RolesEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RoleRepository extends JpaRepository<RolesEntity, Long> {
    List<RolesEntity> findRolesEntitiesByRoleEnumIn(List<String> rolesName);
}
