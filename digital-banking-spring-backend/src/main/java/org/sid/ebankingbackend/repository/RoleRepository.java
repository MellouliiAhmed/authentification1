package org.sid.ebankingbackend.repository;

//////import com.bezkoder.springjwt.models.ERole;
/////////////import com.bezkoder.springjwt.models.Role;
import org.sid.ebankingbackend.models.ERole;
import org.sid.ebankingbackend.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
