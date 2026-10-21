package dev.bastion.admin;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

/** One runtime switch (see SettingsService). */
@Entity
@Table(name = "app_settings")
class AppSetting {

    @Id
    @Column(length = 64)
    String name;

    @Column(name = "setting_value", nullable = false, length = 255)
    String value;

    @Column(name = "updated_at", nullable = false)
    Instant updatedAt;

    protected AppSetting() {
    }

    AppSetting(String name) {
        this.name = name;
    }
}

interface AppSettingRepository extends JpaRepository<AppSetting, String> {
}
