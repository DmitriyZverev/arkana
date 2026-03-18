use std::path::PathBuf;

pub struct Fixture {
    name: &'static str,
}

impl Fixture {
    pub fn password_file_path(&self) -> PathBuf {
        self.file_path("password.txt")
    }

    pub fn plaintext_file_path(&self) -> PathBuf {
        self.file_path("plaintext.txt")
    }

    pub fn encrypted_container_file_path(&self) -> PathBuf {
        self.file_path("encrypted_container.yml")
    }

    pub fn password(&self) -> Result<String, std::io::Error> {
        std::fs::read_to_string(self.password_file_path())
    }

    pub fn plaintext(&self) -> Result<String, std::io::Error> {
        std::fs::read_to_string(self.plaintext_file_path())
    }

    pub fn encrypted_container(&self) -> Result<String, std::io::Error> {
        std::fs::read_to_string(self.encrypted_container_file_path())
    }

    fn file_path(&self, file_name: &str) -> PathBuf {
        PathBuf::from("tests/fixtures")
            .join(self.name)
            .join(file_name)
    }
}

pub static SHORT_TEXT: Fixture = Fixture { name: "short_text" };
pub static SHORT_TEXT_LOWER_CASE: Fixture = Fixture {
    name: "short_text_lower_case",
};
pub static DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2I: Fixture = Fixture {
    name: "default_kdf_argon2_algorithm_argon2i",
};
pub static DEFAULT_KDF_ARGON2_ALGORITHM_ARGON2D: Fixture = Fixture {
    name: "default_kdf_argon2_algorithm_argon2d",
};
pub static DEFAULT_KDF_ARGON2_ITERATIONS_1: Fixture = Fixture {
    name: "default_kdf_argon2_iterations_1",
};
pub static DEFAULT_KDF_ARGON2_MEMORY_65536: Fixture = Fixture {
    name: "default_kdf_argon2_memory_65536",
};
pub static DEFAULT_KDF_ARGON2_PARALLELISM_1: Fixture = Fixture {
    name: "default_kdf_argon2_parallelism_1",
};
pub static DEFAULT_KDF_ARGON2_VERSION_16: Fixture = Fixture {
    name: "default_kdf_argon2_version_16",
};
pub static FASTEST: Fixture = Fixture { name: "fastest" };
pub static LONG_TEXT: Fixture = Fixture { name: "long_text" };
