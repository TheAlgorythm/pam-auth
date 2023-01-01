
compile:
	cargo build --release

install-modules: compile
	sudo cp target/release/libpam_pin.so /lib/security/pam_pin.so
	sudo cp target/release/libpam_direct_fallback.so /lib/security/pam_direct_fallback.so