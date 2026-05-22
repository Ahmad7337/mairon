#C++ 
BINARY       = $(HOME)/.local/bin/mairon_dict_attack
CPP_SRC      = mairon_cli/modules/dict_attack.cpp

.PHONY: all install build-cpp clean uninstall


all: install

install:
	@echo ""
	@echo "  [1/3] Installing Python package..."
	pipx install .
	pipx ensurepath
	@echo "  Please run 'source ./bashrc' to configure the PATH variable"
	@echo ""
	@echo "  [2/3] Compiling dictionary attack module (C++)..."
	$(MAKE) build-cpp
	@echo ""
	@echo "  [3/3] Setting up wordlist..."
	python3 -c "from mairon_cli.utils import download_rockyou; download_rockyou()"
	@echo ""
	@echo "  ✓ Mairon installed. Run 'mairon --help' to get started."
	@echo ""

#dict_attack file
build-cpp:
	@which g++ > /dev/null 2>&1 || \
		(echo "ERROR: g++ not found. Install with: sudo apt install g++" && exit 1)
	@pkg-config --libs openssl > /dev/null 2>&1 || \
		(echo "ERROR: OpenSSL dev libraries not found. Install with: sudo apt install libssl-dev" && exit 1)
	mkdir -p $(HOME)/.local/bin
	g++ -O2 -o $(BINARY) $(CPP_SRC) $$(pkg-config --cflags --libs openssl)
	@echo "  ✓ Binary compiled → $(BINARY)"


uninstall:
	pipx uninstall mairon
	rm -f $(BINARY)
	@echo "  ✓ Mairon uninstalled."

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/
	@echo "  ✓ Build artifacts cleaned."
