# Makefile per filefix-hunter
TARGET = x86_64-pc-windows-gnu
BIN = filefix-hunter.exe

all: build

build:
	cargo build --release --target $(TARGET)

clean:
	cargo clean

deploy:
	cp target/$(TARGET)/release/$(BIN) ~/share

build-deploy: build deploy
	@echo "Build and deployment complete."