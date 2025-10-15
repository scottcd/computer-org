# Project Name: Threads
# Author: Chandler Scott
# Description: Threads example


# Definition of variables
BUILD_TOOL = gcc
BUILD_DIR = ./build/

SOURCES = ./src/crc.c
TARGET = ./build/crc

.PHONY: all clean setup

# Default target
all: setup $(TARGET)

setup:
	mkdir -p $(BUILD_DIR)

$(TARGET): $(SOURCES) 
	$(BUILD_TOOL) $(SOURCES) -o $(TARGET)

# Clean target to remove build artifacts
clean:  
	rm -rf $(BUILD_DIR)
