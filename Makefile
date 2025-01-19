# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -std=c++11

# Libraries
LIBS = -lpcap -lresolv

# Executable name
TARGET = dns-monitor

# Source files
SRC = src/dns-monitor.cpp

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# Clean target
clean:
	rm -f $(TARGET)
