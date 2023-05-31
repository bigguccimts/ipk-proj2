TARGET:=ipk-sniffer
CXX:=g++
CXXFLAGS:=-std=c++20 -Werror -Wall -Wpedantic -I/usr/include/

.PHONY: all clean build

all: build

build: clean
	$(CXX) $(CXXFLAGS) -o $(TARGET) *.cpp -lpcap

clean:
	rm -rf $(TARGET)