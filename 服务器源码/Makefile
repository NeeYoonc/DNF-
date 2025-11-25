# DNF 隧道服务器 Makefile

CXX = g++
CXXFLAGS = -std=c++11 -O2 -Wall -pthread

# 原生隧道服务器
TARGET = dnf-tunnel-server
SOURCES = tcp_tunnel_server.cpp tcp_config_server.cpp
HEADERS = tcp_config_server.h

# WebSocket 桥接
WS_TARGET = dnf-tunnel-ws-bridge
WS_SOURCE = websocket_bridge.cpp

# 默认目标：仅编译原生隧道服务器（保持兼容）
all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $@
	@echo "编译完成: $(TARGET)"
	@echo "运行: ./$(TARGET)"

# 静态编译（兼容性最好）
static: $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -static $(SOURCES) -o $(TARGET)
	@echo "静态编译完成: $(TARGET)"
	@echo "文件大小:"
	@ls -lh $(TARGET)

# 仅编译 WebSocket 桥接（非默认）
ws-bridge: $(WS_TARGET)

$(WS_TARGET): $(WS_SOURCE)
	$(CXX) $(CXXFLAGS) $< -o $@
	@echo "编译完成: $(WS_TARGET)"
	@echo "运行: ./$(WS_TARGET) [listen_port]"

# 静态编译 WebSocket 桥接（若系统支持静态链接）
ws-static: $(WS_SOURCE)
	$(CXX) $(CXXFLAGS) -static $< -o $(WS_TARGET)
	@echo "静态编译完成: $(WS_TARGET)"
	@ls -lh $(WS_TARGET)

# 清理
clean:
	rm -f $(TARGET) $(WS_TARGET)
	@echo "清理完成"

# 安装
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "已安装到: /usr/local/bin/$(TARGET)"

# 卸载
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "已卸载"

.PHONY: all static clean install uninstall ws-bridge ws-static
