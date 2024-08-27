#nde 的 Makefile

# 指定编译器
CC = gcc

# 编译选项
CFLAGS = -Wall -g

# 链接选项
LDFLAGS = -ljson-c

# 目标可执行文件
TARGET = hande

# 源文件
SRC = hande.c

# 目标文件
OBJ = $(SRC:.c=.o)

# 安装路径
INSTALL_DIR = /usr/lib/cgi-bin/

# 默认目标
all: $(TARGET)

# 链接目标文件生成可执行文件
$(TARGET): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

# 编译源文件生成目标文件
$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC)

# 安装目标
install: $(TARGET)
	install -m 755 $(TARGET) $(INSTALL_DIR)

# 清理编译生成的文件
clean:
	rm -f $(TARGET) $(OBJ)

# 卸载目标
uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

