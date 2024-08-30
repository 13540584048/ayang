#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define MAX_QUERY_LENGTH 1024
#define MAX_BUFFER 512


void handle_post_request();
void handle_get_request() {
    printf("{\"message\":\"GET request handled\"}\n");
}

void execute_command(const char *command, char *output, size_t max_size);

char *json_get_string_value_by_field(struct json_object *json, const char *p_field) {
    struct json_object *string_json = NULL;

    json_object_object_get_ex(json, p_field, &string_json);
    if (NULL == string_json) {
        return NULL;
    }

    if (json_type_string == json_object_get_type(string_json)) {
        return (char *)json_object_get_string(string_json);
    }

    return NULL;
}

int json_get_int_value_by_field(struct json_object *json, const char *p_field) {
    struct json_object *int_json = NULL;

    json_object_object_get_ex(json, p_field, &int_json);
    if (NULL == int_json) {
        return -1;
    }

    if (json_type_int == json_object_get_type(int_json)) {
        return json_object_get_int(int_json);
    }

    return -1;
}

const char *json_get_string_value(struct json_object *json) {
    if (json_type_string == json_object_get_type(json)) {
        return json_object_get_string(json);
    }

    return NULL;
}

struct json_object *json_get_json_object_by_field(struct json_object *json, const char *p_field) {
    struct json_object *json_obj = NULL;

    json_object_object_get_ex(json, p_field, &json_obj);
    return json_obj;
}

int json_is_array(struct json_object *json) {
    return (json_type_array == json_object_get_type(json)) ? 0 : -1;
}

void execute_command(const char *command, char *output, size_t max_size) {
    FILE *fp;
    char buffer[MAX_BUFFER];
    size_t current_size = 0;
    fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        output[0] = '\0';
        return;
    }
    while (fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {
        size_t len = strlen(buffer);
        if (current_size + len < max_size - 1) {
            strcpy(output + current_size, buffer);
            current_size += len;
        }
    }
    output[current_size] = '\0'; 
    if (pclose(fp) == -1) {
        perror("pclose failed");
    }
}

void handle_post_request() {
    char query[MAX_QUERY_LENGTH];//声明查询缓冲区
    size_t content_length;
    char *content_length_str = getenv("CONTENT_LENGTH");

    if (content_length_str == NULL) {
        fprintf(stderr, "Error: CONTENT_LENGTH not set\n");
        printf("{\"error\":1,\"message\":\"Missing CONTENT_LENGTH\"}\n");
        return;
    }

    content_length = (size_t)atoi(content_length_str);
    if (content_length >= MAX_QUERY_LENGTH) {
        fprintf(stderr, "Error: Content length %zu exceeds maximum %d\n", content_length, MAX_QUERY_LENGTH);
        printf("{\"error\":1,\"message\":\"Request too large\"}\n");
        return;
    }

    
    size_t bytes_read = fread(query, 1, content_length, stdin);
    if (bytes_read != content_length) {
        fprintf(stderr, "Error: Expected %zu bytes, read %zu bytes\n", content_length, bytes_read);
        printf("{\"error\":1,\"message\":\"Failed to read POST data\"}\n");
        return;
    }
    query[content_length] = '\0'; // 对查询字符串进行空字符终止
	

	// 将查询字符串解析为 JSON 对象
    struct json_object *myjson = json_tokener_parse(query);
	// 检查 JSON 是否有效
    if (myjson == NULL) {
        fprintf(stderr, "Error: Invalid JSON\n");
        printf("{\"error\":1,\"message\":\"Invalid JSON\"}\n");
        return;
    }

	// 从 JSON 对象中获取 action 字段
    char *action = json_get_string_value_by_field(myjson, "ACT");
	// 检查是否存在 action 字段
    if (action == NULL) {
        fprintf(stderr, "Error: Missing action field\n");
        printf("{\"error\":1,\"message\":\"Missing action\"}\n");
        json_object_put(myjson);
        return;
    }

    if (strcmp(action, "Login") == 0) {
        struct json_object *param = json_get_json_object_by_field(myjson, "param");
        if (param == NULL) {
            fprintf(stderr, "Error: Missing parameters\n");
            printf("{\"error\":1,\"message\":\"Missing parameters\"}\n");
            json_object_put(myjson);
            return;
        }

	// 从参数中获取 admin 和 pwd 字段
        char *admin = json_get_string_value_by_field(param, "admin");
        char *pwd = json_get_string_value_by_field(param, "pwd");

	// 检查 admin 和 pwd 是否匹配
        if (admin && pwd && strcmp(admin, "admin") == 0 && strcmp(pwd, "123456") == 0) {
            printf("{\"error\":0}\n");
        } else {
            printf("{\"error\":1,\"message\":\"admin or pwd error\"}\n");
        }
        json_object_put(param);
    } else if (strcmp(action, "GetDHCP") == 0) {
        char ipaddr[MAX_BUFFER] = {0};
        char netmask[MAX_BUFFER] = {0};
        char start[MAX_BUFFER] = {0};
        char limit[MAX_BUFFER] = {0};
        char leasetime[MAX_BUFFER] = {0};

	// 执行命令以获取 DHCP 配置
        execute_command("uci get network.lan.ipaddr", ipaddr, MAX_BUFFER);
        execute_command("uci get network.lan.netmask", netmask, MAX_BUFFER);
        execute_command("uci get dhcp.lan.start", start, MAX_BUFFER);
        execute_command("uci get dhcp.lan.limit", limit, MAX_BUFFER);
        execute_command("uci get dhcp.lan.leasetime", leasetime, MAX_BUFFER);

	// 创建 JSON 对象并添加 DHCP 配置
        struct json_object *response = json_object_new_object();
        json_object_object_add(response, "ipaddr", json_object_new_string(ipaddr));
        json_object_object_add(response, "netmask", json_object_new_string(netmask));
        json_object_object_add(response, "start", json_object_new_string(start));
        json_object_object_add(response, "limit", json_object_new_string(limit));
        json_object_object_add(response, "leasetime", json_object_new_string(leasetime));
        json_object_object_add(response, "error", json_object_new_int(0)); 
        printf("%s\n", json_object_to_json_string(response));
        json_object_put(response);
    }else if (strcmp(action, "GetWiFi") == 0) {
        char ssid[MAX_BUFFER] = {0};
        

         // 执行命令以获取 WiFi 配置
        execute_command("uci get wireless.@wifi-iface[0].ssid", ssid, MAX_BUFFER);

	// 创建 JSON 对象并添加 WiFi 配置
        struct json_object *response = json_object_new_object();
        json_object_object_add(response, "ssid", json_object_new_string(ssid));
        json_object_object_add(response, "error", json_object_new_int(0));

        printf("%s\n", json_object_to_json_string(response));
        json_object_put(response);
    } else if (strcmp(action, "GetVersion") == 0) {
 	// 定义缓冲区，用于存储各类版本信息
        char openwrt[MAX_BUFFER] = {0};
        char kernel[MAX_BUFFER] = {0};
        char fw_version[MAX_BUFFER] = {0};
        char full_fw_version[MAX_BUFFER] = {0};
        char vendor_version[MAX_BUFFER] = {0};

        //获取 OpenWrt 版本
        execute_command("cat /etc/openwrt_version", openwrt, MAX_BUFFER);
	//以获取内核版本
        execute_command("uname -r", kernel, MAX_BUFFER);
	// 从配置文件中获取固件版本信息
        get_value_from_config("/etc/system_version.info", "FW_VERSION", fw_version, MAX_BUFFER);
        get_value_from_config("/etc/system_version.info", "FULL_FW_VERSION", full_fw_version, MAX_BUFFER);
        get_value_from_config("/etc/system_version.info", "VENDOR_ASKEY_VERSION", vendor_version, MAX_BUFFER);
	// 创建一个新的 JSON 对象
        struct json_object *response = json_object_new_object();

        json_object_object_add(response, "openwrt", json_object_new_string(openwrt));
        json_object_object_add(response, "kernel", json_object_new_string(kernel));
        json_object_object_add(response, "fw_version", json_object_new_string(fw_version)); 
        json_object_object_add(response, "full_fw_version", json_object_new_string(full_fw_version));
        json_object_object_add(response, "vendor_version", json_object_new_string(vendor_version));
        
	json_object_object_add(response, "error", json_object_new_int(0));
	// 将 JSON 对象转换为字符串并打印输出
        printf("%s\n", json_object_to_json_string(response));
	// 释放 JSON 对象的内存
        json_object_put(response);
    }else if(!strcmp("SetDHCP", action)){
	char cmd[512] = {0};
	int error = 0;
	// 从 JSON 中获取 DHCP 配置字段
	char *ipaddr = json_get_string_value_by_field(myjson,"ipaddr");
	if(ipaddr == NULL)
	{
		error += 1;
	}
	char *netmask = json_get_string_value_by_field(myjson,"netmask");
	if(netmask == NULL)
	{
		error += 1;
	}
	char *start = json_get_string_value_by_field(myjson,"start");	
	if(start == NULL)
	{
		error += 1;
	}
	char *limit = json_get_string_value_by_field(myjson,"limit");
	if(limit == NULL)
	{
		error += 1;
	}
	char *leasetime = json_get_string_value_by_field(myjson,"leasetime");
	if(leasetime == NULL)
	{
		error += 1;
	}
	// 更新 DHCP 配置
	sprintf(cmd,"uci set network.lan.ipaddr=%s", ipaddr);
	system(cmd);

	memset(cmd,0,512);
	sprintf(cmd,"uci set network.lan.netmask=%s", netmask);
	system(cmd);

	memset(cmd,0,512);
	sprintf(cmd,"uci set network.lan.start=%s", start);
	system(cmd);

	memset(cmd,0,512);
	sprintf(cmd,"uci set network.lan.limit=%s", limit);
	system(cmd);

	memset(cmd,0,512);
	sprintf(cmd,"uci set network.lan.leasetime=%s", leasetime);
	system(cmd);

	// 提交更改，打印有没有更改失败的并且重启网络服务
	system("uci commit");
	printf("{\"error\":%d}\n", error);  
	system("/etc/init.d/network restart");

} 
else if(!strcmp("Setwifi", action)){
	char cmde[512] = {0};
	int errorr = 0;
	 // 从 JSON 中获取 ssid 字段
	char *ssid = json_get_string_value_by_field(myjson,"ssid");
	if(ssid == NULL)
	{
		errorr = 1;
	}

	// 更新 WiFi 配置
	memset(cmde,0,512);
	sprintf(cmde,"uci set wireless.ay.ssid=%s", ssid);
	system(cmde);

	// 提交更改,打印结果并重启 WiFi 服务
	system("uci commit");
	printf("{\"error\":%d}\n", errorr);  
	system("wifi &");
}
else {
        printf("{\"error\":1,\"message\":\"Unknown action\"}\n");
    }

    json_object_put(myjson); 
}

int get_value_from_config(const char *filename, const char *key, char *value, size_t value_size) {
    	// 打开配置文件以进行读取,r是只读
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
	// 如果文件无法打开，输出错误信息
        perror("error opening file");
        return -1;
    }
	// 定义一个缓冲区用于存储每一行内容
	char line[256];
	int found = 0;
	 // 逐行读取配置文件
	while (fgets(line, sizeof(line), file) != NULL) {
		// 查找行中的 '=' 分隔符
		char *delimiter_pos = strchr(line, '=');
		if (delimiter_pos != NULL) {
			// 将 '=' 替换为字符串结束符 '\0'
			*delimiter_pos = '\0';
			char *current_key = line;// 当前行的键
			char *current_value = delimiter_pos + 1;// 当前行的值
			// 查找值中的换行符，并将其替换为字符串结束符
			char *newline_pos = strchr(current_value, '\n');
			if (newline_pos != NULL) {
			*newline_pos = '\0';
		}
		// 检查当前行的键是否与目标键匹配
		if (strcmp(current_key, key) == 0) {
			// 检查值的长度是否适合目标缓冲区
			if (strlen(current_value) < value_size) {
			// 将值复制到目标缓冲区，并确保目标缓冲区以空字符结束
			strncpy(value, current_value, value_size - 1);
			value[value_size - 1] = '\0';
			found = 1;
			} else {
				found = 0;
		}
                break;
            }
        }
    }
 	// 关闭配置文件
	fclose(file);
	// 返回结果：找到键返回 0，否则返回 -1
	return found ? 0 : -1;
}

    

int main() {
    const char *method = getenv("REQUEST_METHOD");

    printf("Content-Type: application/json\n\n");

    if (method != NULL && strcmp(method, "POST") == 0) {
        handle_post_request();
    } else if (method != NULL && strcmp(method, "GET") == 0) {
        handle_get_request(); 
    } else {
        printf("{\"error\":1,\"message\":\"Method not supported\"}\n");
    }

    return 0;
}


