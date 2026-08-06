#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>



int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "用法:\n");
        fprintf(stderr, "  服务端模式: %s server <端口号>\n", argv[0]);
        fprintf(stderr, "  客户端模式: %s client <IP地址> <端口号>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "server") == 0) {
        // 服务端模式
        int port = atoi(argv[2]);
        int sockfd;
        struct sockaddr_in addr;

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket 创建失败");
            exit(EXIT_FAILURE);
        }


        // 允许端口复用，避免重启时“Address already in use”
        int opt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;  // 监听所有网卡
        addr.sin_port = htons(port);

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind 失败");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if (listen(sockfd, 5) < 0) {
            perror("listen 失败");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        printf("正在监听 IP %s, 端口 %d...\n", inet_ntoa(addr.sin_addr), port);

        while (1) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
            if (client_fd < 0) {
                perror("accept 失败");
                continue; // 出错时继续等待下一个连接
            }

            printf("客户端已连接: %s:%d\n",
                   inet_ntoa(client_addr.sin_addr),
                   ntohs(client_addr.sin_port));

            // 构造包含客户端 IP 和端口的消息
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "Hello, TCP client! Your address is %s:%d\n",
                     inet_ntoa(client_addr.sin_addr),
                     ntohs(client_addr.sin_port));
            
            write(client_fd, msg, strlen(msg));

            close(client_fd);
            printf("客户端连接已关闭\n");
        }

        close(sockfd);

    } else if (strcmp(argv[1], "client") == 0) {
        // 客户端模式
        if (argc != 4) {
            fprintf(stderr, "客户端模式用法: %s client <IP地址> <端口号>\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        const char *ip = argv[2];
        int port = atoi(argv[3]);

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket 创建失败");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
            perror("IP 地址无效");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("连接失败");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        printf("已连接到服务器 %s:%d\n", ip, port);

        char buffer[1024];
        int n = read(sockfd, buffer, sizeof(buffer) - 1);
        if (n > 0) {
            buffer[n] = '\0';
            printf("收到消息: %s", buffer);
        }

        close(sockfd);

    } else {
        fprintf(stderr, "未知模式: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    return 0;
}
