#include <net/if.h>
#include <linux/if_tun.h>
#include <cstring>
#include <csignal>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <cerrno>
#include <set>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>

constexpr size_t BUF_SIZE = 4ull * 1024ull * 1024ull;

class fd_guard {
private:
    int fd;
public:
    fd_guard(int fd) : fd(fd) {}
    fd_guard(const fd_guard&) = delete;
    fd_guard(fd_guard&& other) noexcept {
        fd = other.fd;
        other.fd = -1;
    }
    ~fd_guard() {
        if (fd >= 0) close(fd);
    }

    operator int() const {
        return fd;
    }
};

enum class connection_state {
    WAITING_ADDRESS, WAITING_LENGTH, WAITING_CONTENT
};

class connection {
public:
    const fd_guard fd;
    const unsigned tunIndex;
    const in_addr selfAddr;
private:
    mutable connection_state state = connection_state::WAITING_ADDRESS;

    mutable size_t cnt = 0;
    mutable in_addr addr;
    mutable unsigned size;
    mutable char data[BUF_SIZE];

    int setRoute(bool flag) const {
        fd_guard nlSocket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
        if (nlSocket < 0) return -1;

        struct {
            nlmsghdr nh;
            rtmsg rt;
            char attrs[512];
        } req;
        memset(&req, 0, sizeof(req));
        size_t bufAvail = sizeof(req.attrs);
        req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rt));
        req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;
        req.nh.nlmsg_type = flag ? RTM_NEWROUTE : RTM_DELROUTE;
        req.rt.rtm_family = AF_INET;
        req.rt.rtm_src_len = 0;
        req.rt.rtm_dst_len = 32;
        req.rt.rtm_scope = RT_SCOPE_LINK;
        req.rt.rtm_table = RT_TABLE_MAIN;
        req.rt.rtm_type = RTN_UNICAST;
        req.rt.rtm_protocol = RTPROT_BOOT;

        rtattr* attr = RTM_RTA(&req.rt);
        attr->rta_type = RTA_DST;
        attr->rta_len = RTA_LENGTH(sizeof(addr));
        req.nh.nlmsg_len += attr->rta_len;
        memcpy(RTA_DATA(attr), &addr, sizeof(addr));

        attr = RTA_NEXT(attr, bufAvail);
        attr->rta_type = RTA_PREFSRC;
        attr->rta_len = RTA_LENGTH(sizeof(selfAddr));
        req.nh.nlmsg_len += attr->rta_len;
        memcpy(RTA_DATA(attr), &selfAddr, sizeof(selfAddr));

        attr = RTA_NEXT(attr, bufAvail);
        attr->rta_type = RTA_OIF;
        attr->rta_len = RTA_LENGTH(sizeof(tunIndex));
        req.nh.nlmsg_len += attr->rta_len;
        memcpy(RTA_DATA(attr), &tunIndex, sizeof(tunIndex));

        if (write(nlSocket, &req, req.nh.nlmsg_len) < 0) return -2;

        return 0;
    }
public:
    explicit connection(int fd, unsigned tunIndex, const in_addr& selfAddr) : fd(fd), tunIndex(tunIndex), selfAddr(selfAddr) {
        memset(&addr, 0, sizeof(addr));
    }
    explicit connection(fd_guard&& fd, unsigned tunIndex, const in_addr& selfAddr) : fd(std::move(fd)), tunIndex(tunIndex), selfAddr(selfAddr) {
        memset(&addr, 0, sizeof(addr));
    }
    connection(const connection&) = delete;
    connection(connection&& other) = delete;

    ~connection() {
        if (state != connection_state::WAITING_ADDRESS) {
            int res = setRoute(false);
            if (res < 0) printf("[connection %d] setRoute (del) failed with %d\n", operator int(), res);
            printf("[connection %d] Route deleted\n", operator int());
        }
    }

    operator int() const {
        return fd;
    }

    int send(const char* buf, size_t len, bool withLen = true) const {
        if (withLen) {
            unsigned uLen = len;
            auto bytesWritten = write(fd, &uLen, sizeof(uLen));
            if (bytesWritten < 0) {
                printf("[connection %d] write failed with %d\n", operator int(), errno);
                return -1;
            }
        }
        auto bytesWritten = write(fd, buf, len);
        if (bytesWritten < 0) {
            printf("[connection %d] write failed with %d\n", operator int(), errno);
            return -2;
        }
        return 0;
    }

    int init() const {
        return send(reinterpret_cast<const char *>(&selfAddr), sizeof(selfAddr), false);
    }

    int onRecv(const char* buf, size_t len, const fd_guard& tunFD) const {
        while (len) {
            switch (state) {
                case connection_state::WAITING_ADDRESS: {
                    size_t addrLeft = sizeof(addr) - cnt;
                    size_t addrRead = std::min(len, addrLeft);
                    memcpy(reinterpret_cast<char *>(&addr) + cnt, buf, addrRead);
                    cnt += addrRead;
                    buf += addrRead;
                    len -= addrRead;
                    if (cnt == sizeof(addr)) {
                        int res = setRoute(true);
                        if (res < 0) {
                            printf("[connection %d] setRoute (add) failed with %d\n", operator int(), res);
                            return -1;
                        }
                        printf("[connection %d] Route added\n", operator int());
                        state = connection_state::WAITING_LENGTH;
                        cnt = 0;
                    }
                    break;
                }
                case connection_state::WAITING_LENGTH: {
                    size_t sizeLeft = sizeof(size) - cnt;
                    size_t sizeRead = std::min(len, sizeLeft);
                    memcpy(reinterpret_cast<char *>(&size) + cnt, buf, sizeRead);
                    cnt += sizeRead;
                    buf += sizeRead;
                    len -= sizeRead;
                    if (cnt == sizeof(size)) {
                        if (size > BUF_SIZE) {
                            printf("[connection %d] Illegal data size: %u\n", operator int(), size);
                            return -2;
                        }
                        state = connection_state::WAITING_CONTENT;
                        cnt = 0;
                    }
                    break;
                }
                case connection_state::WAITING_CONTENT: {
                    size_t dataLeft = size - cnt;
                    size_t dataRead = std::min(len, dataLeft);
                    memcpy(data + cnt, buf, dataRead);
                    cnt += dataRead;
                    buf += dataRead;
                    len -= dataRead;
                    if (cnt == size) {
                        auto bytesWritten = write(tunFD, data, size);
                        if (bytesWritten < 0) {
                            printf("[connection %d] write to TUN device failed with %d\n", operator int(), errno);
                            return -3;
                        }
                        state = connection_state::WAITING_LENGTH;
                        cnt = 0;
                    }
                    break;
                }
            }
        }
        return 0;
    }
};

char buffer[BUF_SIZE];

fd_guard tun_alloc(char *dev) {
    ifreq ifr;
    int fd, err;

    if((fd = open("/dev/net/tun", O_RDWR)) < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if((err = ioctl(fd, TUNSETIFF, &ifr)) < 0){
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return { fd };
}

int assign_address(const char* name, const in_addr& ip) {
    fd_guard sockFD = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockFD < 0) return -1;

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if (ioctl(sockFD, SIOCGIFFLAGS, &ifr) < 0) return -2;

    if (!(ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
        if (ioctl(sockFD, SIOCSIFFLAGS, &ifr) < 0) return -3;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = ip;
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));

    if (ioctl(sockFD, SIOCSIFADDR, &ifr) < 0) return -4;

    inet_aton("255.255.255.255", &addr.sin_addr);
    memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
    if (ioctl(sockFD, SIOCSIFNETMASK, &ifr) < 0) return -5;

    return 0;
}

int server_loop(const fd_guard& tunFD, unsigned tunIndex, in_addr selfAddr, int port) {
    fd_guard listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) return -1;
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    if (bind(listenSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) return -2;
    if (listen(listenSocket, 4096) < 0) return -3;
    const int keepAlive = 1;
    if (setsockopt(listenSocket, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive)) < 0) return -4;

    printf("[server] Listening on port %d\n", port);

    fd_guard epollFD = epoll_create1(0);
    if (epollFD < 0) return -5;
    epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = listenSocket;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, listenSocket, &event) < 0) return -6;
    event.events = EPOLLIN;
    event.data.fd = tunFD;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, tunFD, &event) < 0) return -7;
    epoll_event events[4096];

    printf("[server] Epoll initialized\n");

    std::set<connection, std::less<void>> clients;
    while (true) {
        int num = epoll_wait(epollFD, events, 4096, -1);
        if (num < 0) {
            printf("[server] epoll_wait failed with %d\n", errno);
            return 0;
        }
        for (int i = 0; i < num; ++i) {
            int curFD = events[i].data.fd;
            if (curFD == listenSocket) {
                int connectionSocket = accept(listenSocket, nullptr, nullptr);
                if (connectionSocket < 0) {
                    printf("[server] accept failed with %d\n", errno);
                    continue;
                }
                if (setsockopt(connectionSocket, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive)) < 0) {
                    printf("[connection %d] setsockopt failed with %d\n", connectionSocket, errno);
                    close(connectionSocket);
                    continue;
                }
                event.events = EPOLLIN;
                event.data.fd = connectionSocket;
                if (epoll_ctl(epollFD, EPOLL_CTL_ADD, connectionSocket, &event) < 0) {
                    printf("[server] epoll_ctl failed with %d\n", errno);
                    close(connectionSocket);
                    return 0;
                }
                auto [iter, success] = clients.emplace(connectionSocket, tunIndex, selfAddr);
                if (!success) {
                    printf("[server] emplace failed\n");
                    close(connectionSocket);
                    continue;
                }
                int res = iter->init();
                if (res < 0) {
                    printf("[connection %d] init failed with %d\n", connectionSocket, res);
                    clients.erase(iter);
                    continue;
                }
                printf("[server] Established new connection %d\n", connectionSocket);
            } else if (curFD == tunFD) {
                auto bytesRead = read(tunFD, buffer, sizeof(buffer));
                if (bytesRead < 0) {
                    printf("[server] read from TUN device failed with %d\n", errno);
                    return 0;
                }
                for (auto iter = clients.begin(); iter != clients.end();) {
                    auto res = iter->send(buffer, bytesRead);
                    if (res < 0) {
                        printf("[connection %d] send failed with %d\n", iter->fd.operator int(), res);
                        clients.erase(iter++);
                    } else ++iter;
                }
            } else {
                auto iter = clients.find<int>(curFD);
                if (iter == clients.end()) continue;
                auto bytesRead = read(curFD, buffer, sizeof(buffer));
                if (bytesRead < 0) {
                    printf("[connection %d] read failed with %d\n", curFD, errno);
                    clients.erase(iter);
                    continue;
                }
                auto res = iter->onRecv(buffer, bytesRead, tunFD);
                if (res < 0) {
                    printf("[connection %d] onRecv failed with %d\n", curFD, res);
                    clients.erase(iter);
                    continue;
                }
            }
        }
    }
}

int client_loop(const fd_guard& tunFD, unsigned tunIndex, in_addr selfAddr, in_addr serverAddr, int port) {
    fd_guard connectSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (connectSocket < 0) return -1;
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = serverAddr;
    addr.sin_port = htons(port);
    const int keepAlive = 1;
    if (setsockopt(connectSocket, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive)) < 0) return -2;
    if (connect(connectSocket, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr)) < 0) return -3;

    printf("[client] Connected to server\n");

    fd_guard epollFD = epoll_create1(0);
    if (epollFD < 0) return -4;
    epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = connectSocket;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, connectSocket, &event) < 0) return -5;
    event.events = EPOLLIN;
    event.data.fd = tunFD;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, tunFD, &event) < 0) return -6;
    epoll_event events[4];

    printf("[client] Epoll initialized\n");

    connection conn{std::move(connectSocket), tunIndex, selfAddr};
    int res = conn.init();
    if (res < 0) {
        printf("[client] init failed with %d\n", res);
        return -7;
    }

    while (true) {
        int num = epoll_wait(epollFD, events, 4, -1);
        if (num < 0) {
            printf("[client] epoll_wait failed with %d\n", errno);
            return 0;
        }
        for (int i = 0; i < num; ++i) {
            int curFD = events[i].data.fd;
            if (curFD == tunFD) {
                auto bytesRead = read(tunFD, buffer, sizeof(buffer));
                if (bytesRead < 0) {
                    printf("[client] read from TUN device failed with %d\n", errno);
                    return 0;
                }
                res = conn.send(buffer, bytesRead);
                if (res < 0) {
                    printf("[client] send failed with %d\n", res);
                    return 0;
                }
            } else if (curFD == conn) {
                auto bytesRead = read(curFD, buffer, sizeof(buffer));
                if (bytesRead < 0) {
                    printf("[client] read failed with %d\n", errno);
                    return 0;
                }
                res = conn.onRecv(buffer, bytesRead, tunFD);
                if (res < 0) {
                    printf("[client] onRecv failed with %d\n", res);
                    return 0;
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) {
        printf("netutil client/server ...\n");
        return 0;
    }

    char devName[1025] = "tun%d";
    fd_guard tunFD = tun_alloc(devName);
    if (tunFD < 0) {
        printf("[main] tun_alloc failed with %d", tunFD.operator int());
        return -1;
    }
    unsigned tunIndex = if_nametoindex(devName);
    printf("[main] Created TUN device %s\n", devName);

    if (strcmp(argv[1], "server") == 0) {
        if (argc != 4) {
            printf("NetworkUtil server <port> <virtual ip>\n");
            return 0;
        }
        in_addr addr;
        inet_aton(argv[3], &addr);
        int res = assign_address(devName, addr);
        if (res < 0) {
            printf("[main] assign_address failed with %d", res);
            return -2;
        }
        printf("[main] Assigned address %s to %s\n", argv[3], devName);
        printf("[main] Starting server loop...\n");
        res = server_loop(tunFD, tunIndex, addr, atoi(argv[2]));
        if (res < 0) printf("[main] Server loop failed with %d\n", res);
    } else if (strcmp(argv[1], "client") == 0) {
        if (argc != 5) {
            printf("NetworkUtil client <virtual ip> <server ip> <server port>\n");
            return 0;
        }
        in_addr addr, serverAddr;
        inet_aton(argv[2], &addr);
        inet_aton(argv[3], &serverAddr);
        int res = assign_address(devName, addr);
        if (res < 0) {
            printf("[main] assign_address failed with %d", res);
            return -2;
        }
        printf("[main] Assigned address %s to %s\n", argv[2], devName);
        printf("[main] Starting client loop...\n");
        res = client_loop(tunFD, tunIndex, addr, serverAddr, atoi(argv[4]));
        if (res < 0) printf("[main] Client loop failed with %d\n", res);
    } else {
        printf("netutil client/server ...\n");
        return 0;
    }
    return 0;
}
