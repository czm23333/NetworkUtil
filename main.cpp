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
#include <netinet/ip.h>
#include <memory>
#include <openssl/evp.h>
#include <vector>
#include <openssl/err.h>
#include <filesystem>
#include <openssl/pem.h>

constexpr size_t BUF_SIZE = 4ull * 1024ull * 1024ull;
constexpr size_t SIG_BUF_SIZE = 512;
constexpr size_t KEY_BUF_SIZE = 4ull * 1024ull;

EVP_MD* sha512;

using pkey_t = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>;
pkey_t privateKey(nullptr, EVP_PKEY_free);
unsigned char myPublicKey[KEY_BUF_SIZE];
size_t myPublicKeyLen = 0;
std::vector<pkey_t> trustedPublicKeys;

class fd_guard {
public:
    int fd;

    fd_guard() : fd(-1) {}
    fd_guard(int fd) : fd(fd) {}
    fd_guard(const fd_guard&) = delete;
    fd_guard(fd_guard&& other) noexcept {
        fd = other.fd;
        other.fd = -1;
    }
    ~fd_guard() {
        if (fd >= 0) close(fd);
    }

    fd_guard& operator=(fd_guard&& other) noexcept {
        if (fd >= 0) close(fd);
        fd = other.fd;
        other.fd = -1;
        return *this;
    }

    operator int() const {
        return fd;
    }
};

class tun_device {
public:
    char devName[1025] = "tun%d";
    fd_guard fd;
    unsigned index = 0;
    in_addr address;

    tun_device() = default;

    int init() {
        fd_guard tmp = open("/dev/net/tun", O_RDWR);
        if(tmp < 0) return -1;

        ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN;
        strncpy(ifr.ifr_name, devName, IFNAMSIZ);

        if(ioctl(tmp, TUNSETIFF, &ifr) < 0) return -2;
        strcpy(devName, ifr.ifr_name);

        index = if_nametoindex(devName);

        fd = std::move(tmp);
        return 0;
    }

    int enable(const in_addr& ip) {
        fd_guard sockFD = socket(AF_INET, SOCK_DGRAM, 0);
        if(sockFD < 0) return -1;

        ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, devName, IFNAMSIZ);
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

        address = ip;

        return 0;
    }

    int send(const char* buf, size_t len) const {
        auto bytesWritten = write(fd, buf, len);
        if (bytesWritten < 0) {
            printf("[tun_device] write failed with %d\n", errno);
            return -1;
        }
        return 0;
    }

    template<size_t S>
    long recv(char (&buf)[S]) const {
        auto bytesRead = read(fd, buf, sizeof(buf));
        if (bytesRead < 0) {
            printf("[tun_device] read failed with %d\n", errno);
            return -1;
        }
        return bytesRead;
    }
};

enum class connection_state {
    WAITING_ADDRESS,
    WAITING_PUBKEY_LENGTH, WAITING_PUBKEY,
    WAITING_SIG_LENGTH, WAITING_SIG,
    WAITING_LENGTH, WAITING_CONTENT
};

class tcp_connection {
public:
    fd_guard fd;
    const tun_device& tun;
    mutable connection_state state = connection_state::WAITING_ADDRESS;
    mutable in_addr addr;
private:
    mutable size_t cnt = 0;
    mutable unsigned size = 0;
    mutable char data[BUF_SIZE];
    mutable unsigned char sendBuf[BUF_SIZE];
    mutable unsigned sigLen = 0;
    mutable unsigned char sig[SIG_BUF_SIZE];
    mutable unsigned char keyBuf[KEY_BUF_SIZE];
    mutable EVP_PKEY* publicKey = nullptr;

    static size_t writeVarUInt(unsigned num, unsigned char* buf) {
        int len = 0;
        do {
            unsigned char tmp = num & 0b1111111u;
            num >>= 7u;
            if (num) tmp |= 0b10000000u;
            *buf = tmp;
            ++buf;
            ++len;
        } while (num);
        return len;
    }

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
        attr->rta_len = RTA_LENGTH(sizeof(tun.address));
        req.nh.nlmsg_len += attr->rta_len;
        memcpy(RTA_DATA(attr), &tun.address, sizeof(tun.address));

        attr = RTA_NEXT(attr, bufAvail);
        attr->rta_type = RTA_OIF;
        attr->rta_len = RTA_LENGTH(sizeof(tun.index));
        req.nh.nlmsg_len += attr->rta_len;
        memcpy(RTA_DATA(attr), &tun.index, sizeof(tun.index));

        if (write(nlSocket, &req, req.nh.nlmsg_len) < 0) return -2;

        return 0;
    }

    static int sign(const char* msg, size_t len, unsigned char* sig, size_t& sigLen) {
        std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (EVP_DigestSignInit(digestContext.get(), nullptr, sha512, nullptr, privateKey.get()) != 1) return -1;
        if (EVP_DigestSignUpdate(digestContext.get(), msg, len) != 1) return -2;
        if (EVP_DigestSignFinal(digestContext.get(), sig, &sigLen) != 1) return -3;
        return 0;
    }

    bool verify(const char* msg, size_t len) const {
        if (publicKey == nullptr) return false;
        std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (EVP_DigestVerifyInit(digestContext.get(), nullptr, sha512, nullptr, publicKey) != 1) return false;
        if (EVP_DigestVerifyUpdate(digestContext.get(), msg, len) != 1) return false;
        if (EVP_DigestVerifyFinal(digestContext.get(), sig, sigLen) != 1) return false;
        return true;
    }
public:
    explicit tcp_connection(const tun_device& tun) : tun(tun) {}
    tcp_connection(int fd, const tun_device& tun) : fd(fd), tun(tun) {}
    tcp_connection(fd_guard&& fd, const tun_device& tun) : fd{ std::move(fd) }, tun(tun) {}
    tcp_connection(const tcp_connection&) = delete;
    tcp_connection(tcp_connection&& other) = delete;

    ~tcp_connection() {
        if (state != connection_state::WAITING_ADDRESS) {
            int res = setRoute(false);
            if (res < 0) printf("[tcp_connection %d] setRoute (del) failed with %d\n", operator int(), res);
            else printf("[tcp_connection %d] Route deleted\n", operator int());
        }
        if (publicKey != nullptr) EVP_PKEY_free(publicKey);
        if (fd >= 0) shutdown(fd, SHUT_RDWR);
    }

    operator int() const {
        return fd;
    }

    int init() {
        int tmp = socket(AF_INET, SOCK_STREAM, 0);
        if (tmp < 0) return -1;
        fd = tmp;
        return 0;
    }

    int enableKeepAlive() const {
        static const int keepAlive = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive)) < 0) return -1;
        return 0;
    }

    int connect(const in_addr& serverAddr, int port) const {
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr = serverAddr;
        addr.sin_port = htons(port);
        if (::connect(fd, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr)) < 0) return -1;
        return 0;
    }

    int send(const char* buf, size_t len, bool withLen = true) const {
        if (len == 0) {
            printf("[tcp_connection %d] Detected sending with 0 length. This shouldn't have happened.\n", operator int());
            return 0;
        }
        if (withLen) {
            unsigned char* ptr = sendBuf;
            size_t lenLen = writeVarUInt(len, ptr);
            if (lenLen + len > BUF_SIZE) return -1;
            ptr += lenLen;
            memcpy(ptr, buf, len);
            auto bytesWritten = write(fd, sendBuf, lenLen + len);
            if (bytesWritten < 0) {
                printf("[tcp_connection %d] write failed with %d\n", operator int(), errno);
                return -2;
            }
        } else {
            auto bytesWritten = write(fd, buf, len);
            if (bytesWritten < 0) {
                printf("[tcp_connection %d] write failed with %d\n", operator int(), errno);
                return -3;
            }
        }
        return 0;
    }

    int sendWithSign(const char* buf, size_t len) const {
        unsigned char sigBuf[SIG_BUF_SIZE];
        size_t sigLen = sizeof(sigBuf);
        int res = sign(buf, len, sigBuf, sigLen);
        if (res < 0) {
            printf("[tcp_connection %d] sign failed with %d\n", operator int(), res);
            return -1;
        }
        res = send(reinterpret_cast<const char*>(sigBuf), sigLen);
        if (res < 0) {
            printf("[tcp_connection %d] send failed with %d\n", operator int(), res);
            return -2;
        }
        res = send(buf, len);
        if (res < 0) {
            printf("[tcp_connection %d] send failed with %d\n", operator int(), res);
            return -3;
        }
        return 0;
    }

    int sendPublicKey() const {
        return send(reinterpret_cast<const char*>(myPublicKey), myPublicKeyLen);
    }

    int sendHandshake() const {
        int res = send(reinterpret_cast<const char*>(&tun.address), sizeof(tun.address), false);
        if (res < 0) {
            printf("[tcp_connection %d] send failed with %d\n", operator int(), res);
            return -1;
        }
        res = sendPublicKey();
        if (res < 0) {
            printf("[tcp_connection %d] sendPublicKey failed with %d\n", operator int(), res);
            return -2;
        }
        return 0;
    }

    template<size_t S>
    long recv(char (&buf)[S]) const {
        auto bytesRead = read(fd, buf, sizeof(buf));
        if (bytesRead < 0) {
            printf("[tcp_connection %d] read failed with %d\n", fd.operator int(), errno);
            return -1;
        }
        return bytesRead;
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
                            printf("[tcp_connection %d] setRoute (add) failed with %d\n", operator int(), res);
                            return -1;
                        }
                        printf("[tcp_connection %d] Route added\n", operator int());
                        state = connection_state::WAITING_PUBKEY_LENGTH;
                        cnt = 0;
                        size = 0;
                    }
                    break;
                }
                case connection_state::WAITING_LENGTH:
                case connection_state::WAITING_PUBKEY_LENGTH:
                case connection_state::WAITING_SIG_LENGTH: {
                    bool flag = false;
                    unsigned bitCnt = 0;
                    while (len) {
                        unsigned char tmp = *buf;
                        size |= (tmp & 0b1111111u) << bitCnt;
                        ++buf;
                        --len;
                        bitCnt += 7;
                        if (!(tmp & 0b10000000u)) {
                            flag = true;
                            break;
                        }
                    }
                    if (flag) {
                        switch (state) {
                            case connection_state::WAITING_LENGTH: {
                                if (size > BUF_SIZE) {
                                    printf("[tcp_connection %d] Illegal data size: %u\n", operator int(), size);
                                    return -2;
                                }
                                state = connection_state::WAITING_CONTENT;
                                cnt = 0;
                                break;
                            }
                            case connection_state::WAITING_PUBKEY_LENGTH: {
                                if (size > KEY_BUF_SIZE) {
                                    printf("[tcp_connection %d] Illegal public key size: %u\n", operator int(), size);
                                    return -3;
                                }
                                state = connection_state::WAITING_PUBKEY;
                                cnt = 0;
                                break;
                            }
                            case connection_state::WAITING_SIG_LENGTH: {
                                if (size > SIG_BUF_SIZE) {
                                    printf("[tcp_connection %d] Illegal signature size: %u\n", operator int(), size);
                                    return -4;
                                }
                                sigLen = size;
                                state = connection_state::WAITING_SIG;
                                cnt = 0;
                                break;
                            }
                            default:
                                break;
                        }
                    }
                    break;
                }
                case connection_state::WAITING_PUBKEY: {
                    size_t keyLeft = size - cnt;
                    size_t keyRead = std::min(len, keyLeft);
                    memcpy(keyBuf + cnt, buf, keyRead);
                    cnt += keyRead;
                    buf += keyRead;
                    len -= keyRead;
                    if (cnt == size) {
                        const unsigned char* ptr = keyBuf;
                        publicKey = d2i_PublicKey(EVP_PKEY_DSA, nullptr, &ptr, size);
                        if (publicKey == nullptr) {
                            printf("[tcp_connection %d] d2i_PublicKey failed with %lu\n", operator int(), ERR_get_error());
                            return -5;
                        }
                        bool flag = false;
                        for (auto& trusted : trustedPublicKeys) {
                            if (EVP_PKEY_eq(trusted.get(), publicKey) == 1) {
                                flag = true;
                                break;
                            }
                        }
                        if (!flag) {
                            printf("[tcp_connection %d] Untrusted public key\n", operator int());
                            return -6;
                        }
                        state = connection_state::WAITING_SIG_LENGTH;
                        cnt = 0;
                        size = 0;
                    }
                    break;
                }
                case connection_state::WAITING_SIG: {
                    size_t sigLeft = size - cnt;
                    size_t sigRead = std::min(len, sigLeft);
                    memcpy(sig + cnt, buf, sigRead);
                    cnt += sigRead;
                    buf += sigRead;
                    len -= sigRead;
                    if (cnt == size) {
                        state = connection_state::WAITING_LENGTH;
                        cnt = 0;
                        size = 0;
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
                        if (!verify(data, size)) {
                            printf("[tcp_connection %d] Invalidated data\n", operator int());
                            return -7;
                        }
                        auto res = tun.send(data, size);
                        if (res < 0) {
                            printf("[tcp_connection %d] write to TUN device failed with %d\n", operator int(), res);
                            return -8;
                        }
                        state = connection_state::WAITING_SIG_LENGTH;
                        cnt = 0;
                        size = 0;
                    }
                    break;
                }
            }
        }
        return 0;
    }
};

char buffer[BUF_SIZE];

int server_loop(const tun_device& tun, int port) {
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
    event.data.fd = tun.fd;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, tun.fd, &event) < 0) return -7;
    epoll_event events[4096];

    printf("[server] Epoll initialized\n");

    std::set<tcp_connection, std::less<void>> clients;
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
                auto [iter, success] = clients.emplace(connectionSocket, tun);
                if (!success) {
                    printf("[server] emplace failed\n");
                    close(connectionSocket);
                    continue;
                }
                int res = iter->enableKeepAlive();
                if (res < 0) {
                    printf("[tcp_connection %d] enableKeepAlive failed with %d\n", connectionSocket, res);
                    clients.erase(iter);
                    continue;
                }
                event.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
                event.data.fd = connectionSocket;
                if (epoll_ctl(epollFD, EPOLL_CTL_ADD, connectionSocket, &event) < 0) {
                    printf("[server] epoll_ctl failed with %d\n", errno);
                    clients.erase(iter);
                    return 0;
                }
                res = iter->sendHandshake();
                if (res < 0) {
                    printf("[tcp_connection %d] sendHandshake failed with %d\n", connectionSocket, res);
                    clients.erase(iter);
                    continue;
                }
                printf("[server] Established new tcp_connection %d\n", connectionSocket);
            } else if (curFD == tun.fd) {
                auto bytesRead = tun.recv(buffer);
                if (bytesRead < 0) {
                    printf("[server] recv from TUN device failed with %ld\n", bytesRead);
                    return 0;
                }
                auto* pi = reinterpret_cast<tun_pi*>(buffer);
                if (ntohs(pi->proto) != ETH_P_IP) continue;
                auto* ipHeader = reinterpret_cast<ip*>(buffer + sizeof(tun_pi));
                in_addr dst = ipHeader->ip_dst;
                for (auto iter = clients.begin(); iter != clients.end();) {
                    if (iter->state == connection_state::WAITING_ADDRESS || memcmp(&dst, &iter->addr, sizeof(dst)) != 0) continue;
                    auto res = iter->sendWithSign(buffer, bytesRead);
                    if (res < 0) {
                        printf("[tcp_connection %d] sendWithSign failed with %d\n", iter->fd.operator int(), res);
                        clients.erase(iter++);
                    } else ++iter;
                }
            } else {
                auto iter = clients.find<int>(curFD);
                if (iter == clients.end()) continue;
                if ((events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLHUP)) {
                    printf("[tcp_connection %d] Disconnected\n", curFD);
                    clients.erase(iter);
                    continue;
                }

                auto bytesRead = iter->recv(buffer);
                if (bytesRead < 0) {
                    printf("[tcp_connection %d] read failed with %ld\n", curFD, bytesRead);
                    clients.erase(iter);
                    continue;
                }
                auto res = iter->onRecv(buffer, bytesRead, tun.fd);
                if (res < 0) {
                    printf("[tcp_connection %d] onRecv failed with %d\n", curFD, res);
                    clients.erase(iter);
                    continue;
                }
            }
        }
    }
}

int client_loop(const tun_device& tun, in_addr serverAddr, int port) {
    std::unique_ptr<tcp_connection> connPtr = std::make_unique<tcp_connection>(tun);
    tcp_connection& conn = *connPtr;
    if (conn.init() < 0) return -1;
    if (conn.enableKeepAlive() < 0) return -2;
    if (conn.connect(serverAddr, port) < 0) return -3;

    printf("[client] Connected to server\n");

    fd_guard epollFD = epoll_create1(0);
    if (epollFD < 0) return -4;
    epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
    event.data.fd = conn;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, conn, &event) < 0) return -5;
    event.events = EPOLLIN;
    event.data.fd = tun.fd;
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, tun.fd, &event) < 0) return -6;
    epoll_event events[4];

    printf("[client] Epoll initialized\n");

    int res = conn.sendHandshake();
    if (res < 0) {
        printf("[client] sendHandshake failed with %d\n", res);
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
            if (curFD == tun.fd) {
                auto bytesRead = tun.recv(buffer);
                if (bytesRead < 0) {
                    printf("[client] recv from TUN device failed with %ld\n", bytesRead);
                    return 0;
                }
                auto* pi = reinterpret_cast<tun_pi*>(buffer);
                if (ntohs(pi->proto) != ETH_P_IP) continue;
                res = conn.sendWithSign(buffer, bytesRead);
                if (res < 0) {
                    printf("[client] sendWithSign failed with %d\n", res);
                    return 0;
                }
            } else if (curFD == conn) {
                if ((events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLHUP)) {
                    printf("[client] Disconnected\n");
                    return 0;
                }

                auto bytesRead = conn.recv(buffer);
                if (bytesRead < 0) {
                    printf("[client] recv failed with %ld\n", bytesRead);
                    return 0;
                }
                res = conn.onRecv(buffer, bytesRead, tun.fd);
                if (res < 0) {
                    printf("[client] onRecv failed with %d\n", res);
                    return 0;
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    OPENSSL_init();
    OpenSSL_add_all_algorithms();
    sha512 = EVP_MD_fetch(nullptr, "SHA512", nullptr);
    signal(SIGPIPE, SIG_IGN);

    if (argc < 5) {
        printf("netutil client/server <private key path> <public key path> <trusted public keys dir> ...\n");
        return 0;
    }

    {
        BIO *priKeyBIO = BIO_new_file(argv[2], "r");
        if (priKeyBIO == nullptr) {
            printf("[main] BIO_new_file on private key file failed\n");
            return -1;
        }
        EVP_PKEY *priKey = PEM_read_bio_PrivateKey(priKeyBIO, nullptr, nullptr, nullptr);
        if (priKey == nullptr) {
            printf("[main] PEM_read_bio_PrivateKey failed\n");
            return -2;
        }
        privateKey = {priKey, EVP_PKEY_free};
        BIO_free(priKeyBIO);
    }

    {
        BIO *pubKeyBIO = BIO_new_file(argv[3], "r");
        if (pubKeyBIO == nullptr) {
            printf("[main] BIO_new_file on public key file failed\n");
            return -3;
        }
        EVP_PKEY *pubKey = PEM_read_bio_PUBKEY(pubKeyBIO, nullptr, nullptr, nullptr);
        if (pubKey == nullptr) {
            printf("[main] PEM_read_bio_PUBKEY failed\n");
            return -4;
        }
        BIO_free(pubKeyBIO);

        unsigned char* myPublicKeyBuf = myPublicKey;
        int lenTmp = i2d_PublicKey(pubKey, &myPublicKeyBuf);
        if (lenTmp < 0) {
            printf("[main] i2d_PublicKey failed with %lu\n", ERR_get_error());
            return -5;
        }
        myPublicKeyLen = lenTmp;

        EVP_PKEY_free(pubKey);
    }

    {
        using namespace std::filesystem;
        path trustedPath(argv[4]);
        if (!is_directory(trustedPath)) {
            printf("[main] Invalid trusted public keys directory\n");
            return -6;
        }
        for (auto& entry : directory_iterator(trustedPath)) {
            BIO *pubKeyBIO = BIO_new_file(entry.path().c_str(), "r");
            if (pubKeyBIO == nullptr) {
                printf("[main] BIO_new_file on trusted public key file failed, skipping\n");
                continue;
            }
            EVP_PKEY *pubKey = PEM_read_bio_PUBKEY(pubKeyBIO, nullptr, nullptr, nullptr);
            BIO_free(pubKeyBIO);
            if (pubKey == nullptr) {
                printf("[main] PEM_read_bio_PUBKEY failed, skipping\n");
                continue;
            }
            trustedPublicKeys.emplace_back(pubKey, EVP_PKEY_free);
        }
    }

    tun_device tun;
    int res = tun.init();
    if (res < 0) {
        printf("[main] tun.init failed with %d\n", res);
        return -7;
    }
    printf("[main] Created TUN device %s\n", tun.devName);

    if (strcmp(argv[1], "server") == 0) {
        if (argc != 7) {
            printf("netutil server <private key path> <public key path> <trusted public keys dir> <port> <virtual ip>\n");
            return 0;
        }
        in_addr addr;
        inet_aton(argv[6], &addr);
        res = tun.enable(addr);
        if (res < 0) {
            printf("[main] tun.enable failed with %d\n", res);
            return -8;
        }
        printf("[main] Assigned address %s to %s\n", argv[6], tun.devName);
        printf("[main] Starting server loop...\n");
        res = server_loop(tun, atoi(argv[5]));
        if (res < 0) printf("[main] Server loop failed with %d\n", res);
    } else if (strcmp(argv[1], "client") == 0) {
        if (argc != 8) {
            printf("netutil client <private key path> <public key path> <trusted public keys dir> <virtual ip> <server ip> <server port>\n");
            return 0;
        }
        in_addr addr, serverAddr;
        inet_aton(argv[5], &addr);
        inet_aton(argv[6], &serverAddr);
        res = tun.enable(addr);
        if (res < 0) {
            printf("[main] tun.enable failed with %d\n", res);
            return -9;
        }
        printf("[main] Assigned address %s to %s\n", argv[5], tun.devName);
        printf("[main] Starting client loop...\n");
        res = client_loop(tun, serverAddr, atoi(argv[7]));
        if (res < 0) printf("[main] Client loop failed with %d\n", res);
    } else {
        printf("netutil client/server ...\n");
        return 0;
    }

    EVP_MD_free(sha512);
    return 0;
}
