#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "netconfig FAIL: %s (errno=%d)\n", msg, errno);    \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int check_rtnetlink(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(fd >= 0, "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)");

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    CHECK(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0, "bind(AF_NETLINK)");

    struct {
        struct nlmsghdr nh;
        struct ifinfomsg ifi;
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = sizeof(req);
    req.nh.nlmsg_type = RTM_GETLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1;

    CHECK(send(fd, &req, sizeof(req), 0) == (ssize_t)sizeof(req),
          "send(RTM_GETLINK)");

    char buf[8192];
    int saw_lo = 0;
    int saw_done = 0;
    while (!saw_done) {
        ssize_t peek = recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
        CHECK(peek > 0 && peek <= (ssize_t)sizeof(buf),
              "recv(MSG_PEEK|MSG_TRUNC)");
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        CHECK(n == peek, "recv(RTM_GETLINK)");
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                saw_done = 1;
                break;
            }
            if (h->nlmsg_type == RTM_NEWLINK) {
                struct ifinfomsg *ifi = NLMSG_DATA(h);
                if (ifi->ifi_flags & IFF_LOOPBACK) {
                    saw_lo = 1;
                }
            }
        }
    }
    CHECK(saw_lo, "RTM_GETLINK returned loopback");

    /* RTM_GETADDR dump */
    struct {
        struct nlmsghdr nh;
        struct ifaddrmsg ifa;
    } areq;
    memset(&areq, 0, sizeof(areq));
    areq.nh.nlmsg_len = sizeof(areq);
    areq.nh.nlmsg_type = RTM_GETADDR;
    areq.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    areq.nh.nlmsg_seq = 2;
    areq.ifa.ifa_family = AF_INET;
    CHECK(send(fd, &areq, sizeof(areq), 0) == (ssize_t)sizeof(areq),
          "send(RTM_GETADDR)");

    int saw_loopback_ip = 0;
    saw_done = 0;
    while (!saw_done) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        CHECK(n > 0, "recv(RTM_GETADDR)");
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                saw_done = 1;
                break;
            }
            if (h->nlmsg_type == RTM_NEWADDR) {
                struct ifaddrmsg *ifa = NLMSG_DATA(h);
                int rlen = (int)IFA_PAYLOAD(h);
                for (struct rtattr *r = IFA_RTA(ifa); RTA_OK(r, rlen);
                     r = RTA_NEXT(r, rlen)) {
                    if (r->rta_type == IFA_LOCAL && RTA_PAYLOAD(r) == 4) {
                        uint32_t ip;
                        memcpy(&ip, RTA_DATA(r), 4);
                        if (ip == htonl(INADDR_LOOPBACK)) {
                            saw_loopback_ip = 1;
                        }
                    }
                }
            }
        }
    }
    CHECK(saw_loopback_ip, "RTM_GETADDR returned 127.0.0.1");

    close(fd);
    return 0;
}

static int check_ioctls(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "socket(AF_INET, SOCK_DGRAM)");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "lo");
    CHECK(ioctl(fd, SIOCGIFINDEX, &ifr) == 0, "SIOCGIFINDEX(lo)");
    CHECK(ifr.ifr_ifindex > 0, "lo ifindex > 0");

    int lo_index = ifr.ifr_ifindex;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifindex = lo_index;
    CHECK(ioctl(fd, SIOCGIFNAME, &ifr) == 0, "SIOCGIFNAME(lo)");
    CHECK(strcmp(ifr.ifr_name, "lo") == 0, "SIOCGIFNAME == lo");

    CHECK(ioctl(fd, SIOCGIFFLAGS, &ifr) == 0, "SIOCGIFFLAGS(lo)");
    CHECK((ifr.ifr_flags & (IFF_UP | IFF_LOOPBACK)) == (IFF_UP | IFF_LOOPBACK),
          "lo flags");

    CHECK(ioctl(fd, SIOCGIFMTU, &ifr) == 0, "SIOCGIFMTU(lo)");
    CHECK(ifr.ifr_mtu >= 1500, "lo mtu");

    CHECK(ioctl(fd, SIOCGIFADDR, &ifr) == 0, "SIOCGIFADDR(lo)");
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    CHECK(sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK), "lo addr 127.0.0.1");

    /* If eth0 exists (Helios guest), verify its MAC and MTU too. */
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "eth0");
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
        CHECK(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0, "SIOCGIFHWADDR(eth0)");
        CHECK(ioctl(fd, SIOCGIFMTU, &ifr) == 0, "SIOCGIFMTU(eth0)");
        CHECK(ifr.ifr_mtu == 1500, "eth0 mtu == 1500");
    }

    close(fd);
    return 0;
}

static int check_packet_socket(void) {
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(0x0800));
    if (fd < 0) {
        CHECK(errno == EPERM || errno == EACCES,
              "AF_PACKET denied only with EPERM/EACCES");
        return 0;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(0x0800);
    sll.sll_ifindex = (int)if_nametoindex("lo");
    CHECK(sll.sll_ifindex > 0, "if_nametoindex(lo)");
    CHECK(bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == 0,
          "bind(AF_PACKET, lo)");
    socklen_t len = sizeof(sll);
    CHECK(getsockname(fd, (struct sockaddr *)&sll, &len) == 0,
          "getsockname(AF_PACKET)");
    CHECK(sll.sll_family == AF_PACKET, "sll_family == AF_PACKET");
    close(fd);
    return 0;
}

int main(void) {
    if (check_rtnetlink() != 0) return 1;
    if (check_ioctls() != 0) return 1;
    if (check_packet_socket() != 0) return 1;
    printf("netconfig: ok\n");
    return 0;
}
