/*
 * Linux socket ABI fixture (#1030): exercises socketpair, TCP client/server,
 * non-blocking connect + epoll + SO_ERROR, UDP connected/unconnected,
 * sendmsg/recvmsg, sendmmsg/recvmmsg, shutdown, sendfile, setsockopt/getsockopt,
 * and IPv4 multicast. Runs identically on Linux and on Helios.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

static void die(const char *msg) {
    fprintf(stderr, "sockets fixture failed: %s (errno=%d: %s)\n",
            msg, errno, strerror(errno));
    exit(1);
}

#define CHECK(cond, msg) do { if (!(cond)) die(msg); } while (0)

static void test_socketpair_and_io(void) {
    int sv[2] = {-1, -1};
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) == 0,
          "socketpair stream");

    int fl = fcntl(sv[0], F_GETFL, 0);
    CHECK(fl >= 0 && (fl & O_NONBLOCK) != 0, "socketpair SOCK_NONBLOCK reflected in F_GETFL");
    int fdfl = fcntl(sv[0], F_GETFD, 0);
    CHECK(fdfl >= 0 && (fdfl & FD_CLOEXEC) != 0, "socketpair SOCK_CLOEXEC reflected in F_GETFD");

    /* Non-blocking empty read returns EAGAIN. */
    char buf[64];
    errno = 0;
    CHECK(recv(sv[1], buf, sizeof(buf), 0) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
          "nonblocking empty recv -> EAGAIN");

    /* Clear O_NONBLOCK via ioctl(FIONBIO) and verify via F_GETFL. */
    int zero = 0;
    CHECK(ioctl(sv[1], FIONBIO, &zero) == 0, "ioctl FIONBIO 0");
    fl = fcntl(sv[1], F_GETFL, 0);
    CHECK(fl >= 0 && (fl & O_NONBLOCK) == 0, "FIONBIO cleared O_NONBLOCK");

    /* MSG_DONTWAIT on a blocking socket still returns EAGAIN. */
    errno = 0;
    CHECK(recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT) == -1 &&
          (errno == EAGAIN || errno == EWOULDBLOCK),
          "MSG_DONTWAIT empty recv -> EAGAIN");

    /* writev -> MSG_PEEK -> read. */
    struct iovec wiov[2] = {
        { .iov_base = "hel", .iov_len = 3 },
        { .iov_base = "ios", .iov_len = 3 },
    };
    CHECK(writev(sv[0], wiov, 2) == 6, "writev on socketpair");

    memset(buf, 0, sizeof(buf));
    CHECK(recv(sv[1], buf, 6, MSG_PEEK) == 6 && memcmp(buf, "helios", 6) == 0,
          "MSG_PEEK on socketpair");
    memset(buf, 0, sizeof(buf));
    CHECK(read(sv[1], buf, 6) == 6 && memcmp(buf, "helios", 6) == 0,
          "read after MSG_PEEK on socketpair");

    /* sendmsg / recvmsg with scatter/gather iovecs. */
    struct iovec siov[2] = {
        { .iov_base = "abc", .iov_len = 3 },
        { .iov_base = "defg", .iov_len = 4 },
    };
    struct msghdr smsg = {0};
    smsg.msg_iov = siov;
    smsg.msg_iovlen = 2;
    CHECK(sendmsg(sv[0], &smsg, 0) == 7, "sendmsg on socketpair");

    char r1[4] = {0}, r2[4] = {0};
    struct iovec riov[2] = {
        { .iov_base = r1, .iov_len = 3 },
        { .iov_base = r2, .iov_len = 4 },
    };
    struct msghdr rmsg = {0};
    rmsg.msg_iov = riov;
    rmsg.msg_iovlen = 2;
    CHECK(recvmsg(sv[1], &rmsg, 0) == 7 && memcmp(r1, "abc", 3) == 0 && memcmp(r2, "defg", 4) == 0,
          "recvmsg scatter on socketpair");

    /* epoll on socketpair. */
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0, "epoll_create1");
    struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP, .data.fd = sv[1] };
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, sv[1], &ev) == 0, "epoll_ctl add socketpair");
    struct epoll_event out[2];
    CHECK(epoll_wait(ep, out, 2, 0) == 0, "epoll_wait empty socketpair == 0");

    CHECK(send(sv[0], "ping", 4, 0) == 4, "send ping");
    CHECK(epoll_wait(ep, out, 2, 100) == 1 && (out[0].events & EPOLLIN) != 0,
          "epoll_wait sees EPOLLIN on socketpair");
    CHECK(recv(sv[1], buf, 4, 0) == 4 && memcmp(buf, "ping", 4) == 0, "recv ping");

    /* sendfile from pipe into socketpair. */
    int pfd[2];
    CHECK(pipe(pfd) == 0, "pipe for sendfile");
    CHECK(write(pfd[1], "sendfile-ok", 11) == 11, "write pipe for sendfile");
    off_t off = 0;
    errno = 0;
    CHECK(sendfile(sv[0], pfd[0], &off, 11) == -1 && errno == ESPIPE,
          "sendfile with offset on pipe -> ESPIPE");
    CHECK(sendfile(sv[0], pfd[0], NULL, 11) == 11, "sendfile pipe -> socketpair");
    memset(buf, 0, sizeof(buf));
    CHECK(recv(sv[1], buf, 11, 0) == 11 && memcmp(buf, "sendfile-ok", 11) == 0,
          "recv after sendfile");
    close(pfd[0]);
    close(pfd[1]);

    /* getsockopt metadata on socketpair. */
    int opt = 0;
    socklen_t optlen = sizeof(opt);
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &opt, &optlen) == 0 && opt == SOCK_STREAM,
          "SO_TYPE on socketpair");
    optlen = sizeof(opt);
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_DOMAIN, &opt, &optlen) == 0 && opt == AF_UNIX,
          "SO_DOMAIN on socketpair");
    optlen = sizeof(opt);
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_PROTOCOL, &opt, &optlen) == 0 && opt == 0,
          "SO_PROTOCOL on socketpair");

    /* shutdown(SHUT_WR) -> peer reads EOF and epoll sees EPOLLIN/EPOLLHUP. */
    CHECK(shutdown(sv[0], SHUT_WR) == 0, "shutdown SHUT_WR on socketpair");
    CHECK(epoll_wait(ep, out, 2, 100) == 1 && (out[0].events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) != 0,
          "epoll sees peer shutdown");
    CHECK(recv(sv[1], buf, sizeof(buf), 0) == 0, "recv EOF after peer SHUT_WR");

    close(ep);
    close(sv[0]);
    close(sv[1]);
}

struct tcp_server_arg {
    int listener;
};

static void *tcp_server_thread(void *raw) {
    struct tcp_server_arg *arg = raw;
    struct sockaddr_in peer = {0};
    socklen_t peerlen = sizeof(peer);
    int conn = accept4(arg->listener, (struct sockaddr *)&peer, &peerlen, SOCK_CLOEXEC);
    if (conn < 0) die("accept4");
    if (peer.sin_family != AF_INET || peer.sin_port == 0) die("accept4 peer addr");

    char buf[32] = {0};
    ssize_t n = recv(conn, buf, sizeof(buf), 0);
    if (n != 5 || memcmp(buf, "hello", 5) != 0) die("server recv hello");
    if (send(conn, "world", 5, MSG_NOSIGNAL) != 5) die("server send world");
    if (shutdown(conn, SHUT_WR) != 0) die("server shutdown SHUT_WR");

    /* Wait for client to close / EOF. */
    if (recv(conn, buf, sizeof(buf), 0) != 0) die("server recv EOF");
    close(conn);
    return NULL;
}

static void test_tcp_loopback(void) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0, "tcp socket");

    int one = 1;
    CHECK(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0,
          "SO_REUSEADDR");
    CHECK(setsockopt(listener, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0,
          "TCP_NODELAY");
    int ttl = 42;
    CHECK(setsockopt(listener, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == 0, "IP_TTL");
    socklen_t optlen = sizeof(ttl);
    ttl = 0;
    CHECK(getsockopt(listener, IPPROTO_IP, IP_TTL, &ttl, &optlen) == 0 && ttl == 42,
          "getsockopt IP_TTL");

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0, "SO_RCVTIMEO");
    struct timeval tv_out = {0};
    optlen = sizeof(tv_out);
    CHECK(getsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &tv_out, &optlen) == 0 &&
          tv_out.tv_sec == 5, "getsockopt SO_RCVTIMEO");

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = 0;
    CHECK(bind(listener, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == 0, "tcp bind");
    CHECK(listen(listener, 4) == 0, "tcp listen");

    int acceptconn = 0;
    optlen = sizeof(acceptconn);
    CHECK(getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN, &acceptconn, &optlen) == 0 &&
          acceptconn == 1, "SO_ACCEPTCONN == 1");

    struct sockaddr_in bound = {0};
    socklen_t boundlen = sizeof(bound);
    CHECK(getsockname(listener, (struct sockaddr *)&bound, &boundlen) == 0 &&
          bound.sin_family == AF_INET && bound.sin_port != 0,
          "getsockname on listening tcp socket");

    pthread_t th;
    struct tcp_server_arg arg = { .listener = listener };
    CHECK(pthread_create(&th, NULL, tcp_server_thread, &arg) == 0, "pthread_create tcp server");

    /* Non-blocking connect + epoll EPOLLOUT + getsockopt(SO_ERROR). */
    int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(client >= 0, "tcp client socket");
    int rc = connect(client, (struct sockaddr *)&bound, sizeof(bound));
    if (rc == -1) {
        CHECK(errno == EINPROGRESS, "nonblocking connect -> EINPROGRESS");
        int ep = epoll_create1(EPOLL_CLOEXEC);
        CHECK(ep >= 0, "epoll_create1 connect");
        struct epoll_event ev = { .events = EPOLLOUT, .data.fd = client };
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, client, &ev) == 0, "epoll_ctl connect");
        struct epoll_event out[1];
        CHECK(epoll_wait(ep, out, 1, 5000) == 1 && (out[0].events & EPOLLOUT) != 0,
              "epoll_wait nonblocking connect EPOLLOUT");
        close(ep);
    }
    int so_err = -1;
    optlen = sizeof(so_err);
    CHECK(getsockopt(client, SOL_SOCKET, SO_ERROR, &so_err, &optlen) == 0 && so_err == 0,
          "SO_ERROR == 0 after connect");

    struct sockaddr_in peer = {0};
    socklen_t peerlen = sizeof(peer);
    CHECK(getpeername(client, (struct sockaddr *)&peer, &peerlen) == 0 &&
          peer.sin_port == bound.sin_port, "getpeername on connected tcp client");
    struct sockaddr_in local = {0};
    socklen_t locallen = sizeof(local);
    CHECK(getsockname(client, (struct sockaddr *)&local, &locallen) == 0 &&
          local.sin_port != 0, "getsockname on connected tcp client");

    CHECK(send(client, "hello", 5, 0) == 5, "client send hello");

    /* Wait for server reply via epoll. */
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0, "epoll_create1 tcp read");
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = client };
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, client, &ev) == 0, "epoll_ctl tcp read");
    struct epoll_event out[1];
    CHECK(epoll_wait(ep, out, 1, 5000) == 1 && (out[0].events & EPOLLIN) != 0,
          "epoll_wait tcp client EPOLLIN");
    close(ep);

    char buf[32] = {0};
    CHECK(recv(client, buf, 5, MSG_PEEK) == 5 && memcmp(buf, "world", 5) == 0,
          "client tcp MSG_PEEK");
    memset(buf, 0, sizeof(buf));
    CHECK(recv(client, buf, 5, 0) == 5 && memcmp(buf, "world", 5) == 0,
          "client tcp recv world");
    CHECK(shutdown(client, SHUT_WR) == 0, "client shutdown SHUT_WR");

    CHECK(pthread_join(th, NULL) == 0, "pthread_join tcp server");
    close(client);
    close(listener);
}

static void test_udp_loopback_and_mmsg(void) {
    int srv = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(srv >= 0, "udp server socket");
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    CHECK(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0, "udp bind");
    socklen_t addrlen = sizeof(addr);
    CHECK(getsockname(srv, (struct sockaddr *)&addr, &addrlen) == 0 && addr.sin_port != 0,
          "udp getsockname");

    int cli = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(cli >= 0, "udp client socket");
    CHECK(sendto(cli, "dgram1", 6, 0, (struct sockaddr *)&addr, sizeof(addr)) == 6,
          "udp sendto");

    /* epoll on UDP socket. */
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0, "epoll_create1 udp");
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = srv };
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, srv, &ev) == 0, "epoll_ctl udp");
    struct epoll_event out[1];
    CHECK(epoll_wait(ep, out, 1, 5000) == 1 && (out[0].events & EPOLLIN) != 0,
          "epoll_wait udp EPOLLIN");
    close(ep);

    char buf[32] = {0};
    struct sockaddr_in from = {0};
    socklen_t fromlen = sizeof(from);
    CHECK(recvfrom(srv, buf, 3, MSG_PEEK | MSG_TRUNC, (struct sockaddr *)&from, &fromlen) == 6 &&
          memcmp(buf, "dgr", 3) == 0 && from.sin_port != 0,
          "udp recvfrom MSG_PEEK | MSG_TRUNC");
    memset(buf, 0, sizeof(buf));
    fromlen = sizeof(from);
    CHECK(recvfrom(srv, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen) == 6 &&
          memcmp(buf, "dgram1", 6) == 0, "udp recvfrom");

    /* Connected UDP + sendmmsg / recvmmsg + AF_UNSPEC disconnect. */
    CHECK(connect(cli, (struct sockaddr *)&addr, sizeof(addr)) == 0, "udp connect");
    struct sockaddr_in peer = {0};
    socklen_t peerlen = sizeof(peer);
    CHECK(getpeername(cli, (struct sockaddr *)&peer, &peerlen) == 0 &&
          peer.sin_port == addr.sin_port, "udp getpeername");

    struct mmsghdr sm[2];
    memset(sm, 0, sizeof(sm));
    struct iovec si0 = { .iov_base = "one", .iov_len = 3 };
    struct iovec si1 = { .iov_base = "two!", .iov_len = 4 };
    sm[0].msg_hdr.msg_iov = &si0;
    sm[0].msg_hdr.msg_iovlen = 1;
    sm[1].msg_hdr.msg_iov = &si1;
    sm[1].msg_hdr.msg_iovlen = 1;
    CHECK(sendmmsg(cli, sm, 2, 0) == 2 && sm[0].msg_len == 3 && sm[1].msg_len == 4,
          "udp sendmmsg");

    struct mmsghdr rm[2];
    memset(rm, 0, sizeof(rm));
    char b0[16] = {0}, b1[16] = {0};
    struct iovec ri0 = { .iov_base = b0, .iov_len = sizeof(b0) };
    struct iovec ri1 = { .iov_base = b1, .iov_len = sizeof(b1) };
    rm[0].msg_hdr.msg_iov = &ri0;
    rm[0].msg_hdr.msg_iovlen = 1;
    rm[1].msg_hdr.msg_iov = &ri1;
    rm[1].msg_hdr.msg_iovlen = 1;
    int got = recvmmsg(srv, rm, 2, 0, NULL);
    CHECK(got == 2 && rm[0].msg_len == 3 && memcmp(b0, "one", 3) == 0 &&
          rm[1].msg_len == 4 && memcmp(b1, "two!", 4) == 0,
          "udp recvmmsg");

    struct sockaddr unspec = { .sa_family = AF_UNSPEC };
    CHECK(connect(cli, &unspec, sizeof(unspec)) == 0, "udp disconnect AF_UNSPEC");
    peerlen = sizeof(peer);
    errno = 0;
    CHECK(getpeername(cli, (struct sockaddr *)&peer, &peerlen) == -1 && errno == ENOTCONN,
          "udp getpeername after disconnect -> ENOTCONN");

    /* recvmsg on a truncated datagram sets MSG_TRUNC in msg_flags. */
    CHECK(sendto(cli, "truncated!", 10, 0, (struct sockaddr *)&addr, sizeof(addr)) == 10,
          "udp sendto for recvmsg MSG_TRUNC");
    char small[4] = {0};
    struct iovec tiov = { .iov_base = small, .iov_len = sizeof(small) };
    struct msghdr tmsg = {0};
    tmsg.msg_iov = &tiov;
    tmsg.msg_iovlen = 1;
    CHECK(recvmsg(srv, &tmsg, 0) == 4 && memcmp(small, "trun", 4) == 0 &&
          (tmsg.msg_flags & MSG_TRUNC) != 0,
          "udp recvmsg sets MSG_TRUNC in msg_flags");

    /* IPv4 multicast options (both 1-byte u8 and 4-byte int). */
    unsigned char mttl_u8 = 2;
    CHECK(setsockopt(srv, IPPROTO_IP, IP_MULTICAST_TTL, &mttl_u8, sizeof(mttl_u8)) == 0,
          "IP_MULTICAST_TTL u8");
    unsigned char mloop_u8 = 1;
    CHECK(setsockopt(srv, IPPROTO_IP, IP_MULTICAST_LOOP, &mloop_u8, sizeof(mloop_u8)) == 0,
          "IP_MULTICAST_LOOP u8");
    struct ip_mreq mreq = {0};
    mreq.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(srv, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
        CHECK(setsockopt(srv, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) == 0,
              "IP_DROP_MEMBERSHIP");
    }

    close(cli);
    close(srv);
}

static void test_error_cases(void) {
    errno = 0;
    CHECK(socket(99, SOCK_STREAM, 0) == -1 && errno == EAFNOSUPPORT,
          "invalid domain -> EAFNOSUPPORT");
    errno = 0;
    CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) == -1 && errno == EPROTONOSUPPORT,
          "mismatched protocol -> EPROTONOSUPPORT");
    int pfd[2];
    CHECK(pipe(pfd) == 0, "pipe for ENOTSOCK");
    errno = 0;
    CHECK(listen(pfd[0], 1) == -1 && errno == ENOTSOCK, "listen on pipe -> ENOTSOCK");
    close(pfd[0]);
    close(pfd[1]);
}

int main(void) {
    test_error_cases();
    test_socketpair_and_io();
    test_tcp_loopback();
    test_udp_loopback_and_mmsg();
    puts("sockets: ok");
    return 0;
}
