# Disposable OpenWrt-like target for the integration tests: dropbear instead of
# OpenSSH, busybox only (no bash, no sudo, no GNU coreutils), login as root.
# Never used outside tests.
FROM alpine:3.20
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# ponytail: unpinned apk package; the image is rebuilt per test run and only
# needs dropbear to exist. Pin the version if an update ever breaks CI.
# hadolint ignore=DL3018
RUN apk add --no-cache dropbear \
 && mkdir /etc/config \
 && echo 'root:router-pass' | chpasswd

EXPOSE 22
# -R: create host keys on first connection, -F: foreground, -E: log to stderr.
CMD ["/usr/sbin/dropbear", "-R", "-F", "-E", "-p", "22"]
