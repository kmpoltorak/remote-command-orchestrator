# Disposable target for the integration tests: real OpenSSH, busybox sh, GNU
# coreutils, bash and sudo that asks for a password. Never used outside tests.
# GNU cp matters: unlike busybox cp it writes through a symlinked destination,
# which is what the planted symlink below checks for.
FROM alpine:3.20
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# ponytail: unpinned apk packages; the image is rebuilt per test run and only
# needs these tools to exist. Pin versions if a package update ever breaks CI.
# hadolint ignore=DL3018
RUN apk add --no-cache openssh bash sudo coreutils \
 && ssh-keygen -A \
 && adduser -D deploy \
 && echo 'deploy:deploy-pass' | chpasswd \
 && echo 'deploy ALL=(ALL) ALL' > /etc/sudoers.d/deploy \
 && mkdir /etc/rco-it \
 && echo untouched > /etc/victim \
 && ln -s /etc/victim /etc/rco-it/app.conf.rco-tmp

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
