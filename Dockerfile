FROM rustlang/rust:nightly

ARG SSH_KEY
ARG SCCACHE_KEY

# add sccache
ENV SCCACHE_VERSION=0.2.8
ADD https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz /tmp
RUN cd /tmp \
  && tar xf sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz \
  && mv sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl/sccache /usr/bin/sccache \
  && rm -rf /tmp/sccache-*
ENV SCCACHE_GCS_BUCKET=umpyre-sccache
ENV SCCACHE_GCS_RW_MODE=READ_WRITE
ENV SCCACHE_GCS_KEY_PATH=/root/sccache.json
ENV RUSTC_WRAPPER=sccache

WORKDIR /app

COPY . /app/src
COPY Rolodex.toml /app

RUN mkdir -p $HOME/.ssh \
  && chmod 0700 $HOME/.ssh \
  && ssh-keyscan github.com > $HOME/.ssh/known_hosts \
  && echo "$SSH_KEY" > $HOME/.ssh/id_rsa \
  && echo "$SCCACHE_KEY" > $SCCACHE_GCS_KEY_PATH \
  && RUST_LOG=sccache=info SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 sccache & \
  && chmod 600 $HOME/.ssh/id_rsa \
  && eval `ssh-agent` \
  && ssh-add -k $HOME/.ssh/id_rsa \
  && cd src \
  && cargo install --path . \
  && cd tools/loader \
  && cargo install --path . \
  && cd .. \
  && rm -rf src \
  && rm -rf $HOME/.cargo/registry \
  && rm -rf $HOME/.cargo/git

# Remove SSH keys
RUN rm -rf /root/.ssh/

ENV RUST_LOG=rolodex=info

ENTRYPOINT [ "rolodex" ]
