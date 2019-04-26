FROM rustlang/rust:nightly

ARG SSH_KEY

WORKDIR /app

COPY . /app/src
COPY Rolodex.toml /app

RUN mkdir -p $HOME/.ssh \
    && chmod 0700 $HOME/.ssh \
    && ssh-keyscan github.com > $HOME/.ssh/known_hosts \
    && echo "$SSH_KEY" > $HOME/.ssh/id_rsa \
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
