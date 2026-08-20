FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:e5e5ecf4fb18a2f47bf0462c37e35728e8f6023ee4b7ff8bc5f903e6acba46da
# The base image ships Go 1.25 and compile_native_go_fuzzer_v2 builds with
# the local toolchain instead of the go.mod auto-switch, so sindook's
# "go 1.26.6" requirement needs a real 1.26.6 toolchain in the image.
RUN curl -fsSL https://go.dev/dl/go1.26.6.linux-amd64.tar.gz -o /tmp/go.tgz \
    && echo '708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89  /tmp/go.tgz' | sha256sum -c - \
    && rm -rf /root/.go \
    && mkdir -p /root/.go \
    && tar -C /root/.go --strip-components=1 -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz \
    && go version | grep -q 'go1.26.6'
# The image's go-118-fuzz-build_v2 was compiled with Go 1.25 and cannot
# process go1.26 sources; rebuild it from the pinned v2 commit with the
# 1.26.6 toolchain. Keep this commit in sync with the `go get` pin in
# build.sh.
RUN git clone -q https://github.com/AdamKorcz/go-118-fuzz-build /tmp/g118fuzz \
    && cd /tmp/g118fuzz \
    && git checkout -q fc5dc53b9db8a38c394c53d6e439a1410cf8fc19 \
    && go build . \
    && mv go-118-fuzz-build /root/go/bin/go-118-fuzz-build_v2 \
    && cd / && rm -rf /tmp/g118fuzz
COPY . $SRC/sindook
WORKDIR $SRC/sindook
COPY .clusterfuzzlite/build.sh $SRC/build.sh
