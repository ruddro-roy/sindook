# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:e5e5ecf4fb18a2f47bf0462c37e35728e8f6023ee4b7ff8bc5f903e6acba46da
# The base image ships Go 1.25 and compile_native_go_fuzzer_v2 builds with
# the local toolchain instead of the go.mod auto-switch, so sindook's
# "go 1.26.6" requirement needs a real 1.26.6 toolchain in the image.
RUN curl -fsSL https://go.dev/dl/go1.26.6.linux-amd64.tar.gz -o /tmp/go.tgz \
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
RUN git clone --depth 1 https://github.com/ruddro-roy/sindook
WORKDIR sindook
COPY build.sh $SRC/
