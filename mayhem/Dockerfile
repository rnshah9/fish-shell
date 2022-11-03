FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake libncurses5-dev git
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN clang++ /repo/mayhem/harness.cpp -L/repo/build -lfishlib -lcurses -lpcre2-32 -fsanitize=address,fuzzer -o /fuzz -I/repo/src -I/repo/build

FROM ubuntu:22.04 as package
COPY --from=builder /fuzz /fuzz
