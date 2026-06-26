CC = gcc
CFLAGS = -O3 -Wall -pthread
LDFLAGS = -lssl -lcrypto -lz -lbpf -lelf -lbpf

BPF_CC = clang
BPF_CFLAGS = -O2 -target bpf -I/usr/include/$(shell uname -m)-linux-gnu

TARGET = netbench
BPF_TARGETS = xdp_rst_filter.o xdp_v15_hybrid.o xdp_v15_stealth.o tc_rst_block.o
SRCS = main.c network.c proxy.c benchmark.c af_xdp.c
OBJS = $(SRCS:.c=.o)

SRCS_MIN = main.c network.c proxy.c benchmark.c
OBJS_MIN = $(SRCS_MIN:.c=.o)

all: $(TARGET) $(BPF_TARGETS)

minimal: CFLAGS += -DNO_AF_XDP
minimal: $(OBJS_MIN)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS_MIN) -lssl -lcrypto -lz
	@cp -f $(TARGET) tornado 2>/dev/null || true
	@echo "Built netbench + tornado (minimal, no AF_XDP/BPF)"

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@cp -f $(TARGET) tornado 2>/dev/null || true

xdp_rst_filter.o: xdp_rst_filter.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

xdp_v15_hybrid.o: xdp_v15_hybrid.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

xdp_v15_stealth.o: xdp_v15_stealth.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

tc_rst_block.o: tc_rst_block.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(BPF_TARGETS)

