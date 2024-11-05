OUT_DIR = dist
SRC_DIR = ./filters
CFLAGS = -O2 -g -target bpf -D__TARGET_BPF

all: $(OUT_DIR) mark ingress egress demangle

mark: $(OUT_DIR)/tc_mark.o

ingress: $(OUT_DIR)/tc_ingress.o

egress: $(OUT_DIR)/tc_egress.o

demangle: $(OUT_DIR)/xdp_demangle.o

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/%.o: $(SRC_DIR)/%.c
	clang $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OUT_DIR)/*.o
