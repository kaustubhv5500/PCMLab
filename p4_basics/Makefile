BUILD_DIR = build
PCAP_DIR = pcaps
SRC_FILE = switch_pipeline.p4

run: build
	sudo python3 mininet_topology.py

build:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR)
	p4c-bm2-ss --p4v 16 --p4runtime-files $(BUILD_DIR)/$(SRC_FILE:.p4=.p4info.txt) -o $(BUILD_DIR)/$(SRC_FILE:.p4=.json) $(SRC_FILE)

stop:
	sudo mn -c

clean: stop
	rm -rf $(BUILD_DIR) $(PCAP_DIR)
