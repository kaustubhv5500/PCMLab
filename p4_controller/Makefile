BUILD_DIR = build
PCAP_DIR = pcaps
LOGS_DIR = logs
SRC_FILE = l3_forwarding.p4
TOPO_FILE = topology.json

run: build
	sudo python3 run_tutorial.py -t $(TOPO_FILE)

build:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOGS_DIR)
	p4c-bm2-ss --p4v 16 --p4runtime-files $(BUILD_DIR)/$(SRC_FILE:.p4=.p4info.txt) -o $(BUILD_DIR)/$(SRC_FILE:.p4=.json) $(SRC_FILE)

stop:
	sudo mn -c

clean: stop
	sudo rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOGS_DIR)