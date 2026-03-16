LD = g++

BUILD = bin
COMMON = common
MLSPP = mlspp
MODIFIED_MLSPP = mlspp-attacker

CXXFLAGS += -I$(MLSPP)/include \
	-I$(MLSPP)/lib/bytes/include \
	-I$(MLSPP)/lib/tls_syntax/include \
	-I$(MLSPP)/lib/hpke/include \
	-I$(MLSPP)/build/include \
	-I$(COMMON) \
	-Icentral-delivery-service \
	-std=c++20
LDFLAGS += $(MLSPP)/build/libmlspp.a \
	$(MLSPP)/build/lib/*/*.a \
	-lssl -lcrypto

M_CXXFLAGS += -I$(MODIFIED_MLSPP)/include \
	-I$(MODIFIED_MLSPP)/lib/bytes/include \
	-I$(MODIFIED_MLSPP)/lib/tls_syntax/include \
	-I$(MODIFIED_MLSPP)/lib/hpke/include \
	-I$(MODIFIED_MLSPP)/build/include \
	-I$(COMMON) \
	-Icentral-delivery-service \
	-std=c++20
M_LDFLAGS += $(MODIFIED_MLSPP)/build/libmlspp.a \
	$(MODIFIED_MLSPP)/build/lib/*/*.a \
	-lssl -lcrypto

ifdef DEBUG
	CXXFLAGS += -g -DPRINT
else
	CXXFLAGS += -O3
endif

all: $(BUILD)/delivery_service $(BUILD)/pki $(BUILD)/centralized_client $(BUILD)/attacker $(BUILD)/ds_aware_client $(BUILD)/welcome_attack_trace

$(BUILD):
	mkdir -p $(BUILD)/

$(MLSPP):
	git clone --recursive https://github.com/cisco/mlspp.git
	cd $(MLSPP) && git checkout c13d725e6cce923f66496ecc3c43d5d3cd831ec2 && make cclean && make dev3 && make

$(BUILD)/pki: simplified-pki/pki.cpp | $(BUILD)
	$(LD) $< -I$(COMMON) -o $@

$(BUILD)/delivery_service: central-delivery-service/delivery_service.cpp | $(MLSPP) $(BUILD)
	$(LD) $< $(CXXFLAGS) $(LDFLAGS) -o $@

$(BUILD)/centralized_client: centralized-client/centralized_client.cpp centralized-client/centralized_ds_interface.hpp | $(MLSPP) $(BUILD)
	$(LD) $< $(CXXFLAGS) $(LDFLAGS) -o $@

$(MODIFIED_MLSPP): | $(MLSPP)
	cp -r $(MLSPP) $(MODIFIED_MLSPP)
	cd $(MODIFIED_MLSPP) && git apply ../mlspp-invalid-proposal-ref.patch && make cclean && make dev3 && make

$(BUILD)/attacker: attacker/centralized_client.cpp attacker/centralized_ds_interface.hpp attacker/malicious_client.hpp | $(MODIFIED_MLSPP) $(BUILD)
	$(LD) $< $(M_CXXFLAGS) $(M_LDFLAGS) -o $@

$(BUILD)/ds_aware_client: ds-aware-client/centralized_client.cpp ds-aware-client/centralized_ds_interface.hpp | $(MLSPP) $(BUILD)
	$(LD) $< $(CXXFLAGS) $(LDFLAGS) -o $@

$(BUILD)/welcome_attack_trace: welcome-attack-trace/main.cpp | $(MLSPP) $(BUILD)
	$(LD) $< $(CXXFLAGS) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf $(BUILD) $(MLSPP) $(MODIFIED_MLSPP)
