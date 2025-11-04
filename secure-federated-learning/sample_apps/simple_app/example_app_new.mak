#    File: example_app.mak



# CERTIFIER_ROOT will be certifier-framework-for-confidential-computing/ dir
CERTIFIER_ROOT = ../..

ifndef OBJ_DIR
OBJ_DIR=.
endif
ifndef EXE_DIR
EXE_DIR=.
endif
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

CP = $(CERTIFIER_ROOT)/certifier_service/certprotos
S= $(CERTIFIER_ROOT)/src
O= $(OBJ_DIR)
US=.
I= $(CERTIFIER_ROOT)/include
INCLUDE= -I. -I$(I) -I/usr/local/opt/openssl@1.1/include/ -I$(S)/sev-snp/
COMMON_SRC = $(CERTIFIER_ROOT)/sample_apps/common

# Added bioinformatics proto path
BIOINFO_PROTO = .

# Compilation flags
CFLAGS_NOERROR=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CFLAGS = $(CFLAGS_NOERROR) -Werror -DSIMPLE_APP
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64 -Wno-deprecated-declarations
CC=g++
LINK=g++
PROTO=protoc
AR=ar
LDFLAGS= -L $(LOCAL_LIB) -lprotobuf -lgtest -lgflags -lpthread -L/usr/local/opt/openssl@1.1/lib/ -lcrypto -lssl

# Added bioinformatics proto objects
dobj = $(O)/example_app.o $(O)/certifier.pb.o $(O)/bioinformatics.pb.o $(O)/certifier.o \
	$(O)/certifier_proofs.o $(O)/support.o $(O)/simulated_enclave.o \
	$(O)/application_enclave.o $(O)/cc_helpers.o $(O)/cc_useful.o

robj = $(O)/example_key_rotation.o $(O)/certifier.pb.o $(O)/certifier.o $(O)/certifier_proofs.o \
	$(O)/support.o $(O)/simulated_enclave.o $(O)/application_enclave.o $(O)/cc_helpers.o \
	$(O)/cc_useful.o

all:    example_app.exe example_key_rotation.exe
clean:
	@echo "removing generated files"
	rm -rf $(US)/certifier.pb.cc $(US)/certifier.pb.h $(I)/certifier.pb.h
	rm -rf $(US)/bioinformatics.pb.cc $(US)/bioinformatics.pb.h
	@echo "removing object files"
	rm -rf $(O)/*.o
	@echo "removing executable file"
	rm -rf $(EXE_DIR)/example_app.exe $(EXE_DIR)/example_key_rotation.exe

$(EXE_DIR)/example_app.exe: $(dobj)
	@echo "\nlinking executable $@"
	$(LINK) $(dobj) $(LDFLAGS) -o $(@D)/$@

$(EXE_DIR)/example_key_rotation.exe: $(robj)
	@echo "\nlinking executable $@"
	$(LINK) $(robj) $(LDFLAGS) -o $(@D)/$@

$(I)/certifier.pb.h: $(US)/certifier.pb.cc
$(US)/certifier.pb.cc: $(CP)/certifier.proto
	$(PROTO) --proto_path=$(<D) --cpp_out=$(@D) $<
	mv $(@D)/certifier.pb.h $(I)

# Added bioinformatics proto generation
$(US)/bioinformatics.pb.cc: $(BIOINFO_PROTO)/bioinformatics.proto
	$(PROTO) --proto_path=$(<D) --cpp_out=$(@D) $<

$(O)/bioinformatics.pb.o: $(US)/bioinformatics.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS_NOERROR) -o $(@D)/$@ -c $<

$(O)/certifier.pb.o: $(US)/certifier.pb.cc $(I)/certifier.pb.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS_NOERROR) -o $(@D)/$@ -c $<

$(O)/example_app.o: $(COMMON_SRC)/example_app.cc $(I)/certifier.h $(US)/certifier.pb.cc $(US)/bioinformatics.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/example_key_rotation.o: $(US)/example_key_rotation.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier.o: $(S)/certifier.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/certifier_proofs.o: $(S)/certifier_proofs.cc $(I)/certifier.pb.h $(I)/certifier.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/support.o: $(S)/support.cc $(I)/support.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/simulated_enclave.o: $(S)/simulated_enclave.cc $(I)/simulated_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/application_enclave.o: $(S)/application_enclave.cc $(I)/application_enclave.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_helpers.o: $(S)/cc_helpers.cc $(I)/certifier.h $(US)/certifier.pb.cc
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<

$(O)/cc_useful.o: $(S)/cc_useful.cc $(I)/cc_useful.h
	@echo "\ncompiling $<"
	$(CC) $(CFLAGS) -o $(@D)/$@ -c $<