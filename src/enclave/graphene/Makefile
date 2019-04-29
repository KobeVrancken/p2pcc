manifests = $(patsubst %.template,%,$(wildcard *.manifest.template))

target = cc1.token ld.token collect2.token as.token gcc.token clangnomod.token distccd.token
#la_wrapper_run.tokenclang-daemon.token distccd.token 

.PHONY: checkpath
checkpath:
ifdef GRAPHENE_PATH
	@echo "${GRAPHENE_PATH}"
else
	$(error GRAPHENE_PATH is not set)
endif

.PHONY: default
default: all

.PHONY: all
all: checkpath $(target)



RUNTIME = ${GRAPHENE_PATH}/Runtime
SIGNER = ${GRAPHENE_PATH}/Pal/src/host/Linux-SGX/signer/

huge_rule = sys.stack.size = 64M\nsys.brk.size = 256M\nglibc.heap_size = 16M\nsgx.enclave_size = 2G

manifest_rules = \
	-e 's:\$$(PAL):$(abspath $(RUNTIME))/pal-Linux-SGX:g' \
	-e 's:\$$(PWD):$(PWD):g' \
	-e 's:\$$(BIN):$(subst .manifest,,$(notdir $@)):g' \
	-e 's:\$$(SHIMPATH):$(abspath $(RUNTIME))/libsysdb.so:g' \
	-e 's:\$$(LIBCDIR):$(abspath $(RUNTIME)):g' \
        -e 's:\$$(DEBUGTYPE):$(if $(DEBUG),inline,none):g' \
        -e 's:\$$(GCCDIR):$(patsubst %/cc1,%,$(shell gcc -print-file-name=cc1)):g' \
        -e 's:\$$(HUGERULE):$(if $(HUGE),$(huge_rule),):g'
relative-to = $(shell python -c "import os.path; print os.path.relpath(\"$(abspath $2)\",\"$(abspath $1)\")")


%token: %manifest.sgx
	${SIGNER}/pal-sgx-get-token -output $@ -sig $(basename $(basename $<)).sig


.PRECIOUS: %manifest.sgx
%manifest.sgx: %manifest
	${SIGNER}/pal-sgx-sign -libpal ${GRAPHENE_PATH}/Runtime/libpal-Linux-SGX.so -key ${SIGNER}/enclave-key.pem -output $@ -manifest $<

%manifest: %manifest.template
	@echo [ $@ ]
	RELDIR=$(filter-out ./,$(call relative-to,$(dir $@),$(shell pwd))/) && \
	sed $(manifest_rules) $< > $@
	(grep -q '^#!' $@ && chmod +x $@) || true

manifest: manifest.template
	@echo [ $@ ]
	sed $(manifest_rules) $< > $@

.PHONY: clean
clean: 
	rm -rf *.sgx *.sig *.token *.manifest
