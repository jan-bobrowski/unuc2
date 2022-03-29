# gmake

NAME = unuc2
VERSION = 0.6.2
BINDIR = /usr/local/bin

CFLAGS += -DNDEBUG -Os
CFLAGS += -g -Wall
$(O)libunuc2.o $(O)libunuc2.so: CFLAGS += -std=c99
$(O)unuc2.o: CFLAGS += -std=gnu99 -DVERSION=$(VERSION)

.PHONY: all
all: $(O)unuc2$(EXE)

$(O)libunuc2.a: $(O)libunuc2.o $(O)super.o
	$(AR) rs $@ $^

$(O)libunuc2.so: $(I)libunuc2.c $(O)super.o
	$(CC) -fpic -shared $(CFLAGS) $^ $(LDFLAGS) -o $@

$(O)libunuc2.o: $(I)libunuc2.c $(I)Makefile $(I)list.h $(I)libunuc2.h $(DEPS)
	$(CC) -c $(CFLAGS) $< -o $@

$(O)super.o: $(I)super.bin
	$(X)ld -r -b binary \
	 --defsym $(decorsym)uc2_supermaster_compressed=$(or $(supersym),_binary_super_bin)_start \
	 --defsym $(decorsym)uc2_supermaster_compressed_end=$(or $(supersym),_binary_super_bin)_end \
	 -o $@ $(I)super.bin

$(O)unuc2.o: $(I)unuc2.c $(I)Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(O)unuc2$(EXE): $(O)unuc2.o $(O)libunuc2.a
	$(CC) $^ $(LDFLAGS) -o $@

.PHONY: install
install: $(O)unuc2$(EXE)
	install -s $^ $(BINDIR)

.PHONY: clean
clean:
	$(RM) $(O)unuc2$(EXE) $(O)unuc2.o $(O)libunuc2.a $(O)libunuc2.so $(O)libunuc2.o $(O)super.o
	@$(CLEAN)
