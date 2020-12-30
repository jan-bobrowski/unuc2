# gmake

NAME = unuc2
VERSION = 0.1
BINDIR = /usr/local/bin

CFLAGS += -DNDEBUG -Os
CFLAGS += -g -Wall
$(O)libunuc2.o $(O)libunuc2.so: CFLAGS += -std=c99
$(O)unuc2.o: CFLAGS += -std=gnu99

.PHONY: all
all: $(O)unuc2$(EXE)

$(O)libunuc2.a: $(O)libunuc2.o $(O)super.o
	$(AR) rs $@ $^

$(O)libunuc2.so: libunuc2.c super.S
	$(CC) -fpic -shared $(CFLAGS) $^ $(LDFLAGS) -o $@

$(O)libunuc2.o: libunuc2.c Makefile list.h libunuc2.h $(DEPS)
	$(CC) $(CFLAGS) $< -c -o $@

$(O)super.o: super.S super.bin
	$(CC) $(CFLAGS) $< -c -o $@

$(O)unuc2$(EXE): $(O)unuc2.o $(O)libunuc2.a
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -DVERSION=$(VERSION) -o $@

$(O)unuc2.o: unuc2.c Makefile list.h libunuc2.h $(DEPS)
	$(CC) $(CFLAGS) $< -c -o $@

.PHONY: install
install: $(O)unuc2$(EXE)
	install -s $^ $(BINDIR)

.PHONY: clean
clean:
	rm -f $(O)unuc2$(EXE) $(O)unuc2.o $(O)libunuc2.a $(O)libunuc2.so $(O)libunuc2.o $(O)super.o
