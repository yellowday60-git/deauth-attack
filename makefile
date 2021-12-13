LDLIBS=-lpcap

all: deauth-attack

deauth-attack: mac.o main.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o