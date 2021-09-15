# build all programs with names like `membug[0-9]`
DSPROGRAMS = $(patsubst %.cc,%,$(wildcard membug[0-9].cc membug[0-9][0-9].cc l[0-9].cc l[0-9][0-9].cc))
PROGRAMS = $(DSPROGRAMS) greet1 accessor inserter
all: $(PROGRAMS)

ALLPROGRAMS = $(PROGRAMS) inv testinsert0 greet1

include ../common/rules.mk

LIBS = -lm


# Rules for making object files (i.e., parts of executables)
# from source files

%.o: %.cc $(BUILDSTAMP)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPCFLAGS) $(O) -o $@ -c $<


# Rules for making executables (runnable programs) from object files

membug%: membug%.o hexdump.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(O) -o $@ $^ $(LIBS)

l1 l2 l3 l4 l5 l6 l7 l8 l9 l10 l11 greet1 accessor inserter: \
%: %.o hexdump.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(O) -o $@ $^ $(LIBS)


clean:
	rm -rf $(ALLPROGRAMS) *.o $(DEPSDIR)

.PHONY: all clean
