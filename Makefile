src = \
	src/pexplorer.c \
	src/pefile.c

obj = $(src:.c=.o)

CCFLAGS = -Wall

pexplorer: $(obj)
	$(CC) $(CCFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f $(obj) pexplorer
