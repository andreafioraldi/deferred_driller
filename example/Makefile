AFL_PATH=~/afl/

all:
	clang -no-pie -fno-stack-protector -D__DRILLER test1.c ../driller_init.s -o test1_driller
	$(AFL_PATH)/afl-clang-fast -no-pie -fno-stack-protector test1.c -o test1_afl

musl:
	musl-gcc -no-pie -fno-stack-protector -D__DRILLER test1.c ../driller_init.s -o test1_driller
	$(AFL_PATH)/afl-clang-fast -no-pie -fno-stack-protector test1.c -o test1_afl

