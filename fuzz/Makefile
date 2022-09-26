
leaf-fuzzer: leaf-fuzzer.c ../leaf/leaf.cpp
	clang -g -fsanitize=fuzzer,address ../leaf/leaf.cpp leaf-fuzzer.c -o leaf-fuzzer