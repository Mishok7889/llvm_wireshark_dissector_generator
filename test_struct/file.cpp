#include <cstdint>

enum class D { AA, BB, CC };

struct C
{
  int a;
  //bool b;
  D dd;
};

struct B {
  int A;
  long B;
  char D[32];
  C cc;
};

struct A {
  uint8_t magic;
  D df : 3;
  D de : 3;
  D dt : 2;
  D dff;
  int a;
  int b;
  B bb;
};

struct TrivialA
{
  char a;
  int b;
  long c;
  uint64_t l;

  D df;

  B bbb;

  uint8_t aaa[10];
};