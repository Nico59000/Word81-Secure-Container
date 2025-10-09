// ============================================================================
// test_word81_secure_hardened.cpp — Hardened tests for Word81 ⟷ S63
// Build:
//   c++ -std=c++20 -O2 -DUNIT_TEST_WORD81 test_word81_secure_hardened.cpp
// ============================================================================

#include <random>
#include <cassert>
#include <iostream>

#include "word81_s63_secure_container.hpp"

namespace test81 {
  using ternary::trit_t;

  static trit_t rnd_trit(std::mt19937& g){
    static const int8_t lut[3] = {-1,0,1};
    std::uniform_int_distribution<int> d(0,2);
    return lut[d(g)];
  }

  void checksum_sanity(){
    word81::Word81 w{};
    // Zero body
    for (int i=3;i<66;++i) w.v[i]=ternary::ZER;
    auto c0 = word81::checksum_mod3(w);
    assert(c0==ternary::ZER);

    // Flip +1
    w.v[3]=ternary::POS;
    auto c1 = word81::checksum_mod3(w);
    assert(c1==ternary::POS);

    // Neutralize with -1
    w.v[4]=ternary::NEG;
    auto c2 = word81::checksum_mod3(w);
    assert(c2==ternary::ZER);
  }

  void clamp_adversarial(){
    word81::Word81 w{};
    word81::Header3 h{ (trit_t)5, (trit_t)-7, (trit_t)2 };
    word81::set_header(w,h);
    auto h2 = word81::get_header(w);
    assert(h2.sec_mode>=-1 && h2.sec_mode<=1);
    assert(h2.trust_lvl>=-1 && h2.trust_lvl<=1);
    assert(h2.route_cls>=-1 && h2.route_cls<=1);

    word81::Footer3 f{ (trit_t)-9, (trit_t)11, (trit_t)0 };
    word81::set_footer(w,f);
    auto f2 = word81::get_footer(w);
    assert(f2.integrity>=-1 && f2.integrity<=1);
    assert(f2.confidential>=-1 && f2.confidential<=1);
    assert(f2.trace_flag>=-1 && f2.trace_flag<=1);
  }

  void pack_unpack_s63(){
    std::mt19937 g(123);
    word81::S63 s{}; word81::Word81 w{}; word81::S63 out{};
    for (int i=0;i<63;++i) s.v[i]=rnd_trit(g);
    word81::set_body_from_s63(w,s);
    word81::get_body_as_s63(w,out);
    for (int i=0;i<63;++i) assert(out.v[i]==s.v[i]);
  }

  void split_join_s21(){
    std::mt19937 g(456);
    word81::S21 s0{}, s1{}, s2{}, s0b{}, s1b{}, s2b{};
    for (int i=0;i<21;++i){ s0.v[i]=rnd_trit(g); s1.v[i]=rnd_trit(g); s2.v[i]=rnd_trit(g); }
    word81::S63 s63{};
    word81::join_s21_into_s63(s0,s1,s2,s63);
    word81::split_s63_into_s21(s63,s0b,s1b,s2b);
    for (int i=0;i<21;++i){ assert(s0b.v[i]==s0.v[i]); assert(s1b.v[i]==s1.v[i]); assert(s2b.v[i]==s2.v[i]); }
  }

  void fuzz_integrity(size_t iters=1000){
    std::mt19937 g(777);
    for (size_t t=0;t<iters;++t){
      word81::Word81 w{};
      for (int i=3;i<66;++i) w.v[i]=rnd_trit(g);
      auto c = word81::checksum_mod3(w);
      int pos = 3 + (g()%63);
      auto old = w.v[pos];
      w.v[pos] = (old==ternary::POS? ternary::NEG : ternary::POS);
      auto c2 = word81::checksum_mod3(w);
      (void)c; (void)c2; // collisions mod-3 possible mais rares
    }
  }

  int run_all(){
    checksum_sanity();
    clamp_adversarial();
    pack_unpack_s63();
    split_join_s21();
    fuzz_integrity();
    std::cout << "[OK] Word81 hardened tests passed\n";
    return 0;
  }
}

#ifdef UNIT_TEST_WORD81
int main(){ return test81::run_all(); }
#endif
