// ============================================================================
// test_rsw81_hardened.cpp
// Hardened tests for rs_word81_adapters.hpp on Word81⟷S63 containers.
//
// Build (exemple):
//   c++ -std=c++20 -O2 -DUNIT_TEST_RSW81 \
//       test_rsw81_hardened.cpp -o test_rsw81
//
// Prérequis (dans l'include path):
//   - word81_s63_secure_container.hpp
//   - rs_facade_gf27.hpp
//   - rs_word81_adapters.hpp
// ============================================================================

#include <cassert>
#include <iostream>
#include <random>
#include <vector>
#include <array>

#include "word81_s63_secure_container.hpp"
#include "rs_facade_gf27.hpp"
#include "rs_word81_adapters.hpp"

using ternary::trit_t;

// -----------------------------------------------------------------------------
// Moteur RS de test (déterministe, interface-compatible)
//
// encode(plan, data[k], parity[P]) remplit parity[i] = (S + i) mod 27
// où S = somme des data symbols (0..26). Ce n'est PAS un RS réel, mais
// son déterminisme permet de vérifier que le placement écrit bien ce qui est
// demandé là où on l'attend (Slack/Footer/Header), sans ambiguïté.
// -----------------------------------------------------------------------------
struct TestRSEngine {
  void encode(const RSPlan& plan, const gf27::sym_t* data, gf27::sym_t* parity) const {
    int S = 0;
    for (int i = 0; i < plan.k; ++i) {
      S += static_cast<int>(data[i] % 27);
    }
    S %= 27;
    for (int p = 0; p < plan.parities; ++p) {
      parity[p] = static_cast<gf27::sym_t>((S + p) % 27);
    }
  }
};

// -----------------------------------------------------------------------------
// Helpers : lire un symbole GF(27) exact aux offsets Header/Footer/Slack
// -----------------------------------------------------------------------------
static gf27::sym_t read_header_symbol(const word81::Word81& w) {
  return gf27::pack3(w.v[0], w.v[1], w.v[2]);
}
static gf27::sym_t read_footer_symbol(const word81::Word81& w) {
  return gf27::pack3(w.v[78], w.v[79], w.v[80]);
}
static std::array<gf27::sym_t,4> read_slack_symbols(const word81::Word81& w) {
  std::array<gf27::sym_t,4> out{};
  for (int s=0; s<4; ++s) {
    int t = 66 + 3*s;
    out[static_cast<std::size_t>(s)] = gf27::pack3(w.v[t+0], w.v[t+1], w.v[t+2]);
  }
  return out;
}

// Initialise un Word81 avec S63 déterministe, Header/Footer à zéro, Slack à 0..3
static word81::Word81 make_deterministic_word81() {
  word81::Word81 w{};
  // Header = (0,0,0)
  w.v[0] = w.v[1] = w.v[2] = ternary::ZER;
  // Body S63 : motif périodique -1,0,+1 (facile à recomposer)
  for (int i = 3; i < 66; ++i) {
    int mod = (i-3) % 3;
    w.v[i] = (mod==0? ternary::NEG : (mod==1? ternary::ZER : ternary::POS));
  }
  // Slack : quatre symboles distincts (0→(0,0,0), 1→(0,0,+1), 2→(0,+1,0), 3→(+1,0,0))
  const ternary::trit_t lut[4][3] = {
    {ternary::ZER, ternary::ZER, ternary::ZER},
    {ternary::ZER, ternary::ZER, ternary::POS},
    {ternary::ZER, ternary::POS, ternary::ZER},
    {ternary::POS, ternary::ZER, ternary::ZER}
  };
  for (int s=0; s<4; ++s) {
    int t = 66 + 3*s;
    w.v[t+0] = lut[s][0];
    w.v[t+1] = lut[s][1];
    w.v[t+2] = lut[s][2];
  }
  // Footer = (0,0,0)
  w.v[78] = w.v[79] = w.v[80] = ternary::ZER;
  return w;
}

// Somme des 13 symbols DATA (S63[0..12]) pour reproduire l’attendu du moteur
static int sum_DATA_symbols_mod27(const word81::Word81& w) {
  int S = 0;
  for (int s=0; s<13; ++s) {
    int t = 3 + 3*s;
    S += gf27::pack3(w.v[t+0], w.v[t+1], w.v[t+2]);
  }
  return S % 27;
}

// Somme des 21 symbols S63 (DATA+INLINE) mod 27
static int sum_S63_symbols_mod27(const word81::Word81& w) {
  int S = 0;
  for (int s=0; s<21; ++s) {
    int t = 3 + 3*s;
    S += gf27::pack3(w.v[t+0], w.v[t+1], w.v[t+2]);
  }
  return S % 27;
}

// BODY25 = S63(21) + Slack(4)
static int sum_BODY25_symbols_mod27(const word81::Word81& w) {
  int S = sum_S63_symbols_mod27(w);
  auto slk = read_slack_symbols(w);
  for (auto v : slk) S += static_cast<int>(v);
  return S % 27;
}

// -----------------------------------------------------------------------------
// TEST 1 — protect_DATA_symbols : P=4, placement SlackFirstFooterThenHeader
//  → attendu : les 4 parités vont intégralement dans le Slack, H/F intacts.
// -----------------------------------------------------------------------------
static void test_protect_DATA_P4_slack_first() {
  TestRSEngine eng;
  auto w = make_deterministic_word81();

  const auto H_before = read_header_symbol(w);
  const auto F_before = read_footer_symbol(w);
  const auto SL_before = read_slack_symbols(w);

  const int S = sum_DATA_symbols_mod27(w);
  std::array<gf27::sym_t,4> par_expect{};
  for (int i=0;i<4;++i) par_expect[static_cast<std::size_t>(i)] = static_cast<gf27::sym_t>((S + i) % 27);

  rsw81::protect_DATA_symbols<TestRSEngine>(w, /*P=*/4,
        rsw81::ParityPlacement::SlackFirstFooterThenHeader, eng);

  const auto H_after = read_header_symbol(w);
  const auto F_after = read_footer_symbol(w);
  const auto SL_after = read_slack_symbols(w);

  // Header/Footer doivent être inchangés
  assert(H_before == H_after);
  assert(F_before == F_after);

  // Slack doit contenir exactement les 4 parités attendues
  for (int i=0;i<4;++i) {
    assert(SL_after[static_cast<std::size_t>(i)] == par_expect[static_cast<std::size_t>(i)]);
  }
}

// -----------------------------------------------------------------------------
// TEST 2 — protect_S63_symbols : P=6, placement SlackFirstFooterThenHeader
//  → attendu : 4 parités dans Slack, 1 en Footer, 1 en Header.
// -----------------------------------------------------------------------------
static void test_protect_S63_P6_slack_first() {
  TestRSEngine eng;
  auto w = make_deterministic_word81();

  const int S = sum_S63_symbols_mod27(w);
  std::array<gf27::sym_t,6> par_expect{};
  for (int i=0;i<6;++i) par_expect[static_cast<std::size_t>(i)] = static_cast<gf27::sym_t>((S + i) % 27);

  rsw81::protect_S63_symbols<TestRSEngine>(w, /*P=*/6,
        rsw81::ParityPlacement::SlackFirstFooterThenHeader, eng);

  const auto SL = read_slack_symbols(w);
  const auto F  = read_footer_symbol(w);
  const auto H  = read_header_symbol(w);

  // Slack : par[0..3]
  for (int i=0;i<4;++i) {
    assert(SL[static_cast<std::size_t>(i)] == par_expect[static_cast<std::size_t>(i)]);
  }
  // Footer : par[4]
  assert(F == par_expect[4]);
  // Header : par[5]
  assert(H == par_expect[5]);
}

// -----------------------------------------------------------------------------
// TEST 3 — protect_DATA_symbols : P=4, placement SlackOnly
//  → attendu : 4 parités dans Slack, H/F restent intacts, aucune erreur.
// -----------------------------------------------------------------------------
static void test_protect_DATA_P4_slack_only() {
  TestRSEngine eng;
  auto w = make_deterministic_word81();

  const auto H_before = read_header_symbol(w);
  const auto F_before = read_footer_symbol(w);

  const int S = sum_DATA_symbols_mod27(w);
  std::array<gf27::sym_t,4> par_expect{};
  for (int i=0;i<4;++i) par_expect[static_cast<std::size_t>(i)] = static_cast<gf27::sym_t>((S + i) % 27);

  rsw81::protect_DATA_symbols<TestRSEngine>(w, /*P=*/4,
        rsw81::ParityPlacement::SlackOnly, eng);

  const auto SL = read_slack_symbols(w);
  const auto H  = read_header_symbol(w);
  const auto F  = read_footer_symbol(w);

  // Slack : par[0..3]
  for (int i=0;i<4;++i) {
    assert(SL[static_cast<std::size_t>(i)] == par_expect[static_cast<std::size_t>(i)]);
  }
  // H/F inchangés
  assert(H == H_before);
  assert(F == F_before);
}

// -----------------------------------------------------------------------------
// TEST 4 — protect_BODY25_symbols : P=2 (max), Footer puis Header
//  → attendu : par[0] en Footer, par[1] en Header, Slack intact.
// -----------------------------------------------------------------------------
static void test_protect_BODY25_P2_footer_header() {
  TestRSEngine eng;
  auto w = make_deterministic_word81();

  const auto SL_before = read_slack_symbols(w);
  const int S = sum_BODY25_symbols_mod27(w);
  std::array<gf27::sym_t,2> par_expect{
    static_cast<gf27::sym_t>((S + 0) % 27),
    static_cast<gf27::sym_t>((S + 1) % 27)
  };

  rsw81::protect_BODY25_symbols<TestRSEngine>(w, /*P=*/2, eng);

  const auto SL_after = read_slack_symbols(w);
  const auto F  = read_footer_symbol(w);
  const auto H  = read_header_symbol(w);

  // Slack ne doit pas être modifié par BODY25 (parités hors BODY)
  for (int i=0;i<4;++i) {
    assert(SL_after[static_cast<std::size_t>(i)] == SL_before[static_cast<std::size_t>(i)]);
  }
  // Footer/Header reçoivent les 2 parités
  assert(F == par_expect[0]);
  assert(H == par_expect[1]);
}

// -----------------------------------------------------------------------------
// TEST 5 — Bornes & invariants simples
//  - P dans [0..6] pour DATA/S63
//  - P dans [0..2] pour BODY25 (on ne "crash" pas; ici on vérifie P=0)
// -----------------------------------------------------------------------------
static void test_bounds_and_noop() {
  TestRSEngine eng;
  auto w = make_deterministic_word81();

  // P=0 → no-op (rien n'écrit), on compare avant/après
  const auto SL0 = read_slack_symbols(w);
  const auto H0  = read_header_symbol(w);
  const auto F0  = read_footer_symbol(w);

  rsw81::protect_S63_symbols<TestRSEngine>(w, /*P=*/0,
        rsw81::ParityPlacement::SlackFirstFooterThenHeader, eng);

  const auto SL1 = read_slack_symbols(w);
  const auto H1  = read_header_symbol(w);
  const auto F1  = read_footer_symbol(w);

  for (int i=0;i<4;++i) assert(SL0[static_cast<std::size_t>(i)] == SL1[static_cast<std::size_t>(i)]);
  assert(H0 == H1);
  assert(F0 == F1);
}

// -----------------------------------------------------------------------------
// Runner
// -----------------------------------------------------------------------------
static int run_all() {
  test_protect_DATA_P4_slack_first();
  test_protect_S63_P6_slack_first();
  test_protect_DATA_P4_slack_only();
  test_protect_BODY25_P2_footer_header();
  test_bounds_and_noop();
  std::cout << "[OK] rs_word81_adapters hardened tests passed\n";
  return 0;
}

#ifdef UNIT_TEST_RSW81
int main() { return run_all(); }
#else
int main() {
  // Par défaut, on exécute quand même.
  return run_all();
}
#endif
