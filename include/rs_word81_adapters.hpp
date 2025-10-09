// ============================================================================
// rs_word81_adapters.hpp
// ----------------------------------------------------------------------------
// Adapters for applying RS(GF27) parity protection to Word81⟷S63 secure
// containers, leveraging the generic facade from rs_facade_gf27.hpp.
// - Packing/unpacking at GF(27) symbol granularity (1 symbol = 3 trits).
// - Clear separation of what is protected (DATA, S63, BODY25) and where
//   parities are placed (Slack, Footer, Header) without altering header/footer
//   semantics unless explicitly requested.
// - Strict coding style, Doxygen documentation, and explicit constants.
// ----------------------------------------------------------------------------
// Dependencies:
//   • word81_s63_secure_container.hpp : Word81/S63 container and balanced trits
//   • rs_facade_gf27.hpp              : gf27::pack3/unpack3 and RSPlan/engine
// ----------------------------------------------------------------------------
// Author : (your project)
// License: Apache-2.0
// Version: 1.1
// ============================================================================

#pragma once

#include <array>
#include <vector>
#include <cstddef>
#include <cassert>

#include "word81_s63_secure_container.hpp"
#include "rs_facade_gf27.hpp"

namespace rsw81 {

// ---------------------------------------------------------------------------
// Constants & bookkeeping (symbol-level, 1 symbol = 3 trits)
// ---------------------------------------------------------------------------

/** Symbol constants for Word81 layout */
struct SymbolConst final {
  // Word81 layout in trits:
  //   Header : [0..2]         = 3 trits  = 1 symbol
  //   Body   : [3..65]        = 63 trits = 21 symbols  (S63 = 3×S21)
  //   Slack  : [66..77]       = 12 trits = 4 symbols
  //   Footer : [78..80]       = 3 trits  = 1 symbol

  // S63 sub-layout (by symbols):
  //   DATA   : first 13 symbols (39 trits)
  //   INLINE : next   8 symbols (24 trits)
  static constexpr int kWord81TotalSymbols     = 27;
  static constexpr int kHeaderSymbols          = 1;
  static constexpr int kFooterSymbols          = 1;
  static constexpr int kS63Symbols             = 21;
  static constexpr int kS63DataBeginSym        = 0;
  static constexpr int kS63DataCountSym        = 13;
  static constexpr int kS63InlineBeginSym      = 13;
  static constexpr int kS63InlineCountSym      = 8;
  static constexpr int kSlackSymbols           = 4;

  // Trit offsets (absolute) for each region
  static constexpr int kHeaderTritBegin        = 0;
  static constexpr int kBodyTritBegin          = 3;
  static constexpr int kBodyTritEndExclusive   = 66; // 3 + 63
  static constexpr int kSlackTritBegin         = 66;
  static constexpr int kSlackTritEndExclusive  = 78; // 66 + 12
  static constexpr int kFooterTritBegin        = 78;
  static constexpr int kFooterTritEndExclusive = 81;

  // Sanity
  static_assert(kS63DataCountSym + kS63InlineCountSym == kS63Symbols,
                "S63 symbol partition mismatch");
  static_assert((kBodyTritEndExclusive - kBodyTritBegin) == 63, "S63 size mismatch");
  static_assert((kSlackTritEndExclusive - kSlackTritBegin) == 12, "Slack size mismatch");
};

/** Small helpers for trit/symbol conversions */
struct TritSym final {
  static constexpr int kTritsPerSymbol = 3;

  /// @return absolute trit offset in Word81 given a symbol index relative to S63
  static constexpr int body_symbol_to_trit(int s63_symbol_index) noexcept {
    return SymbolConst::kBodyTritBegin + (s63_symbol_index * kTritsPerSymbol);
  }
  /// @return absolute trit offset in Word81 given a symbol index relative to Slack
  static constexpr int slack_symbol_to_trit(int slack_symbol_index) noexcept {
    return SymbolConst::kSlackTritBegin + (slack_symbol_index * kTritsPerSymbol);
  }
};

// ---------------------------------------------------------------------------
// Placement policy for parities
// ---------------------------------------------------------------------------

/**
 * @brief Where to store parity symbols, in decreasing order of preference.
 *        - SlackFirstFooterThenHeader: Slack (up to 4), then Footer, then Header.
 *        - FooterHeaderOnly          : Footer then Header (no Slack).
 *        - SlackOnly                 : Slack only (errors if P > 4).
 */
enum class ParityPlacement : uint8_t {
  SlackFirstFooterThenHeader,
  FooterHeaderOnly,
  SlackOnly
};

// ---------------------------------------------------------------------------
// Internal packing utilities (balanced ternary → GF(27) symbol)
// ---------------------------------------------------------------------------

/**
 * @brief Pack 3 balanced trits at absolute offset t into a GF(27) symbol.
 * @pre t, t+1, t+2 must be valid trit indices inside Word81::v.
 */
inline gf27::sym_t pack3_at(const word81::Word81& w, int t) noexcept {
  using ternary::trit_t;
  const trit_t* base = &w.v[t];
  return gf27::pack3(base[0], base[1], base[2]);
}

/**
 * @brief Unpack a GF(27) symbol into 3 balanced trits at absolute offset t.
 * @pre t, t+1, t+2 must be valid trit indices inside Word81::v.
 */
inline void unpack3_at(word81::Word81& w, int t, gf27::sym_t s) noexcept {
  auto tri = gf27::unpack3(s);
  w.v[t+0] = tri[0];
  w.v[t+1] = tri[1];
  w.v[t+2] = tri[2];
}

// ---------------------------------------------------------------------------
// Extraction of symbol streams from S63 and Slack
// ---------------------------------------------------------------------------

/**
 * @brief Extract all 21 S63 symbols (DATA+INLINE) from Word81 body.
 * @param w   Word81 container
 * @param out Filled with S63 symbols in-order [0..20]
 */
inline void extract_s63_symbols(const word81::Word81& w,
                                std::array<gf27::sym_t, SymbolConst::kS63Symbols>& out) noexcept {
  for (int s = 0; s < SymbolConst::kS63Symbols; ++s) {
    const int t = TritSym::body_symbol_to_trit(s);
    out[static_cast<std::size_t>(s)] = pack3_at(w, t);
  }
}

/**
 * @brief Extract Slack symbols (4) from Word81 slack region.
 * @param w   Word81 container
 * @param out Filled with slack symbols in-order [0..3]
 */
inline void extract_slack_symbols(const word81::Word81& w,
                                  std::array<gf27::sym_t, SymbolConst::kSlackSymbols>& out) noexcept {
  for (int s = 0; s < SymbolConst::kSlackSymbols; ++s) {
    const int t = TritSym::slack_symbol_to_trit(s);
    out[static_cast<std::size_t>(s)] = pack3_at(w, t);
  }
}

// ---------------------------------------------------------------------------
// Parity write helpers (Slack / Footer / Header)
// ---------------------------------------------------------------------------

/**
 * @brief Write up to 4 parity symbols into Slack (overwriting existing slack).
 * @param w        Word81 container
 * @param par      pointer to parity symbols
 * @param count    number of parity symbols to write (0..4)
 * @return number of symbols actually written
 */
inline int write_parities_into_slack(word81::Word81& w,
                                     const gf27::sym_t* par,
                                     int count) noexcept {
  const int n = (count < 0 ? 0 : (count > SymbolConst::kSlackSymbols ? SymbolConst::kSlackSymbols : count));
  for (int s = 0; s < n; ++s) {
    const int t = TritSym::slack_symbol_to_trit(s);
    unpack3_at(w, t, par[s]);
  }
  return n;
}

/** @brief Write exactly one parity symbol into Footer (3 trits). */
inline void write_one_parity_into_footer(word81::Word81& w, gf27::sym_t p) noexcept {
  unpack3_at(w, SymbolConst::kFooterTritBegin, p);
}

/** @brief Write exactly one parity symbol into Header (3 trits). */
inline void write_one_parity_into_header(word81::Word81& w, gf27::sym_t p) noexcept {
  unpack3_at(w, SymbolConst::kHeaderTritBegin, p);
}

// ---------------------------------------------------------------------------
// Core encoding (generic on RSEngine)
// ---------------------------------------------------------------------------

/**
 * @brief Encode parity for the first 13 symbols (DATA) of S63 and place them.
 *
 * DATA = 13 symbols extracted from S63 (symbols 0..12). INLINE untouched.
 *
 * @tparam RSEngine  RS engine type with signature:
 *                   void encode(const RSPlan&, const gf27::sym_t* data, gf27::sym_t* parity) const;
 * @param  w         Word81 container (parities are written back into regions chosen by 'place')
 * @param  P         Number of parity symbols to generate (0..6) — Slack(4) + Footer(1) + Header(1)
 * @param  place     Parity placement policy (default: Slack → Footer → Header)
 * @param  eng       RS engine instance (default: DummyRSEngine)
 *
 * @note   RS code is RS(13+P, 13). Correction capability t = floor(P/2).
 */
template<class RSEngine = DummyRSEngine>
inline void protect_DATA_symbols(word81::Word81& w,
                                 int P,
                                 ParityPlacement place = ParityPlacement::SlackFirstFooterThenHeader,
                                 const RSEngine& eng = RSEngine{}) {
  assert(P >= 0 && P <= 6 && "P out of supported range [0..6]");

  // 1) Extract DATA symbols 0..12 from S63
  std::array<gf27::sym_t, SymbolConst::kS63Symbols> s63{};
  extract_s63_symbols(w, s63);

  std::array<gf27::sym_t, SymbolConst::kS63DataCountSym> data{};
  for (int i = 0; i < SymbolConst::kS63DataCountSym; ++i) {
    data[static_cast<std::size_t>(i)] = s63[static_cast<std::size_t>(SymbolConst::kS63DataBeginSym + i)];
  }

  // 2) RS encode
  RSPlan plan; plan.k = SymbolConst::kS63DataCountSym; plan.parities = P;
  std::vector<gf27::sym_t> par(static_cast<std::size_t>(P > 0 ? P : 1));
  if (P > 0) eng.encode(plan, data.data(), par.data());

  // 3) Place parities
  int remaining = P, idx = 0;

  if (place == ParityPlacement::SlackFirstFooterThenHeader || place == ParityPlacement::SlackOnly) {
    const int wrote = write_parities_into_slack(w, par.data() + idx, remaining);
    idx += wrote; remaining -= wrote;
    if (place == ParityPlacement::SlackOnly) { assert(remaining == 0 && "SlackOnly cannot store more than 4 parities"); return; }
  }

  if (place == ParityPlacement::SlackFirstFooterThenHeader || place == ParityPlacement::FooterHeaderOnly) {
    if (remaining > 0) { write_one_parity_into_footer(w, par[static_cast<std::size_t>(idx++)]); --remaining; }
    if (remaining > 0) { write_one_parity_into_header(w, par[static_cast<std::size_t>(idx++)]); --remaining; }
    assert(remaining == 0 && "Not enough destinations to place all parities");
  }
}

/**
 * @brief Encode parity for all 21 S63 symbols (DATA+INLINE) and place them.
 *
 * S63 = DATA(13) || INLINE(8), both protected. Header/Footer left intact by default.
 *
 * @tparam RSEngine  RS engine type (see protect_DATA_symbols)
 * @param  w         Word81 container
 * @param  P         Number of parity symbols to generate (0..6)
 * @param  place     Placement policy
 * @param  eng       RS engine instance
 *
 * @note   RS code is RS(21+P, 21). Correction capability t = floor(P/2).
 */
template<class RSEngine = DummyRSEngine>
inline void protect_S63_symbols(word81::Word81& w,
                                int P,
                                ParityPlacement place = ParityPlacement::SlackFirstFooterThenHeader,
                                const RSEngine& eng = RSEngine{}) {
  assert(P >= 0 && P <= 6 && "P out of supported range [0..6]");

  // 1) Extract full S63 (21 symbols)
  std::array<gf27::sym_t, SymbolConst::kS63Symbols> s63{};
  extract_s63_symbols(w, s63);

  // 2) RS encode
  RSPlan plan; plan.k = SymbolConst::kS63Symbols; plan.parities = P;
  std::vector<gf27::sym_t> par(static_cast<std::size_t>(P > 0 ? P : 1));
  if (P > 0) eng.encode(plan, s63.data(), par.data());

  // 3) Place parities
  int remaining = P, idx = 0;

  if (place == ParityPlacement::SlackFirstFooterThenHeader || place == ParityPlacement::SlackOnly) {
    const int wrote = write_parities_into_slack(w, par.data() + idx, remaining);
    idx += wrote; remaining -= wrote;
    if (place == ParityPlacement::SlackOnly) { assert(remaining == 0 && "SlackOnly cannot store more than 4 parities"); return; }
  }

  if (place == ParityPlacement::SlackFirstFooterThenHeader || place == ParityPlacement::FooterHeaderOnly) {
    if (remaining > 0) { write_one_parity_into_footer(w, par[static_cast<std::size_t>(idx++)]); --remaining; }
    if (remaining > 0) { write_one_parity_into_header(w, par[static_cast<std::size_t>(idx++)]); --remaining; }
    assert(remaining == 0 && "Not enough destinations to place all parities");
  }
}

/**
 * @brief Encode parity for the 25 BODY symbols (S63 + Slack), leaving H/F intact.
 *
 * BODY25 = S63(21) || Slack(4). This protects the entire payload-bearing body,
 * while header/footer remain readable. Parities must then be stored out of BODY,
 * hence the maximum P is 2 (Footer + Header).
 *
 * @tparam RSEngine  RS engine type (see protect_DATA_symbols)
 * @param  w         Word81 container
 * @param  P         Number of parity symbols (0..2) (Footer+Header)
 * @param  eng       RS engine instance
 *
 * @note   RS code is RS(25+P, 25). Correction capability t = floor(P/2).
 * @warning Slack content is part of the protected vector, but parity is stored
 *          outside BODY (Footer/Header). If you want a fully systematic code
 *          into Slack as well, predefine how Slack is re-serialized.
 */
template<class RSEngine = DummyRSEngine>
inline void protect_BODY25_symbols(word81::Word81& w,
                                   int P,
                                   const RSEngine& eng = RSEngine{}) {
  assert(P >= 0 && P <= 2 && "BODY25 can only place up to 2 parities (Footer+Header)");

  // 1) Extract S63 + Slack (25 symbols)
  std::array<gf27::sym_t, SymbolConst::kS63Symbols> s63{};
  extract_s63_symbols(w, s63);

  std::array<gf27::sym_t, SymbolConst::kSlackSymbols> slk{};
  extract_slack_symbols(w, slk);

  std::array<gf27::sym_t, 25> body{};
  for (int i = 0; i < SymbolConst::kS63Symbols; ++i) body[static_cast<std::size_t>(i)] = s63[static_cast<std::size_t>(i)];
  for (int i = 0; i < SymbolConst::kSlackSymbols; ++i) body[static_cast<std::size_t>(SymbolConst::kS63Symbols + i)] = slk[static_cast<std::size_t>(i)];

  // 2) RS encode
  RSPlan plan; plan.k = 25; plan.parities = P;
  std::vector<gf27::sym_t> par(static_cast<std::size_t>(P > 0 ? P : 1));
  if (P > 0) eng.encode(plan, body.data(), par.data());

  // 3) Place parities strictly outside BODY: Footer → Header
  int remaining = P, idx = 0;
  if (remaining > 0) { write_one_parity_into_footer(w, par[static_cast<std::size_t>(idx++)]); --remaining; }
  if (remaining > 0) { write_one_parity_into_header(w, par[static_cast<std::size_t>(idx++)]); --remaining; }
  assert(remaining == 0 && "BODY25 has only Footer+Header available for parity");
}

} // namespace rsw81
