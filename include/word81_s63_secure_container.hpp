// ============================================================================
// Word81 ⟷ S63 Secure Container (balanced ternary)
// ----------------------------------------------------------------------------
// Spec & reference helpers to encapsulate 3×S21 (S63) into a fixed Word81
// container carrying a 3-trit header and a 3-trit footer for policy/routing/
// integrity signaling. Designed to mirror the Word27⟷S21 API, with identical
// semantics and adapter hooks.
//
// Layout (all counts in trits):
//   [Header 3] + [Body 63] + [Slack 12] + [Footer 3]  = 81
// Where Body = S63 = 3 × S21 = 3 × (13 data + 8 inline)
// Slack (12 trits) is reserved for higher-layer use (e.g., RS parities,
// aggregated contexts, policy shadow, etc.).
//
// Hooks:
//   - Header3 / Footer3 semantics are identical to Word27.
//   - Adapter namespace (word81_adapt) exposes encode_header / decode_header and
//     make_footer_default interop, compatible with security_policy.hpp and
//     security_route_helper.hpp (via the same mapping approach).
//
// Author: Nicolas B | License: Mit
// Version: 1.0
// ============================================================================

#pragma once

#include <cstdint>
#include <array>
#include <type_traits>

namespace ternary
{
using trit_t = int8_t;                    // must be -1, 0, +1
inline constexpr trit_t NEG = -1;
inline constexpr trit_t ZER =  0;
inline constexpr trit_t POS = +1;

inline constexpr trit_t clamp(trit_t t)   // enforce balanced domain
{
    return (t < -1) ? -1 : (t > 1 ? 1 : t);
}

// For GF(27) mapping support (3 trits -> 1 symbol) if desired upstream.
inline constexpr uint8_t to_unbalanced(trit_t t)
{
    return (t==NEG) ? 2u : (t==ZER ? 0u : 1u);
}
inline constexpr trit_t  to_balanced(uint8_t u)
{
    return (u==2u)  ? NEG : (u==0u ? ZER : POS);
}
}

namespace word81
{
using ternary::trit_t;

// ---------------------------
// Fixed-size ternary word 81
// ---------------------------
struct Word81
{
    std::array<trit_t,81> v{};
};

// ---------------------------
// Header (3 trits) semantics
// ---------------------------
struct Header3
{
    // {-1=open, 0=signed, +1=encrypted}
    trit_t sec_mode;

    // {-1=unverified, 0=standard, +1=verified}
    trit_t trust_lvl;

    // {-1=media, 0=telemetry, +1=control}
    trit_t route_cls;
};

// ---------------------------
// Footer (3 trits) semantics
// ---------------------------
struct Footer3
{
    // checksum mod-3 of Body (or RS syndrome proxy)
    trit_t integrity;

    // {-1=clear, 0=mixed, +1=encrypted}
    trit_t confidential;

    // {-1=none, 0=soft, +1=strong}
    trit_t trace_flag;
};

// ---------------------------
// S63 = 3 × S21 (21 trits)
// ---------------------------
struct S21
{
    std::array<trit_t,21> v{};
};   // logical: 13 data + 8 inline
struct S63
{
    std::array<trit_t,63> v{};
};   // concatenation S21[0], S21[1], S21[2]

// ---------------------------
// Header/Footer accessors
// ---------------------------
inline Header3 get_header(const Word81& w)
{
    return Header3{ w.v[0], w.v[1], w.v[2] };
}
inline Footer3 get_footer(const Word81& w)
{
    return Footer3{ w.v[78], w.v[79], w.v[80] };
}

inline void set_header(Word81& w, const Header3& h)
{
    w.v[0] = ternary::clamp(h.sec_mode);
    w.v[1] = ternary::clamp(h.trust_lvl);
    w.v[2] = ternary::clamp(h.route_cls);
}
inline void set_footer(Word81& w, const Footer3& f)
{
    w.v[78] = ternary::clamp(f.integrity);
    w.v[79] = ternary::clamp(f.confidential);
    w.v[80] = ternary::clamp(f.trace_flag);
}

// ---------------------------
// Views for sub-sections
// ---------------------------
// Body (S63): indices [3 .. 66)  => 63 trits
// Slack     : indices [66 .. 78) => 12 trits
struct TritSpan
{
    trit_t* begin;
    trit_t* end;
};

inline TritSpan body_view(Word81& w)
{
    return TritSpan{ &w.v[3],  &w.v[66]  };
}
inline TritSpan slack_view(Word81& w)
{
    return TritSpan{ &w.v[66], &w.v[78]  };
}
inline TritSpan body_view(const Word81& w)
{
    return TritSpan{ const_cast<trit_t*>(&w.v[3]),  const_cast<trit_t*>(&w.v[66])  };
}
inline TritSpan slack_view(const Word81& w)
{
    return TritSpan{ const_cast<trit_t*>(&w.v[66]), const_cast<trit_t*>(&w.v[78]) };
}

// ---------------------------
// Checksum over S63 body only
// ---------------------------
inline trit_t checksum_mod3(const Word81& w)
{
    int sum = 0;
    for (int i=3; i<66; ++i) sum += int(w.v[i]);
    int r = ((sum % 3) + 3) % 3; // 0..2
    return ternary::to_balanced(static_cast<uint8_t>(r));
}

// ---------------------------
// Set/Get body as S63
// ---------------------------
inline void set_body_from_s63(Word81& w, const S63& s)
{
    for (int i=0; i<63; ++i) w.v[3+i] = ternary::clamp(s.v[i]);
}
inline void get_body_as_s63(const Word81& w, S63& s)
{
    for (int i=0; i<63; ++i) s.v[i] = w.v[3+i];
}

// ---------------------------
// Split/Join S63 into 3×S21
// ---------------------------
inline void split_s63_into_s21(const S63& s63, S21& s0, S21& s1, S21& s2)
{
    for (int i=0; i<21; ++i)
    {
        s0.v[i] = s63.v[i];
    }
    for (int i=0; i<21; ++i)
    {
        s1.v[i] = s63.v[21 + i];
    }
    for (int i=0; i<21; ++i)
    {
        s2.v[i] = s63.v[42 + i];
    }
}
inline void join_s21_into_s63(const S21& s0, const S21& s1, const S21& s2, S63& s63)
{
    for (int i=0; i<21; ++i)
    {
        s63.v[i]       = s0.v[i];
    }
    for (int i=0; i<21; ++i)
    {
        s63.v[21 + i]  = s1.v[i];
    }
    for (int i=0; i<21; ++i)
    {
        s63.v[42 + i]  = s2.v[i];
    }
}

// ---------------------------
// Footer helper (default impl)
// ---------------------------
inline Footer3 make_footer_default(const Word81& w, bool encrypted, int trace_level)
{
    using namespace ternary;
    Footer3 f;
    f.integrity    = checksum_mod3(w);
    f.confidential = encrypted ? POS : NEG;
    f.trace_flag   = (trace_level>1 ? POS : (trace_level==1 ? ZER : NEG));
    return f;
}

// Compile-time sanity.
static_assert(sizeof(ternary::trit_t)==1, "trit_t must be int8_t-sized");
static_assert(std::is_same<ternary::trit_t,int8_t>::value, "balanced trit type");
// GF(27) symbol accounting: 81 trits = 27 symbols (3 trits/symbol)
static_assert(81/3 == 27, "Word81 = 27 GF(27) symbols (bookkeeping)");
} // namespace word81

// ============================================================================
// Adapter hooks (same spirit as word27_adapt::*)
// Specialize MapSecMode/MapTrust/MapRouteClass for your actual enums.
// ============================================================================

namespace word81_adapt
{
using ternary::trit_t;

template<class SecPolicy> struct MapSecMode
{
    static trit_t to_trit(typename SecPolicy::SecMode m)
    {
        using M=typename SecPolicy::SecMode;
        switch(m)
        {
        case M::Open:
            return ternary::NEG;
        case M::Signed:
            return ternary::ZER;
        case M::Encrypted:
            return ternary::POS;
        }
        return ternary::ZER;
    }
    static typename SecPolicy::SecMode from_trit(trit_t t)
    {
        if (t==ternary::NEG) return SecPolicy::SecMode::Open;
        if (t==ternary::POS) return SecPolicy::SecMode::Encrypted;
        return SecPolicy::SecMode::Signed;
    }
};

template<class SecPolicy> struct MapTrust
{
    static trit_t to_trit(typename SecPolicy::Trust v)
    {
        using T=typename SecPolicy::Trust;
        switch(v)
        {
        case T::Unverified:
            return ternary::NEG;
        case T::Standard:
            return ternary::ZER;
        case T::Verified:
            return ternary::POS;
        }
        return ternary::ZER;
    }
    static typename SecPolicy::Trust from_trit(trit_t t)
    {
        if (t==ternary::NEG) return SecPolicy::Trust::Unverified;
        if (t==ternary::POS) return SecPolicy::Trust::Verified;
        return SecPolicy::Trust::Standard;
    }
};

template<class RouteNS> struct MapRouteClass
{
    static trit_t to_trit(typename RouteNS::RouteClass r)
    {
        using R=typename RouteNS::RouteClass;
        switch(r)
        {
        case R::Media:
            return ternary::NEG;
        case R::Telemetry:
            return ternary::ZER;
        case R::Control:
            return ternary::POS;
        }
        return ternary::ZER;
    }
    static typename RouteNS::RouteClass from_trit(trit_t t)
    {
        if (t==ternary::NEG) return RouteNS::RouteClass::Media;
        if (t==ternary::POS) return RouteNS::RouteClass::Control;
        return RouteNS::RouteClass::Telemetry;
    }
};

template<class SecPolicy, class RouteNS>
inline word81::Header3 encode_header(const SecPolicy&,
                                     typename SecPolicy::SecMode m,
                                     typename SecPolicy::Trust trust,
                                     typename RouteNS::RouteClass rc)
{
    return word81::Header3
    {
        MapSecMode<SecPolicy>::to_trit(m),
        MapTrust<SecPolicy>::to_trit(trust),
        MapRouteClass<RouteNS>::to_trit(rc)
    };
}

template<class SecPolicy, class RouteNS>
inline void decode_header(const word81::Header3& h,
                          typename SecPolicy::SecMode& m,
                          typename SecPolicy::Trust& trust,
                          typename RouteNS::RouteClass& rc)
{
    m     = MapSecMode<SecPolicy>::from_trit(h.sec_mode);
    trust = MapTrust<SecPolicy>::from_trit(h.trust_lvl);
    rc    = MapRouteClass<RouteNS>::from_trit(h.route_cls);
}

inline word81::Footer3 make_footer_default(const word81::Word81& w,
        bool encrypted,
        int trace_level)
{
    return word81::make_footer_default(w, encrypted, trace_level);
}
} // namespace word81_adapt
