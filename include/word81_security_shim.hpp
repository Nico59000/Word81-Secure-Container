// ============================================================================
// word81_security_shim.hpp — Auto-detect & bind external security_policy.hpp /
// security_route_helper.hpp via SFINAE/concepts, with safe fallbacks.
// Mirrors the Word27 shim API, adapted to Word81 types.
// ============================================================================

#pragma once
#include <type_traits>
#include "word81_s63_secure_container.hpp"

namespace secshim81 {
  template <class T, class = void> struct has_SecMode    : std::false_type{};
  template <class T> struct has_SecMode<T, std::void_t<typename T::SecMode>> : std::true_type{};
  template <class T, class = void> struct has_Trust      : std::false_type{};
  template <class T> struct has_Trust<T, std::void_t<typename T::Trust>> : std::true_type{};
  template <class RNS, class = void> struct has_RouteClass : std::false_type{};
  template <class RNS> struct has_RouteClass<RNS, std::void_t<typename RNS::RouteClass>> : std::true_type{};

  template<class Policy> using is_security_policy = std::conjunction<has_SecMode<Policy>, has_Trust<Policy>>;
  template<class RNS>    using is_route_namespace = has_RouteClass<RNS>;

  template<class SecPolicy, class Enable = void>
  struct SecModeMapperShim { static ternary::trit_t to(typename SecPolicy::SecMode){ return ternary::ZER; } };
  template<class SecPolicy>
  struct SecModeMapperShim<SecPolicy, std::enable_if_t<is_security_policy<SecPolicy>::value>> {
    static ternary::trit_t to(typename SecPolicy::SecMode){ return ternary::ZER; } // customize in project
  };

  template<class SecPolicy, class Enable = void>
  struct TrustMapperShim { static ternary::trit_t to(typename SecPolicy::Trust){ return ternary::ZER; } };
  template<class SecPolicy>
  struct TrustMapperShim<SecPolicy, std::enable_if_t<is_security_policy<SecPolicy>::value>> {
    static ternary::trit_t to(typename SecPolicy::Trust){ return ternary::ZER; } // customize in project
  };

  template<class RNS, class Enable = void>
  struct RouteMapperShim { static ternary::trit_t to(typename RNS::RouteClass){ return ternary::ZER; } };
  template<class RNS>
  struct RouteMapperShim<RNS, std::enable_if_t<is_route_namespace<RNS>::value>> {
    static ternary::trit_t to(typename RNS::RouteClass){ return ternary::ZER; } // customize in project
  };

  template<class SecPolicy, class RNS>
  inline word81::Header3 make_header_auto(const SecPolicy&, typename SecPolicy::SecMode m,
                                          typename SecPolicy::Trust t, typename RNS::RouteClass r){
    return word81::Header3{
      SecModeMapperShim<SecPolicy>::to(m),
      TrustMapperShim<SecPolicy>::to(t),
      RouteMapperShim<RNS>::to(r)
    };
  }

  inline word81::Footer3 make_footer_auto(const word81::Word81& w, bool encrypted, int trace_level){
    return word81_adapt::make_footer_default(w, encrypted, trace_level);
  }
}
