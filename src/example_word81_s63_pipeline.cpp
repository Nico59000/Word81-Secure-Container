// ============================================================================
// example_word81_s63_pipeline.cpp — Minimal end-to-end example
// Build: c++ -std=c++20 -O2 example_word81_s63_pipeline.cpp
// ============================================================================

#include <iostream>
#include "word81_s63_secure_container.hpp"

// Mock external interfaces (replace with your real headers)
namespace security {
  struct Policy {
    enum class SecMode { Open, Signed, Encrypted };
    enum class Trust  { Unverified, Standard, Verified };
  };
}
namespace routing { enum class RouteClass { Media, Telemetry, Control }; }

// Provide concrete adapters for the mocks (normally specialize in your project)
namespace word81_adapt {
  template<> struct MapSecMode<security::Policy>{
    static ternary::trit_t to_trit(security::Policy::SecMode m){
      using M=security::Policy::SecMode; if(m==M::Open) return ternary::NEG; if(m==M::Encrypted) return ternary::POS; return ternary::ZER; }
    static security::Policy::SecMode from_trit(ternary::trit_t t){
      return (t==ternary::NEG)?security::Policy::SecMode::Open:
             (t==ternary::POS)?security::Policy::SecMode::Encrypted:
                                security::Policy::SecMode::Signed; }
  };
  template<> struct MapTrust<security::Policy>{
    static ternary::trit_t to_trit(security::Policy::Trust v){
      using T=security::Policy::Trust; if(v==T::Unverified) return ternary::NEG; if(v==T::Verified) return ternary::POS; return ternary::ZER; }
    static security::Policy::Trust from_trit(ternary::trit_t t){
      return (t==ternary::NEG)?security::Policy::Trust::Unverified:
             (t==ternary::POS)?security::Policy::Trust::Verified:
                                security::Policy::Trust::Standard; }
  };
  template<> struct MapRouteClass<routing>{
    static ternary::trit_t to_trit(routing::RouteClass r){
      using R=routing::RouteClass; if(r==R::Media) return ternary::NEG; if(r==R::Control) return ternary::POS; return ternary::ZER; }
    static routing::RouteClass from_trit(ternary::trit_t t){
      return (t==ternary::NEG)?routing::RouteClass::Media:
             (t==ternary::POS)?routing::RouteClass::Control:
                                routing::RouteClass::Telemetry; }
  };
}

int main(){
  // Build a S63 body (3×S21)
  word81::S21 s0{}, s1{}, s2{};
  for (int i=0;i<21;++i) { s0.v[i] = (i%3==0? ternary::NEG : (i%3==1? ternary::ZER : ternary::POS)); }
  for (int i=0;i<21;++i) { s1.v[i] = (i%2==0? ternary::POS : ternary::NEG); }
  for (int i=0;i<21;++i) { s2.v[i] = ternary::ZER; }

  word81::S63 s63{};
  word81::join_s21_into_s63(s0, s1, s2, s63);

  // Create Word81, encode header/body/footer
  word81::Word81 w{};
  auto hdr = word81_adapt::encode_header<security::Policy, routing>(
      security::Policy{}, security::Policy::SecMode::Signed,
      security::Policy::Trust::Verified, routing::RouteClass::Media);
  word81::set_header(w, hdr);
  word81::set_body_from_s63(w, s63);

  auto ftr = word81_adapt::make_footer_default(w, /*encrypted=*/false, /*trace=*/1);
  word81::set_footer(w, ftr);

  // Inspect
  auto H = word81::get_header(w);
  auto F = word81::get_footer(w);
  std::cout << "Header(sec=" << int(H.sec_mode) << ", trust=" << int(H.trust_lvl)
            << ", route=" << int(H.route_cls) << ")\n";
  std::cout << "Footer(intg=" << int(F.integrity) << ", conf=" << int(F.confidential)
            << ", trace=" << int(F.trace_flag) << ")\n";
  return 0;
}
