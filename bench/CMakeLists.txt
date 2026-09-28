# Benchmarks. Every measured operation is a completed operation: validation,
# canonical encoding, staging write, read-back verification, atomic publish and head
# commit all happen inside the timed region.

add_executable(fa_bench_authority bench_authority.cpp)
target_link_libraries(fa_bench_authority PRIVATE feed_authority)
feed_authority_apply_strict_options(fa_bench_authority)
