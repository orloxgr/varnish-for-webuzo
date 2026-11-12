# Basic: public HTTP caching without application-specific route assumptions.
# Cookies reach the origin and query strings remain in the cache key.
# Authentication, private sessions and response cache policy are enforced
# by the common envelope; an unknown cookie or query is not a bypass reason.
sub wvw_basic_recv {
}
