// stands in for an injected library in the live demo. it does nothing at
// all; the point is that it gets loaded into the jvm from a directory the
// bouncer never trusted, so the shutdown sweep has something real to catch.

extern "C" int Agent_OnLoad(void *, char *, void *) { return 0; }

extern "C" void Agent_OnUnload(void *) {}
